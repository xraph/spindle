package spindle

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// ControllerConfig configures the controlling side of a handshake.
type ControllerConfig struct {
	// Identity is the controller's long-term identity. Required.
	Identity *ControllerIdentity

	// DeviceStatic is the device's pinned X25519 public key, as recorded in the
	// device registry at commissioning time. Required — Spindle will not
	// handshake against an unpinned device, because pinning is what stops a
	// broker-side attacker from substituting its own device.
	DeviceStatic []byte

	// Scope is the deployment scope bound into the prologue. Both endpoints must
	// agree on it or the handshake fails.
	Scope string

	// Random overrides the entropy source. Leave nil outside tests.
	Random io.Reader
}

// Controller drives the controlling side of the handshake: write msg1, read
// msg2, get a Session.
type Controller struct {
	hs      *noise.HandshakeState
	binding []byte
	sentMsg bool
}

// NewController prepares a handshake as the Noise initiator.
func NewController(cfg ControllerConfig) (*Controller, error) {
	if cfg.Identity == nil || len(cfg.Identity.Static.Private) != DHLen {
		return nil, ErrMissingStatic
	}
	if len(cfg.DeviceStatic) != DHLen {
		return nil, ErrMissingPeerStatic
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Random:        cfg.Random,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildPrologue(cfg.Scope),
		StaticKeypair: cfg.Identity.Static,
		PeerStatic:    cfg.DeviceStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("spindle: init controller handshake: %w", err)
	}
	return &Controller{hs: hs}, nil
}

// Hello writes handshake message 1. The payload is encrypted to the pinned
// device — under IK the static-static DH has already been mixed by this point —
// so it is a safe place for a challenge nonce or session parameters.
func (c *Controller) Hello(payload []byte) ([]byte, error) {
	if c.sentMsg {
		return nil, ErrHandshakeState
	}
	msg, _, _, err := c.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("spindle: write hello: %w", err)
	}
	c.sentMsg = true
	c.binding = cloneBinding(c.hs.ChannelBinding())
	return msg, nil
}

// AttestationBinding returns the handshake hash as it stands immediately after
// message 1, which is the value both endpoints use as the transcript for
// firmware attestation.
//
// It is a snapshot rather than the live binding for a specific reason: the
// device must produce its attestation signature while composing message 2, at
// which point it has processed message 1 but not yet mixed its own ephemeral.
// The controller therefore captures the same intermediate state after writing
// message 1. Both sides get identical bytes covering the prologue, both static
// keys, the controller's ephemeral, and the message-1 payload — enough to make
// an attestation unreplayable across sessions.
//
// Returns nil before Hello has been called.
func (c *Controller) AttestationBinding() []byte { return cloneBinding(c.binding) }

// Complete consumes handshake message 2 and returns the live Session plus the
// device's decrypted payload.
func (c *Controller) Complete(msg2 []byte) (*Session, []byte, error) {
	if !c.sentMsg {
		return nil, nil, ErrHandshakeState
	}
	payload, tx, rx, err := c.hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("spindle: read welcome: %w", err)
	}
	if tx == nil || rx == nil {
		return nil, nil, ErrHandshakeState
	}
	return newSession(c.hs.ChannelBinding(), tx, rx), payload, nil
}

// DeviceConfig configures the device side of a handshake.
type DeviceConfig struct {
	// Keys is the device's long-term identity. Required.
	Keys *DeviceKeys

	// ControllerStatic is the controller's pinned X25519 public key, written to
	// the device during commissioning. Required unless Commissioning is set.
	//
	// Noise_IK delivers the controller's static inside message 1, and the
	// pattern's static-static DH already proves the sender holds the matching
	// private key. What it does not do is tell the device *which* controller it
	// should be willing to talk to — so ReadHello compares the delivered key
	// against this pinned value and refuses anything else.
	ControllerStatic []byte

	// Commissioning accepts whichever controller static arrives in message 1
	// instead of enforcing ControllerStatic, for the one handshake during which
	// a device has no pin yet. Read the adopted key with
	// AdoptedControllerStatic and persist it before the device carries traffic.
	//
	// It must be set explicitly and is mutually exclusive with
	// ControllerStatic. Treating an absent pin as "accept anything" would mean a
	// config that simply forgot to set ControllerStatic failed open, which is
	// the opposite of what this field is for.
	//
	// A device in this mode will complete a handshake with any controller that
	// knows its static public key, so it is only safe while the device is under
	// physical operator control and the adopted key is confirmed out of band.
	Commissioning bool

	// Scope is the deployment scope bound into the prologue.
	Scope string

	// Random overrides the entropy source. Leave nil outside tests.
	Random io.Reader
}

// Device drives the device side of the handshake: read msg1, write msg2, get a
// Session.
type Device struct {
	hs            *noise.HandshakeState
	pinned        []byte
	commissioning bool
	adopted       []byte
	binding       []byte
	readMsg       bool
	wroteReply    bool
}

// NewDevice prepares a handshake as the Noise responder.
func NewDevice(cfg DeviceConfig) (*Device, error) {
	if cfg.Keys == nil || len(cfg.Keys.Static.Private) != DHLen {
		return nil, ErrMissingStatic
	}
	switch {
	case cfg.Commissioning && len(cfg.ControllerStatic) > 0:
		return nil, ErrPinAndCommissioning
	case !cfg.Commissioning && len(cfg.ControllerStatic) != DHLen:
		return nil, ErrMissingPeerStatic
	}

	// PeerStatic is deliberately not set here. In IK the only pre-message is the
	// responder's own static; the initiator's static arrives in message 1.
	// Setting PeerStatic would mix a key the pattern does not expect at this
	// point and desynchronise the handshake hash.
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Random:        cfg.Random,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      BuildPrologue(cfg.Scope),
		StaticKeypair: cfg.Keys.Static,
	})
	if err != nil {
		return nil, fmt.Errorf("spindle: init device handshake: %w", err)
	}

	d := &Device{hs: hs, commissioning: cfg.Commissioning}
	if !cfg.Commissioning {
		d.pinned = make([]byte, DHLen)
		copy(d.pinned, cfg.ControllerStatic)
	}
	return d, nil
}

// ReadHello consumes handshake message 1, enforces controller pinning, and
// returns the controller's decrypted payload.
func (d *Device) ReadHello(msg1 []byte) ([]byte, error) {
	if d.readMsg {
		return nil, ErrHandshakeState
	}
	payload, _, _, err := d.hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, fmt.Errorf("spindle: read hello: %w", err)
	}

	peer := d.hs.PeerStatic()
	if d.commissioning {
		d.adopted = cloneBinding(peer)
	} else if subtle.ConstantTimeCompare(peer, d.pinned) != 1 {
		// Constant-time so a mismatched key cannot be recovered by timing the
		// rejection.
		return nil, ErrControllerNotPinned
	}

	d.readMsg = true
	d.binding = cloneBinding(d.hs.ChannelBinding())
	return payload, nil
}

// AdoptedControllerStatic returns the controller static delivered in message 1.
// It is non-nil only in commissioning mode, after ReadHello has succeeded — this
// is the value to seal once the operator confirms the fingerprint out of band.
//
// A pinned device returns nil: it already knows the key, and handing back a
// value that only ever equals the pin would invite callers to re-derive their
// trust root from the wire.
func (d *Device) AdoptedControllerStatic() []byte { return cloneBinding(d.adopted) }

// AttestationBinding returns the transcript the device signs for attestation.
// See Controller.AttestationBinding for why this is a post-message-1 snapshot.
// Returns nil before ReadHello has succeeded.
func (d *Device) AttestationBinding() []byte { return cloneBinding(d.binding) }

// Welcome writes handshake message 2 and returns the live Session. The payload
// carries device identity and any attestation evidence; it is encrypted.
func (d *Device) Welcome(payload []byte) ([]byte, *Session, error) {
	if !d.readMsg || d.wroteReply {
		return nil, nil, ErrHandshakeState
	}
	msg, rx, tx, err := d.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("spindle: write welcome: %w", err)
	}
	if tx == nil || rx == nil {
		return nil, nil, ErrHandshakeState
	}
	d.wroteReply = true

	// WriteMessage returns (cs1, cs2) as (initiator→responder, responder→
	// initiator). This is the responder, so the second is ours to send with and
	// the first is ours to receive with — hence the swapped binding above.
	return msg, newSession(d.hs.ChannelBinding(), tx, rx), nil
}

// cloneBinding copies a channel binding. noise.ChannelBinding returns a slice
// into live handshake state that keeps mutating as the handshake proceeds, so
// anything we retain must be copied.
func cloneBinding(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
