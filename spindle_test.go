package spindle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

const testScope = "ws_test"

type pair struct {
	controller *Controller
	device     *Device
	ctrlSess   *Session
	devSess    *Session
	ctrlID     *ControllerIdentity
	devKeys    *DeviceKeys
	helloPay   []byte
	welcomePay []byte
}

// handshakeOpts lets individual tests bend one input without duplicating the
// whole four-step dance.
type handshakeOpts struct {
	controllerScope string
	deviceScope     string
	pinnedDevice    []byte
	pinnedCtrl      []byte
	helloPayload    []byte
	welcomePayload  []byte
}

func newPair(t *testing.T, opts handshakeOpts) *pair {
	t.Helper()

	ctrlID, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("controller identity: %v", err)
	}
	devKeys, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("device keys: %v", err)
	}

	if opts.controllerScope == "" {
		opts.controllerScope = testScope
	}
	if opts.deviceScope == "" {
		opts.deviceScope = testScope
	}
	if opts.pinnedDevice == nil {
		opts.pinnedDevice = devKeys.Static.Public
	}
	if opts.pinnedCtrl == nil {
		opts.pinnedCtrl = ctrlID.Static.Public
	}

	c, err := NewController(ControllerConfig{
		Identity:     ctrlID,
		DeviceStatic: opts.pinnedDevice,
		Scope:        opts.controllerScope,
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	d, err := NewDevice(DeviceConfig{
		Keys:             devKeys,
		ControllerStatic: opts.pinnedCtrl,
		Scope:            opts.deviceScope,
	})
	if err != nil {
		t.Fatalf("new device: %v", err)
	}

	return &pair{
		controller: c, device: d,
		ctrlID: ctrlID, devKeys: devKeys,
		helloPay: opts.helloPayload, welcomePay: opts.welcomePayload,
	}
}

// run drives the full handshake, returning the first error encountered.
func (p *pair) run() error {
	msg1, err := p.controller.Hello(p.helloPay)
	if err != nil {
		return err
	}
	if _, err = p.device.ReadHello(msg1); err != nil {
		return err
	}
	msg2, devSess, err := p.device.Welcome(p.welcomePay)
	if err != nil {
		return err
	}
	ctrlSess, _, err := p.controller.Complete(msg2)
	if err != nil {
		return err
	}
	p.ctrlSess, p.devSess = ctrlSess, devSess
	return nil
}

func established(t *testing.T) *pair {
	t.Helper()
	p := newPair(t, handshakeOpts{})
	if err := p.run(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return p
}

func TestHandshake_roundTripBothDirections(t *testing.T) {
	p := established(t)
	aad := AAD("app/control/v1")

	// Controller → device. This is the assertion that catches a swapped
	// tx/rx CipherState pairing: get the split ordering wrong and nothing
	// decrypts at all.
	want := []byte("actuate valve 3")
	frame, err := p.ctrlSess.Seal(aad, want)
	if err != nil {
		t.Fatalf("controller seal: %v", err)
	}
	got, seq, err := p.devSess.Open(aad, frame)
	if err != nil {
		t.Fatalf("device open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("controller→device payload = %q, want %q", got, want)
	}
	if seq != 0 {
		t.Errorf("first frame seq = %d, want 0", seq)
	}

	// Device → controller.
	want = []byte("valve 3 open")
	frame, err = p.devSess.Seal(aad, want)
	if err != nil {
		t.Fatalf("device seal: %v", err)
	}
	got, _, err = p.ctrlSess.Open(aad, frame)
	if err != nil {
		t.Fatalf("controller open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("device→controller payload = %q, want %q", got, want)
	}
}

func TestHandshake_payloadsCrossEncrypted(t *testing.T) {
	hello := []byte("challenge-nonce")
	welcome := []byte("device-42")

	p := newPair(t, handshakeOpts{helloPayload: hello, welcomePayload: welcome})

	msg1, err := p.controller.Hello(hello)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if bytes.Contains(msg1, hello) {
		t.Error("message 1 carries its payload in cleartext")
	}
	gotHello, err := p.device.ReadHello(msg1)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if !bytes.Equal(gotHello, hello) {
		t.Errorf("hello payload = %q, want %q", gotHello, hello)
	}

	msg2, _, err := p.device.Welcome(welcome)
	if err != nil {
		t.Fatalf("welcome: %v", err)
	}
	if bytes.Contains(msg2, welcome) {
		t.Error("message 2 carries its payload in cleartext")
	}
	_, gotWelcome, err := p.controller.Complete(msg2)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !bytes.Equal(gotWelcome, welcome) {
		t.Errorf("welcome payload = %q, want %q", gotWelcome, welcome)
	}
}

func TestHandshake_endpointsAgreeOnDerivedValues(t *testing.T) {
	p := established(t)

	if p.ctrlSess.ID() != p.devSess.ID() {
		t.Errorf("session IDs differ: controller %d, device %d", p.ctrlSess.ID(), p.devSess.ID())
	}
	if p.ctrlSess.ID() == 0 {
		t.Error("session ID is zero, suggesting it was never derived")
	}
	if !bytes.Equal(p.ctrlSess.Binding(), p.devSess.Binding()) {
		t.Error("session bindings differ between endpoints")
	}
	// The attestation snapshot must match across endpoints, or the device's
	// signature can never be verified by the controller.
	if !bytes.Equal(p.controller.AttestationBinding(), p.device.AttestationBinding()) {
		t.Error("attestation bindings differ between endpoints")
	}
	if len(p.controller.AttestationBinding()) == 0 {
		t.Error("attestation binding is empty")
	}
	// The post-handshake binding must differ from the message-1 snapshot,
	// otherwise the snapshot is not actually a snapshot.
	if bytes.Equal(p.ctrlSess.Binding(), p.controller.AttestationBinding()) {
		t.Error("session binding equals the message-1 snapshot; ChannelBinding was not copied")
	}
}

func TestHandshake_rejects(t *testing.T) {
	otherDevice, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("other device keys: %v", err)
	}
	otherCtrl, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("other controller identity: %v", err)
	}

	tests := []struct {
		name    string
		opts    handshakeOpts
		wantErr error // nil means "any error"
	}{
		{
			name: "scope mismatch",
			opts: handshakeOpts{controllerScope: "ws_a", deviceScope: "ws_b"},
		},
		{
			name: "controller pins the wrong device",
			opts: handshakeOpts{pinnedDevice: otherDevice.Static.Public},
		},
		{
			name:    "device pinned to a different controller",
			opts:    handshakeOpts{pinnedCtrl: otherCtrl.Static.Public},
			wantErr: ErrControllerNotPinned,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPair(t, tt.opts)
			err := p.run()
			if err == nil {
				t.Fatal("handshake succeeded, want failure")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandshake_scopeIsBoundNotAdvisory(t *testing.T) {
	// Two scopes differing only by a boundary shift must not produce the same
	// prologue — that is what the length prefix is for.
	if bytes.Equal(BuildPrologue("ws"), BuildPrologue("ws\x00")) {
		t.Error("prologues collide across scope boundary")
	}
	a, b := BuildPrologue("ab"), BuildPrologue("a")
	if bytes.HasPrefix(a, b) && len(a) == len(b)+1 {
		t.Error("prologue is a bare concatenation; scopes can collide")
	}
}

func TestHandshake_outOfOrderCalls(t *testing.T) {
	p := newPair(t, handshakeOpts{})

	if _, _, err := p.controller.Complete([]byte("premature")); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("Complete before Hello: %v, want ErrHandshakeState", err)
	}
	if _, _, err := p.device.Welcome(nil); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("Welcome before ReadHello: %v, want ErrHandshakeState", err)
	}

	msg1, err := p.controller.Hello(nil)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := p.controller.Hello(nil); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("second Hello: %v, want ErrHandshakeState", err)
	}
	if _, err := p.device.ReadHello(msg1); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if _, err := p.device.ReadHello(msg1); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("second ReadHello: %v, want ErrHandshakeState", err)
	}
}

func TestNewController_requiresPinnedDevice(t *testing.T) {
	id, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if _, err := NewController(ControllerConfig{Identity: id, Scope: testScope}); !errors.Is(err, ErrMissingPeerStatic) {
		t.Errorf("error = %v, want ErrMissingPeerStatic", err)
	}
	if _, err := NewController(ControllerConfig{DeviceStatic: make([]byte, DHLen)}); !errors.Is(err, ErrMissingStatic) {
		t.Errorf("error = %v, want ErrMissingStatic", err)
	}
}

func TestNewDevice_requiresPinnedController(t *testing.T) {
	keys, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	// An absent pin must fail closed. A config that simply forgot to set
	// ControllerStatic must not be read as "accept any controller".
	if _, err := NewDevice(DeviceConfig{Keys: keys, Scope: testScope}); !errors.Is(err, ErrMissingPeerStatic) {
		t.Errorf("error = %v, want ErrMissingPeerStatic", err)
	}

	if _, err := NewDevice(DeviceConfig{
		Keys:             keys,
		ControllerStatic: make([]byte, DHLen),
		Commissioning:    true,
		Scope:            testScope,
	}); !errors.Is(err, ErrPinAndCommissioning) {
		t.Errorf("error = %v, want ErrPinAndCommissioning", err)
	}
}

func TestDevice_commissioningAdoptsControllerStatic(t *testing.T) {
	ctrlID, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("controller identity: %v", err)
	}
	devKeys, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("device keys: %v", err)
	}

	c, err := NewController(ControllerConfig{
		Identity:     ctrlID,
		DeviceStatic: devKeys.Static.Public,
		Scope:        testScope,
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	d, err := NewDevice(DeviceConfig{Keys: devKeys, Commissioning: true, Scope: testScope})
	if err != nil {
		t.Fatalf("new device: %v", err)
	}

	if got := d.AdoptedControllerStatic(); got != nil {
		t.Error("adopted key available before ReadHello")
	}

	msg1, err := c.Hello(nil)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := d.ReadHello(msg1); err != nil {
		t.Fatalf("commissioning device rejected an unpinned controller: %v", err)
	}

	adopted := d.AdoptedControllerStatic()
	if !bytes.Equal(adopted, ctrlID.Static.Public) {
		t.Fatalf("adopted key = %x, want %x", adopted, ctrlID.Static.Public)
	}

	// The session must still work — commissioning suspends the pin check, not
	// the cryptography.
	msg2, devSess, err := d.Welcome(nil)
	if err != nil {
		t.Fatalf("welcome: %v", err)
	}
	ctrlSess, _, err := c.Complete(msg2)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	aad := AAD("app/control/v1")
	frame, err := ctrlSess.Seal(aad, []byte("ping"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := devSess.Open(aad, frame); err != nil {
		t.Fatalf("open: %v", err)
	}

	// And the adopted key must be exactly what a later pinned handshake accepts.
	d2, err := NewDevice(DeviceConfig{Keys: devKeys, ControllerStatic: adopted, Scope: testScope})
	if err != nil {
		t.Fatalf("new pinned device: %v", err)
	}
	c2, err := NewController(ControllerConfig{
		Identity:     ctrlID,
		DeviceStatic: devKeys.Static.Public,
		Scope:        testScope,
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	msg1, err = c2.Hello(nil)
	if err != nil {
		t.Fatalf("second hello: %v", err)
	}
	if _, err := d2.ReadHello(msg1); err != nil {
		t.Errorf("pinned handshake with the adopted key failed: %v", err)
	}
}

func TestDevice_pinnedModeExposesNoAdoptedKey(t *testing.T) {
	p := established(t)
	if got := p.device.AdoptedControllerStatic(); got != nil {
		t.Errorf("pinned device exposed an adopted key: %x", got)
	}
}

func TestSession_aadSeparatesTrafficClasses(t *testing.T) {
	p := established(t)

	frame, err := p.ctrlSess.Seal(AAD("app/control/v1"), []byte("shutdown"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := p.devSess.Open(AAD("app/heartbeat/v1"), frame); err == nil {
		t.Error("a control frame was accepted as a heartbeat frame")
	}
}

func TestSession_replayRejected(t *testing.T) {
	p := established(t)
	aad := AAD("app/control/v1")

	frame, err := p.ctrlSess.Seal(aad, []byte("open"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := p.devSess.Open(aad, frame); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, _, err := p.devSess.Open(aad, frame); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed frame: %v, want ErrReplay", err)
	}
}

func TestSession_acceptsOutOfOrderWithinWindow(t *testing.T) {
	p := established(t)
	aad := AAD("app/control/v1")

	frames := make([][]byte, 5)
	for i := range frames {
		f, err := p.ctrlSess.Seal(aad, []byte{byte('a' + i)})
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		frames[i] = f
	}

	// Deliver 4,2,0,3,1 — the shape a lossy pub/sub link actually produces.
	for _, i := range []int{4, 2, 0, 3, 1} {
		got, seq, err := p.devSess.Open(aad, frames[i])
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if seq != uint64(i) {
			t.Errorf("frame %d reported seq %d", i, seq)
		}
		if want := byte('a' + i); got[0] != want {
			t.Errorf("frame %d payload = %q, want %q", i, got[0], want)
		}
	}

	// Every one of them is now a duplicate.
	for _, i := range []int{0, 4} {
		if _, _, err := p.devSess.Open(aad, frames[i]); !errors.Is(err, ErrReplay) {
			t.Errorf("re-delivered frame %d: %v, want ErrReplay", i, err)
		}
	}
}

func TestSession_forgedFrameDoesNotConsumeWindowSlot(t *testing.T) {
	p := established(t)
	aad := AAD("app/control/v1")

	frame, err := p.ctrlSess.Seal(aad, []byte("legitimate"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Flip a ciphertext bit, keeping the header — a broker-side attacker's
	// cheapest move.
	forged := bytes.Clone(frame)
	forged[len(forged)-1] ^= 0x01
	if _, _, err := p.devSess.Open(aad, forged); err == nil {
		t.Fatal("forged frame was accepted")
	}

	// The genuine frame at the same sequence must still be accepted, or a
	// forgery would be a cheap denial of service against that slot.
	got, _, err := p.devSess.Open(aad, frame)
	if err != nil {
		t.Fatalf("genuine frame after forgery: %v", err)
	}
	if !bytes.Equal(got, []byte("legitimate")) {
		t.Errorf("payload = %q", got)
	}
}

func TestSession_rejectsForeignAndMalformedFrames(t *testing.T) {
	p := established(t)
	other := established(t)
	aad := AAD("app/control/v1")

	foreign, err := other.ctrlSess.Seal(aad, []byte("wrong session"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := p.devSess.Open(aad, foreign); !errors.Is(err, ErrSessionMismatch) {
		t.Errorf("foreign frame: %v, want ErrSessionMismatch", err)
	}

	if _, _, err := p.devSess.Open(aad, []byte("tiny")); !errors.Is(err, ErrShortFrame) {
		t.Errorf("short frame: %v, want ErrShortFrame", err)
	}
}

func TestSession_rejectsOversizePayload(t *testing.T) {
	p := established(t)
	if _, err := p.ctrlSess.Seal(nil, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("error = %v, want ErrPayloadTooLarge", err)
	}
}

func TestSession_sequenceExhaustionIsHardStop(t *testing.T) {
	p := established(t)

	// Wind the send counter to the boundary. Wrapping here would reuse a
	// (key, nonce) pair, which is catastrophic for ChaCha20-Poly1305 — so this
	// must be an error, not an overflow.
	p.ctrlSess.tx.SetNonce(MaxSeq)
	if _, err := p.ctrlSess.Seal(nil, []byte("one too many")); !errors.Is(err, ErrSeqExhausted) {
		t.Errorf("error = %v, want ErrSeqExhausted", err)
	}
	if got := p.ctrlSess.TxSeq(); got != MaxSeq {
		t.Errorf("counter advanced past exhaustion to %d", got)
	}
}

func TestReplayWindow(t *testing.T) {
	t.Run("accepts sequence zero as the first frame", func(t *testing.T) {
		// Sequences start at 0, and a zero-valued window also has top == 0, so
		// this is the case a naive implementation rejects as a self-duplicate.
		if w := NewReplayWindow(DefaultReplayWindow); !w.Accept(0) {
			t.Error("first frame at seq 0 was rejected")
		}
	})

	t.Run("rejects duplicate of first frame", func(t *testing.T) {
		w := NewReplayWindow(DefaultReplayWindow)
		w.Accept(0)
		if w.Accept(0) {
			t.Error("duplicate seq 0 accepted")
		}
	})

	t.Run("strictly monotonic when size is zero", func(t *testing.T) {
		w := NewReplayWindow(0)
		if !w.Accept(5) {
			t.Fatal("seq 5 rejected")
		}
		if w.Accept(4) {
			t.Error("size-0 window accepted an out-of-order frame")
		}
		if !w.Accept(6) {
			t.Error("seq 6 rejected")
		}
	})

	t.Run("rejects frames that fell out of the window", func(t *testing.T) {
		w := NewReplayWindow(8)
		if !w.Accept(100) {
			t.Fatal("seq 100 rejected")
		}
		if w.Accept(91) {
			t.Error("seq 91 accepted with an 8-frame window at top 100")
		}
		if !w.Accept(97) {
			t.Error("seq 97 rejected inside an 8-frame window")
		}
		if w.Accept(97) {
			t.Error("seq 97 accepted twice")
		}
	})

	t.Run("large jump resets the bitmap without false positives", func(t *testing.T) {
		w := NewReplayWindow(DefaultReplayWindow)
		w.Accept(1)
		if !w.Accept(1_000_000) {
			t.Fatal("large forward jump rejected")
		}
		if w.Accept(1_000_000) {
			t.Error("duplicate after jump accepted")
		}
		if w.Accept(1) {
			t.Error("stale seq accepted after the window moved past it")
		}
	})
}

func TestFingerprintWordlist_complete(t *testing.T) {
	// A Go array literal leaves unlisted entries as "". A short list therefore
	// renders blank words for the digest bytes that index past its end, silently
	// weakening the human comparison that detects a commissioning MITM.
	seen := make(map[string]int, len(fingerprintWordlist))
	for i, w := range fingerprintWordlist {
		if w == "" {
			t.Errorf("wordlist index %d is empty", i)
			continue
		}
		if prev, dup := seen[w]; dup {
			t.Errorf("wordlist index %d duplicates index %d (%q)", i, prev, w)
		}
		seen[w] = i
	}
	if len(seen) != 256 {
		t.Errorf("wordlist has %d distinct words, want 256", len(seen))
	}
}

func TestFingerprintWords(t *testing.T) {
	transcript := []byte("transcript bytes")

	got := FingerprintWords(transcript)
	if n := len(bytes.Split([]byte(got), []byte("-"))); n != FingerprintWordCount {
		t.Errorf("fingerprint %q has %d words, want %d", got, n, FingerprintWordCount)
	}
	if bytes.Contains([]byte(got), []byte("--")) {
		t.Errorf("fingerprint %q contains an empty word", got)
	}
	if again := FingerprintWords(transcript); again != got {
		t.Error("fingerprint is not deterministic")
	}
	if other := FingerprintWords([]byte("different")); other == got {
		t.Error("transcript does not affect the fingerprint")
	}
}

func TestFingerprintEqual(t *testing.T) {
	if !FingerprintEqual("alpha-beta", "alpha-beta") {
		t.Error("identical fingerprints compared unequal")
	}
	if FingerprintEqual("alpha-beta", "alpha-gamma") {
		t.Error("differing fingerprints compared equal")
	}
	if FingerprintEqual("alpha", "alpha-beta") {
		t.Error("different-length fingerprints compared equal")
	}
}

func TestCommissioningCode(t *testing.T) {
	if got := CommissioningCode(nil); got != "000000" {
		t.Errorf("empty seed = %q, want 000000", got)
	}
	code := CommissioningCode([]byte("seed"))
	if len(code) != 6 {
		t.Errorf("code %q is not 6 digits", code)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("code %q contains a non-digit", code)
		}
	}
	if CommissioningCode([]byte("seed")) != code {
		t.Error("code is not deterministic")
	}
	if CommissioningCode([]byte("other")) == code {
		t.Error("distinct seeds produced the same code")
	}
}

func TestAttestation_roundTrip(t *testing.T) {
	p := established(t)

	signer, err := NewSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	firmware := []byte("sha256-of-image")
	nonce := []byte("sixteen-byte-non")

	binding := p.device.AttestationBinding()
	sig := signer.Sign(AttestationInput(binding, firmware, 7, nonce))

	// The controller verifies against its own snapshot, not the device's.
	if !VerifyAttestation(signer.Pub, sig, p.controller.AttestationBinding(), firmware, 7, nonce) {
		t.Fatal("valid attestation rejected")
	}

	t.Run("rejects tampered inputs", func(t *testing.T) {
		ctrlBinding := p.controller.AttestationBinding()
		cases := []struct {
			name     string
			binding  []byte
			firmware []byte
			version  int64
			nonce    []byte
		}{
			{"downgraded version", ctrlBinding, firmware, 6, nonce},
			{"swapped firmware", ctrlBinding, []byte("other-image"), 7, nonce},
			{"replayed into another session", established(t).controller.AttestationBinding(), firmware, 7, nonce},
			{"different nonce", ctrlBinding, firmware, 7, []byte("another-16-bytes")},
		}
		for _, tc := range cases {
			if VerifyAttestation(signer.Pub, sig, tc.binding, tc.firmware, tc.version, tc.nonce) {
				t.Errorf("%s: attestation accepted", tc.name)
			}
		}
	})

	t.Run("absent signer is not success", func(t *testing.T) {
		if VerifyAttestation(nil, nil, binding, firmware, 7, nonce) {
			t.Error("missing key and signature verified as valid")
		}
		if VerifyAttestation(signer.Pub, nil, binding, firmware, 7, nonce) {
			t.Error("missing signature verified as valid")
		}
	})
}

func TestAttestationInput_fieldsAreUnambiguous(t *testing.T) {
	// Without length prefixes, moving a byte across a field boundary would
	// produce identical signed bytes and let one signature stand for two
	// different claims.
	a := AttestationInput([]byte("aa"), []byte("bb"), 1, []byte("cc"))
	b := AttestationInput([]byte("aab"), []byte("b"), 1, []byte("cc"))
	if bytes.Equal(a, b) {
		t.Error("attestation inputs collide across a field boundary")
	}
}

func TestParseDeviceKeys(t *testing.T) {
	keys, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	privHex := hex.EncodeToString(keys.Static.Private)
	pubHex := hex.EncodeToString(keys.Static.Public)

	got, err := ParseDeviceKeys(privHex, pubHex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(got.Static.Public, keys.Static.Public) {
		t.Error("parsed public key differs")
	}

	other, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("other keys: %v", err)
	}
	if _, err := ParseDeviceKeys(privHex, hex.EncodeToString(other.Static.Public)); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("mismatched pair: %v, want ErrKeyMismatch", err)
	}
	if _, err := ParseDeviceKeys("zz", pubHex); err == nil {
		t.Error("non-hex private key accepted")
	}
	if _, err := ParseDeviceKeys(hex.EncodeToString([]byte{1, 2, 3}), pubHex); err == nil {
		t.Error("short private key accepted")
	}
}

func TestSigningKey_nilSafe(t *testing.T) {
	var k *SigningKey
	if sig := k.Sign([]byte("msg")); sig != nil {
		t.Error("nil signing key produced a signature")
	}
	if sig := (&SigningKey{}).Sign([]byte("msg")); sig != nil {
		t.Error("empty signing key produced a signature")
	}
}

func TestProtocolName_matchesSuite(t *testing.T) {
	// The advertised name must match what the library actually negotiates, since
	// the whole vouchability argument rests on it.
	want := "Noise_IK_" + string(CipherSuite.Name())
	if ProtocolName != want {
		t.Errorf("ProtocolName = %q, but the suite builds %q", ProtocolName, want)
	}
}

func TestAAD_domainSeparated(t *testing.T) {
	if bytes.Equal(AAD("a"), AAD("b")) {
		t.Error("distinct labels produced the same AAD")
	}
	if len(AAD("a")) != 32 {
		t.Error("AAD is not 32 bytes")
	}
	if !bytes.Equal(AAD("a"), AAD("a")) {
		t.Error("AAD is not deterministic")
	}
}

func TestControllerIdentity_signingKeyIsNotTheStatic(t *testing.T) {
	id, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if len(id.Signing.Pub) != ed25519.PublicKeySize {
		t.Errorf("signing pub is %d bytes", len(id.Signing.Pub))
	}
	// Separate keys: compromise of the audit signer must not imply compromise
	// of the channel identity.
	if bytes.Equal(id.Signing.Pub, id.Static.Public) {
		t.Error("signing key and static key are the same material")
	}
}

func TestNewControllerIdentityFrom_roundTrip(t *testing.T) {
	orig, err := NewControllerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	got, err := NewControllerIdentityFrom(orig.Static.Private, orig.Signing.Priv)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !bytes.Equal(got.Static.Public, orig.Static.Public) {
		t.Error("rebuilt static public differs")
	}
	if !bytes.Equal(got.Signing.Pub, orig.Signing.Pub) {
		t.Error("rebuilt signing public differs")
	}

	// A rebuilt identity must actually work as a handshake identity.
	devKeys, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("device keys: %v", err)
	}
	c, err := NewController(ControllerConfig{Identity: got, DeviceStatic: devKeys.Static.Public, Scope: testScope})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	d, err := NewDevice(DeviceConfig{Keys: devKeys, ControllerStatic: orig.Static.Public, Scope: testScope})
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	msg1, err := c.Hello(nil)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := d.ReadHello(msg1); err != nil {
		t.Errorf("device rejected a rebuilt identity: %v", err)
	}

	if _, err := NewControllerIdentityFrom([]byte{1, 2}, orig.Signing.Priv); err == nil {
		t.Error("short static accepted")
	}
	if _, err := NewControllerIdentityFrom(orig.Static.Private, ed25519.PrivateKey("short")); err == nil {
		t.Error("short signing key accepted")
	}

	// Signing is optional: a controller that only ever opens channels does not
	// need an audit signer.
	noSigner, err := NewControllerIdentityFrom(orig.Static.Private, nil)
	if err != nil {
		t.Fatalf("no-signer identity: %v", err)
	}
	if noSigner.Signing != nil {
		t.Error("nil signing key produced a signer")
	}
}

func TestNewDeviceKeysFrom_roundTrip(t *testing.T) {
	orig, err := NewDeviceKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	got, err := NewDeviceKeysFrom(orig.Static.Private)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !bytes.Equal(got.Static.Public, orig.Static.Public) {
		t.Error("rebuilt device public differs")
	}
	if _, err := NewDeviceKeysFrom([]byte{9}); err == nil {
		t.Error("short key accepted")
	}
}
