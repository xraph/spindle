package spindle

import (
	"encoding/binary"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2b"
)

// ProtocolName is the Noise protocol name this package implements. It is fixed:
// there is no negotiation and no alternative pattern, so there is nothing an
// attacker can downgrade to.
const ProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2b"

// ProtocolLabel is the domain-separation label mixed into the prologue and into
// every derived value. Changing it is a protocol break — every device
// re-provisions.
const ProtocolLabel = "spindle/v2"

// MaxFramePayload is the largest plaintext a single DATA frame carries. Noise
// caps a message at 65535 bytes including the 16-byte AEAD tag; callers that
// need more must fragment above this layer.
const MaxFramePayload = 65535 - 16

// CipherSuite is the single suite this package uses. X25519 for DH,
// ChaCha20-Poly1305 for AEAD (constant-time in software, so devices without
// AES-NI are not penalised), BLAKE2b for hashing.
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)

// BuildPrologue constructs the Noise prologue from a deployment scope string.
//
// The prologue is hashed into the handshake state before any key material is
// exchanged, so both endpoints must derive the identical value or the handshake
// fails. This is what binds a session to its scope: a device commissioned for
// scope A cannot complete a handshake presented as scope B, because the
// controller's and device's prologues disagree and every subsequent MAC check
// fails.
//
// scope is length-prefixed so that adjacent values cannot collide — without it
// a scope of "ws" followed by trailing bytes could hash identically to "wsx".
func BuildPrologue(scope string) []byte {
	out := make([]byte, 0, len(ProtocolLabel)+2+len(scope))
	out = append(out, ProtocolLabel...)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(scope)))
	out = append(out, n[:]...)
	out = append(out, scope...)
	return out
}

// deriveSessionID turns a completed handshake's channel binding into a 64-bit
// session identifier.
//
// Both endpoints compute this independently from the same binding, so the
// identifier never travels on the wire during the handshake and there is no
// "session mismatch" case to check: a peer that derived a different binding
// could not have produced a valid frame in the first place. It is unique per
// handshake because the binding covers both fresh ephemeral keys.
func deriveSessionID(binding []byte) uint64 {
	h, _ := blake2b.New(8, []byte(ProtocolLabel+"/sid"))
	h.Write(binding)
	return binary.BigEndian.Uint64(h.Sum(nil))
}

// AAD derives a stable 32-byte authenticated-associated-data value from a
// domain label. Both endpoints pass the same label for a given frame class, so
// a frame sealed as one class cannot be accepted as another — a heartbeat
// cannot be replayed into the control path even though both use the same
// session key.
func AAD(label string) []byte {
	h, _ := blake2b.New256([]byte(ProtocolLabel + "/aad"))
	h.Write([]byte(label))
	return h.Sum(nil)
}
