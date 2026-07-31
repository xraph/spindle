// Package spindle provides an end-to-end secure channel for remote control of
// physical and virtual devices across an untrusted message broker.
//
// The problem it solves is narrow and specific: MQTT and similar pub/sub
// transports terminate TLS at the broker, so the broker sees every control
// command in plaintext. When the command actuates real hardware, the broker is
// part of the trust boundary whether you wanted it to be or not. Spindle moves
// confidentiality and authenticity to the endpoints, so a compromised broker
// can drop, reorder, or observe ciphertext but cannot read or forge a command.
//
// # Protocol
//
// The channel is Noise_IK_25519_ChaChaPoly_BLAKE2b, unmodified. The controller
// is the Noise initiator and pins the device's static public key at
// provisioning time; the device is the responder and pins the controller's
// static public key. There is exactly one pattern and no negotiation, so there
// is no downgrade surface.
//
//	controller → device   msg1: e, es, s, ss  + encrypted payload
//	device → controller   msg2: e, ee, se     + encrypted payload
//	controller ⇄ device   DATA[sessionID, seq, ciphertext(tag)]
//
// Deployment context is bound into the handshake through the Noise prologue
// (see BuildPrologue), so a device provisioned for one scope cannot be
// re-pointed at another without re-provisioning: the prologue mismatch makes
// the handshake fail rather than producing a working session in the wrong
// place.
//
// # Out-of-order delivery
//
// Noise's CipherState assumes an ordered stream. Pub/sub transports do not
// provide one. Spindle therefore carries an explicit sequence number in each
// frame header and drives the receiving CipherState's nonce from the wire
// value, gated by a sliding ReplayWindow. This is the one place where Spindle
// deliberately steps outside the plain Noise transport model, and it is the
// reason this package exists rather than a bare Noise handle:
//
//   - Duplicate and already-seen sequence numbers are rejected before any
//     decryption is attempted.
//   - A frame that fails authentication never marks its sequence number as
//     seen, so a forged frame cannot burn a window slot.
//   - Sequence exhaustion is a hard error (ErrSeqExhausted) rather than a
//     silent wrap.
//
// # What this package does not do
//
// Spindle is the channel and the commissioning primitives only. Device
// registry, authorization, command semantics, and audit logging belong to the
// caller. Long-term key rotation is likewise out of band: there is no in-band
// rotation message, by design.
package spindle
