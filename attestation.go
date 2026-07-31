package spindle

import (
	"crypto/ed25519"
	"encoding/binary"
)

// AttestationInput builds the byte string a device signs to attest its running
// firmware, and that the controller reconstructs to verify it.
//
// binding is the post-message-1 handshake snapshot from
// Device.AttestationBinding or Controller.AttestationBinding. Because that value
// covers the prologue, both static keys, the controller's fresh ephemeral, and
// the message-1 payload, a signature over it cannot be lifted from one session
// and replayed into another.
//
// Every variable-length field is length-prefixed. Without that, a firmware hash
// of a different length would shift the bytes that follow, and one endpoint's
// signature could be reinterpreted as a signature over different values.
func AttestationInput(binding, firmwareHash []byte, firmwareVersion int64, nonce []byte) []byte {
	out := make([]byte, 0, len(binding)+len(firmwareHash)+len(nonce)+16)
	out = appendField(out, binding)
	out = appendField(out, firmwareHash)
	out = binary.BigEndian.AppendUint64(out, uint64(firmwareVersion))
	out = appendField(out, nonce)
	return out
}

// VerifyAttestation checks sig over the attestation input for the given device
// signing key. A device with no provisioned signing key produces no signature,
// so an empty key or signature is reported as invalid rather than as success —
// deployments that require attestation must provision a signer.
func VerifyAttestation(devicePub ed25519.PublicKey, sig, binding, firmwareHash []byte, firmwareVersion int64, nonce []byte) bool {
	if len(devicePub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(devicePub, AttestationInput(binding, firmwareHash, firmwareVersion, nonce), sig)
}

func appendField(acc, field []byte) []byte {
	acc = binary.BigEndian.AppendUint32(acc, uint32(len(field)))
	return append(acc, field...)
}
