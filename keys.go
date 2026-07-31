package spindle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// DHLen is the length of an X25519 public or private key in bytes.
const DHLen = 32

// SigningKey is an Ed25519 keypair used for signatures that sit above the
// channel: firmware attestation on the device side, audit-log heads on the
// controller side.
//
// It is deliberately not part of the handshake. Under Noise_IK both peers are
// authenticated by their static X25519 keys through the DH pattern itself, so a
// signature over the transcript would be redundant. Keeping the signing key
// separate means compromise of one does not imply compromise of the other.
type SigningKey struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// NewSigningKey generates a fresh Ed25519 keypair.
func NewSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("spindle: generate signing key: %w", err)
	}
	return &SigningKey{Priv: priv, Pub: pub}, nil
}

// Sign produces a detached Ed25519 signature over msg.
func (k *SigningKey) Sign(msg []byte) []byte {
	if k == nil || len(k.Priv) == 0 {
		return nil
	}
	return ed25519.Sign(k.Priv, msg)
}

// ControllerIdentity is the controlling side's long-term identity.
//
// Static is the X25519 keypair that devices pin at provisioning time; it is the
// controller's handshake identity. Signing is optional and used only for
// out-of-channel signatures such as audit-log heads.
type ControllerIdentity struct {
	Static  noise.DHKey
	Signing *SigningKey
}

// NewControllerIdentity generates a controller identity with both a static
// X25519 keypair and an Ed25519 signing keypair. Callers persist all of it,
// with private material encrypted at rest.
func NewControllerIdentity() (*ControllerIdentity, error) {
	static, err := CipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("spindle: generate controller static: %w", err)
	}
	signing, err := NewSigningKey()
	if err != nil {
		return nil, err
	}
	return &ControllerIdentity{Static: static, Signing: signing}, nil
}

// NewControllerIdentityFrom rebuilds a controller identity from stored key
// material: a 32-byte X25519 static private key and an Ed25519 signing key.
//
// It exists so callers can load an identity from their own storage without
// importing the underlying Noise package to construct a DHKey.
func NewControllerIdentityFrom(staticPriv []byte, signPriv ed25519.PrivateKey) (*ControllerIdentity, error) {
	if len(staticPriv) != DHLen {
		return nil, fmt.Errorf("spindle: static private key must be %d bytes, got %d", DHLen, len(staticPriv))
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("spindle: derive static public: %w", err)
	}

	id := &ControllerIdentity{
		Static: noise.DHKey{
			Private: append([]byte(nil), staticPriv...),
			Public:  pub,
		},
	}
	if len(signPriv) > 0 {
		if len(signPriv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("spindle: signing key must be %d bytes, got %d", ed25519.PrivateKeySize, len(signPriv))
		}
		id.Signing = &SigningKey{
			Priv: signPriv,
			Pub:  signPriv.Public().(ed25519.PublicKey),
		}
	}
	return id, nil
}

// DeviceKeys is a device's long-term identity.
//
// Static is the X25519 keypair whose public half the controller pins in its
// device registry. Signing is optional; deployments that require firmware
// attestation must provision one during commissioning.
type DeviceKeys struct {
	Static  noise.DHKey
	Signing *SigningKey
}

// NewDeviceKeys generates a fresh device static keypair. It does not generate a
// signing key — call NewSigningKey separately when attestation is required, so
// that deployments which do not use it never carry the key material.
func NewDeviceKeys() (*DeviceKeys, error) {
	static, err := CipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("spindle: generate device static: %w", err)
	}
	return &DeviceKeys{Static: static}, nil
}

// NewDeviceKeysFrom rebuilds device keys from a stored 32-byte X25519 private
// key, deriving the public half.
func NewDeviceKeysFrom(staticPriv []byte) (*DeviceKeys, error) {
	if len(staticPriv) != DHLen {
		return nil, fmt.Errorf("spindle: static private key must be %d bytes, got %d", DHLen, len(staticPriv))
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("spindle: derive static public: %w", err)
	}
	return &DeviceKeys{Static: noise.DHKey{
		Private: append([]byte(nil), staticPriv...),
		Public:  pub,
	}}, nil
}

// ParseDeviceKeys reconstructs a device keypair from hex-encoded material, as
// carried in a provisioning file. It verifies that pub actually derives from
// priv, so a corrupted or mismatched provisioning file fails at load rather
// than as an unexplained handshake failure in the field.
func ParseDeviceKeys(privHex, pubHex string) (*DeviceKeys, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("spindle: decode private key: %w", err)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("spindle: decode public key: %w", err)
	}
	if len(priv) != DHLen {
		return nil, fmt.Errorf("spindle: private key must be %d bytes, got %d", DHLen, len(priv))
	}
	if len(pub) != DHLen {
		return nil, fmt.Errorf("spindle: public key must be %d bytes, got %d", DHLen, len(pub))
	}

	derived, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("spindle: derive public key: %w", err)
	}
	if subtle.ConstantTimeCompare(derived, pub) != 1 {
		return nil, ErrKeyMismatch
	}

	return &DeviceKeys{Static: noise.DHKey{Private: priv, Public: pub}}, nil
}
