package spindle

import "errors"

var (
	// ErrReplay means a DATA frame's sequence number was already seen or has
	// fallen out of the receiver's window. The frame is discarded; the session
	// stays usable.
	ErrReplay = errors.New("spindle: replay detected")

	// ErrShortFrame means a DATA frame was truncated before its AEAD tag.
	ErrShortFrame = errors.New("spindle: short frame")

	// ErrSessionMismatch means a DATA frame carried a session identifier that
	// does not belong to this session — usually a frame from a previous session
	// arriving after a rekey.
	ErrSessionMismatch = errors.New("spindle: frame belongs to a different session")

	// ErrSeqExhausted means the send counter reached its maximum. The session
	// must be torn down and a fresh handshake performed. Spindle refuses to
	// wrap: reusing a (key, nonce) pair under ChaCha20-Poly1305 is catastrophic,
	// so exhaustion is a hard stop rather than a silent overflow.
	ErrSeqExhausted = errors.New("spindle: sequence space exhausted, rehandshake required")

	// ErrPayloadTooLarge means a plaintext exceeded MaxFramePayload.
	ErrPayloadTooLarge = errors.New("spindle: payload exceeds maximum frame size")

	// ErrHandshakeState means a handshake method was called out of order.
	ErrHandshakeState = errors.New("spindle: handshake called out of sequence")

	// ErrMissingStatic means a required long-term key was absent from a config.
	ErrMissingStatic = errors.New("spindle: missing static keypair")

	// ErrMissingPeerStatic means the pinned peer static key was absent. Spindle
	// never completes a handshake against an unpinned peer — pinning at
	// provisioning time is the MITM defence.
	ErrMissingPeerStatic = errors.New("spindle: missing pinned peer static key")

	// ErrKeyMismatch means a parsed keypair's public key does not derive from
	// its private key.
	ErrKeyMismatch = errors.New("spindle: public key does not match private key")

	// ErrScopeTooLong means a config carried a scope beyond MaxScopeLen. The
	// prologue's 16-bit length prefix cannot describe it, and silently truncating
	// would let two different scopes produce the same prologue.
	ErrScopeTooLong = errors.New("spindle: scope exceeds the maximum length the prologue can bind")

	// ErrPinAndCommissioning means a device config set both ControllerStatic and
	// Commissioning. They are mutually exclusive: one enforces a pin, the other
	// suspends enforcement, and guessing which was intended is not this
	// package's call to make.
	ErrPinAndCommissioning = errors.New("spindle: ControllerStatic and Commissioning are mutually exclusive")

	// ErrControllerNotPinned means message 1 carried a controller static key
	// other than the one this device was commissioned against. The peer proved
	// it holds the private key, so this is not a forgery — it is the wrong
	// controller, which is exactly what pinning exists to catch.
	ErrControllerNotPinned = errors.New("spindle: controller static key does not match pinned value")
)
