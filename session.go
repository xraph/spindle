package spindle

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/flynn/noise"
)

// HeaderSize is the on-wire size of the DATA frame preamble.
const HeaderSize = 16 // 8B session ID + 8B sequence

// MaxSeq is the highest usable sequence number. Beyond it the session must
// rehandshake; Spindle never wraps.
const MaxSeq = noise.MaxNonce

// DefaultReplayWindow is a reasonable out-of-order tolerance for a lossy
// pub/sub link.
const DefaultReplayWindow = 64

// Session is an established Spindle channel. It is safe for concurrent use.
//
// The frame layout is:
//
//	| 8B sessionID | 8B seq | ciphertext || 16B tag |
//
// The AEAD nonce is not transmitted — it is the sequence number, which is
// already in the header. Sending it separately would add bytes and hand an
// attacker a degree of freedom over nonce selection.
type Session struct {
	id      uint64
	binding []byte

	mu     sync.Mutex
	tx     *noise.CipherState
	rx     *noise.CipherState
	window *ReplayWindow
}

func newSession(binding []byte, tx, rx *noise.CipherState) *Session {
	b := cloneBinding(binding)
	return &Session{
		id:      deriveSessionID(b),
		binding: b,
		tx:      tx,
		rx:      rx,
		window:  NewReplayWindow(DefaultReplayWindow),
	}
}

// ID returns the session identifier carried in every frame header. Both
// endpoints derive it from the handshake, so it never crosses the wire during
// the handshake and cannot disagree between peers.
func (s *Session) ID() uint64 { return s.id }

// Binding returns the completed handshake hash. It uniquely identifies this
// session and is suitable as a channel binding for signatures made after the
// handshake, such as audit-log heads.
func (s *Session) Binding() []byte { return cloneBinding(s.binding) }

// SetReplayWindow replaces the out-of-order tolerance. A size of 0 makes the
// receiver strictly monotonic. Call before the session carries traffic.
func (s *Session) SetReplayWindow(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.window = NewReplayWindow(size)
}

// TxSeq returns the sequence number the next Seal will use.
func (s *Session) TxSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tx.Nonce()
}

// Seal encrypts plaintext into a DATA frame. aad binds the frame to a class of
// traffic — pass the same value on both endpoints, from AAD — so a frame sealed
// for one class cannot be accepted as another.
func (s *Session) Seal(aad, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxFramePayload {
		return nil, ErrPayloadTooLarge
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seq := s.tx.Nonce()
	if seq >= MaxSeq {
		return nil, ErrSeqExhausted
	}

	out := make([]byte, 0, HeaderSize+len(plaintext)+16)
	out = binary.BigEndian.AppendUint64(out, s.id)
	out = binary.BigEndian.AppendUint64(out, seq)

	out, err := s.tx.Encrypt(out, aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("spindle: seal: %w", err)
	}
	return out, nil
}

// Open authenticates and decrypts a DATA frame, returning the plaintext and the
// frame's sequence number.
//
// Frames may arrive out of order, so the receiving cipher state's nonce is
// driven from the header rather than from an internal counter. The replay window
// is consulted only after authentication succeeds: a frame that fails its AEAD
// check never marks a sequence number as seen, so an attacker cannot exhaust the
// window with forged frames. The cost is that a replayed frame is decrypted
// before being rejected — acceptable, since only a genuine captured frame can
// reach that point at all.
func (s *Session) Open(aad, frame []byte) (plaintext []byte, seq uint64, err error) {
	if len(frame) < HeaderSize+16 {
		return nil, 0, ErrShortFrame
	}

	id := binary.BigEndian.Uint64(frame[0:8])
	seq = binary.BigEndian.Uint64(frame[8:16])
	if id != s.id {
		return nil, seq, ErrSessionMismatch
	}
	if seq > MaxSeq {
		return nil, seq, ErrSeqExhausted
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rx.SetNonce(seq)
	plaintext, err = s.rx.Decrypt(nil, aad, frame[HeaderSize:])
	if err != nil {
		return nil, seq, fmt.Errorf("spindle: open: %w", err)
	}

	if !s.window.Accept(seq) {
		return nil, seq, ErrReplay
	}
	return plaintext, seq, nil
}
