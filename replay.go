package spindle

import "sync"

// bitmapWidth is the number of sequence numbers a single window word can track.
const bitmapWidth = 64

// ReplayWindow tracks the highest accepted sequence number plus a sliding bitmap
// of recent acceptances, so slightly out-of-order frames are accepted while
// duplicates are rejected. Out-of-order delivery is normal on pub/sub links, so
// strict monotonicity would drop legitimate traffic.
//
// One window per direction per session.
type ReplayWindow struct {
	mu      sync.Mutex
	size    uint64 // out-of-order tolerance, in frames
	top     uint64 // highest sequence accepted so far
	bitmap  uint64 // bit i set ⇒ sequence (top-i) already accepted
	started bool   // false until the first frame is accepted
}

// NewReplayWindow returns a window with the given out-of-order tolerance. A size
// of 0 makes the window strictly monotonic. Sizes above 64 are clamped, since
// the bitmap is a single 64-bit word.
func NewReplayWindow(size uint64) *ReplayWindow {
	if size > bitmapWidth {
		size = bitmapWidth
	}
	return &ReplayWindow{size: size}
}

// Accept reports whether seq is fresh, and records it if so. A false return
// leaves the window unchanged, so a rejected frame never consumes a slot.
func (w *ReplayWindow) Accept(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// A zero-valued window has top == 0, which is also a legitimate first
	// sequence number — sequences start at 0. Without this flag the opening
	// frame of every session would be mistaken for a duplicate of itself.
	if !w.started {
		w.started = true
		w.top = seq
		w.bitmap = 1
		return true
	}

	switch {
	case seq > w.top:
		shift := seq - w.top
		if shift >= bitmapWidth {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.top = seq
		return true

	case seq == w.top:
		return false

	default: // seq < w.top
		diff := w.top - seq
		if diff >= w.size {
			return false
		}
		bit := uint64(1) << diff
		if w.bitmap&bit != 0 {
			return false
		}
		w.bitmap |= bit
		return true
	}
}
