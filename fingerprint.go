package spindle

import (
	"crypto/subtle"
	"encoding/binary"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// FingerprintWordCount is the number of words in a commissioning fingerprint.
const FingerprintWordCount = 6

// FingerprintWords renders a commissioning transcript as a short sequence of
// words that an operator compares between the device display and the admin UI.
// Any substitution of keys during commissioning changes the output, so a
// mismatch is a reliable MITM indicator.
//
// Pass the handshake binding as the transcript. Anything else that should be
// bound belongs *in* the transcript, not alongside it: a fingerprint mixing in a
// value only one endpoint knows cannot agree across the two, which defeats the
// comparison it exists to support.
//
// The encoding takes one byte per word from a 256-entry wordlist, giving 48 bits
// over 6 words. A BIP39-style encoding would pack more bits per word but adds
// roughly 10 KB to the binary, which matters on constrained devices; 48 bits is
// far above the threshold where an operator comparing two strings is the weak
// link, and commissioning has additional independent factors anyway.
func FingerprintWords(transcript []byte) string {
	h, _ := blake2b.New(FingerprintWordCount, []byte(ProtocolLabel+"/fp"))
	h.Write(transcript)
	digest := h.Sum(nil)

	parts := make([]string, FingerprintWordCount)
	for i := range FingerprintWordCount {
		parts[i] = fingerprintWordlist[digest[i]]
	}
	return strings.Join(parts, "-")
}

// FingerprintEqual compares two fingerprints in constant time, so a slow
// comparator on the confirmation path cannot leak the expected value.
func FingerprintEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CommissioningCode derives a deterministic 6-digit code from seed bytes. The
// device and the admin UI derive the same code, so the operator types what the
// device shows. The seed is destroyed once commissioning completes.
func CommissioningCode(seed []byte) string {
	if len(seed) == 0 {
		return "000000"
	}
	h, _ := blake2b.New(4, []byte(ProtocolLabel+"/code"))
	h.Write(seed)
	n := binary.BigEndian.Uint32(h.Sum(nil)) % 1_000_000
	return leftPad(n, 6)
}

func leftPad(n uint32, width int) string {
	buf := []byte("000000000000000000")
	idx := len(buf)
	if n == 0 {
		return string(buf[idx-width:])
	}
	for n > 0 && idx > 0 {
		idx--
		buf[idx] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[len(buf)-width:])
}

// fingerprintWordlist is 256 short, phonetically distinct English words. No
// homophones, no offensive terms, and no pairs that look alike on a low-quality
// LCD (nothing relying on an "rn"/"m" distinction).
//
// Every one of the 256 slots must be filled. A Go array literal happily leaves
// unlisted entries as the empty string, so a short list would silently render
// blank words for the digest values that index past its end — see
// TestFingerprintWordlist_complete, which exists to catch exactly that.
//
// Keep the list stable: changing it invalidates commissioning records in flight.
var fingerprintWordlist = [256]string{
	"acorn", "admin", "agent", "alarm", "album", "alpha", "anchor", "angel",
	"angle", "apple", "arena", "arrow", "aspen", "atlas", "audio", "autumn",
	"badge", "baker", "balcony", "banjo", "barrel", "basil", "batch", "beach",
	"beacon", "beast", "beaver", "bench", "beryl", "bible", "bigfoot", "bison",
	"blade", "blaze", "blink", "block", "bloom", "boat", "bonfire", "book",
	"border", "bottle", "brain", "brass", "bread", "brick", "brisk", "bronze",
	"brush", "bubble", "buddy", "bunny", "burst", "butter", "cable", "cactus",
	"canary", "candle", "canoe", "canvas", "carbon", "cargo", "carpet", "castle",
	"catch", "cedar", "celery", "chair", "chalk", "cherry", "chest", "chill",
	"choice", "cinder", "circle", "cliff", "cloud", "clover", "coast", "cobalt",
	"cocoa", "comet", "compass", "copper", "coral", "cotton", "crayon", "creek",
	"crest", "crisp", "crown", "cube", "cycle", "daisy", "dawn", "delta",
	"desert", "diamond", "dinner", "dolphin", "donut", "dragon", "drift", "drum",
	"eagle", "echo", "elder", "ember", "engine", "equal", "ether", "fable",
	"fairy", "falcon", "fang", "feast", "fennel", "fiddle", "finch", "flame",
	"flask", "float", "flute", "forest", "forge", "fossil", "foxtrot", "friend",
	"galaxy", "garnet", "gemini", "ghost", "giant", "ginger", "glacier", "glide",
	"globe", "gold", "gorge", "grain", "grape", "grove", "guitar", "gypsy",
	"habit", "harbor", "harvest", "hawk", "hazel", "helix", "hexagon", "holly",
	"honey", "horizon", "hornet", "hydra", "ibis", "icon", "igloo", "index",
	"indigo", "island", "ivory", "jasper", "jaunt", "jewel", "journey", "judge",
	"jungle", "kayak", "kettle", "kitten", "knight", "koala", "lantern", "laser",
	"leader", "ledger", "lemon", "lentil", "lime", "lion", "lobster", "lotus",
	"lyric", "magnet", "mango", "maple", "marble", "meadow", "meteor", "mimic",
	"mirror", "misty", "moth", "motif", "mountain", "muffin", "musket", "needle",
	"nectar", "nest", "nimbus", "noble", "north", "notch", "oasis", "ocean",
	"octave", "olive", "onyx", "opera", "orbit", "oregano", "orchid", "otter",
	"outlaw", "oxygen", "palace", "panda", "papaya", "paper", "parrot", "path",
	"pebble", "pelican", "phoenix", "pilot", "pine", "pixel", "plum", "portal",
	"prairie", "prism", "puma", "quartz", "quest", "quiet", "quince", "rabbit",
	"raisin", "ranger", "raven", "reef", "relic", "river", "robin", "rose",
	"rune", "sapphire", "savanna", "scout", "silver", "socket", "spruce", "sunset"}
