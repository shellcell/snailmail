package hexdigest

import (
	"strings"
	"testing"
)

// Case matters. The same bytes written two ways compare unequal everywhere
// digests are compared as strings, which is nearly everywhere in this project,
// so an uppercase digest has to be refused rather than quietly folded.
func TestValidSHA256(t *testing.T) {
	lower := strings.Repeat("ab", 32)
	if !ValidSHA256(lower) {
		t.Fatal("a lowercase 64-character hex digest was refused")
	}
	for _, value := range []string{
		strings.ToUpper(lower),
		strings.Repeat("ab", 31), // too short
		strings.Repeat("ab", 33), // too long
		strings.Repeat("zz", 32), // not hex
		" " + lower,              // padded
		lower + "\n",             // trailing newline
		"",                       // absent
		"sha256:" + lower,        // prefixed the way a reference is written
	} {
		if ValidSHA256(value) {
			t.Errorf("accepted %q as a SHA-256", value)
		}
	}
}

// An OpenPGP v4 fingerprint is 20 bytes, not 32; the two must not be
// interchangeable, or a key could be pinned by something that is not one.
func TestValidFingerprint(t *testing.T) {
	fingerprint := strings.Repeat("ab", 20)
	if !ValidFingerprint(fingerprint) {
		t.Fatal("a lowercase 40-character hex fingerprint was refused")
	}
	if ValidFingerprint(strings.Repeat("ab", 32)) {
		t.Error("a SHA-256 was accepted as a fingerprint")
	}
	if ValidSHA256(fingerprint) {
		t.Error("a fingerprint was accepted as a SHA-256")
	}
	if ValidFingerprint(strings.ToUpper(fingerprint)) {
		t.Error("an uppercase fingerprint was accepted")
	}
}

// S3 reports checksums base64-encoded while everything here compares hex. An
// unreadable value becomes empty, which fails the comparison it was fetched
// for — the same outcome as an absent checksum, and the safe one.
func TestFromBase64(t *testing.T) {
	if got := FromBase64("q80="); got != "abcd" {
		t.Errorf("FromBase64 = %q, want %q", got, "abcd")
	}
	for _, value := range []string{"not base64!!", "%%%", "a"} {
		if got := FromBase64(value); got != "" {
			t.Errorf("FromBase64(%q) = %q, want empty", value, got)
		}
	}
	// A valid conversion must round-trip into something ValidSHA256 accepts,
	// since that is the only reason this function exists.
	digest := FromBase64("q83vq83vq83vq83vq83vq83vq83vq83vq83vq83vq80=")
	if !ValidSHA256(digest) {
		t.Errorf("a converted 32-byte checksum is not a valid SHA-256: %q", digest)
	}
}
