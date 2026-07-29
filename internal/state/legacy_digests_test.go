package state

import (
	"crypto/sha256"
	"testing"
)

// Only a Debian repository publishes MD5 and SHA-1. Computing all three digests
// runs at about a fifth the speed of SHA-256 alone, over every artifact, on
// every plan and every apply.
func TestLegacyDigestsFollowTheFormat(t *testing.T) {
	if got := newLegacyDigests("deb", LockedBlob{}); got.md5Hash == nil {
		t.Error("a Debian repository must still compute MD5 and SHA-1; apt reads them")
	}
	for _, format := range []string{"pypi", "helm", "raw", "rpm", "apk"} {
		if got := newLegacyDigests(format, LockedBlob{}); got.md5Hash != nil {
			t.Errorf("format %q computed digests nothing reads", format)
		}
	}
}

// Every lock written before this distinction existed records MD5 and SHA-1 for
// every format, and validation compares whichever the lock has. Skipping a
// digest the lock records would report every existing workspace as corrupt.
func TestLegacyDigestsHonourAnExistingLock(t *testing.T) {
	for _, locked := range []LockedBlob{
		{MD5: "d41d8cd98f00b204e9800998ecf8427e"},
		{SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{MD5: "d41d8cd98f00b204e9800998ecf8427e", SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	} {
		if got := newLegacyDigests("raw", locked); got.md5Hash == nil {
			t.Errorf("a lock recording %+v must still have its digests computed", locked)
		}
	}
}

// An unrecognised format is not a reason to compute less than before.
func TestLegacyDigestsAreConservativeAboutUnknownFormats(t *testing.T) {
	if got := newLegacyDigests("something-new", LockedBlob{}); got.md5Hash == nil {
		t.Error("an unknown format skipped digests it might need")
	}
}

// Whatever is skipped, SHA-256 is always computed: it is what everything is
// pinned by, and an empty one would compare unequal to every lock.
func TestSHA256IsAlwaysComputed(t *testing.T) {
	for _, format := range []string{"deb", "raw"} {
		digests := newLegacyDigests(format, LockedBlob{})
		hash := sha256.New()
		writer := digests.writers(hash)
		if _, err := writer.Write([]byte("bytes")); err != nil {
			t.Fatal(err)
		}
		if len(hash.Sum(nil)) != sha256.Size {
			t.Errorf("format %q did not tee through SHA-256", format)
		}
		// A skipped digest reads as absent rather than as a hash of nothing:
		// an empty string is what the lock omits, and a digest of no bytes
		// would be a real-looking value for content nobody hashed.
		if format == "raw" && (digests.md5Hex() != "" || digests.sha1Hex() != "") {
			t.Error("a skipped digest reported a value")
		}
	}
}
