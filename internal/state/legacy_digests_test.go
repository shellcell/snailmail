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

// A lock written before these were computed by need records MD5 and SHA-1 for
// every format. Those values are not recomputed to be checked against: the
// content is pinned by SHA-256, so bytes matching it match every other digest
// of them too, and an hour of hashing per publication bought nothing.
func TestRecordedLegacyDigestsDoNotForceTheWork(t *testing.T) {
	for _, locked := range []LockedBlob{
		{MD5: "d41d8cd98f00b204e9800998ecf8427e"},
		{SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{MD5: "d41d8cd98f00b204e9800998ecf8427e", SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	} {
		if got := newLegacyDigests("raw", locked); got.md5Hash != nil {
			t.Errorf("a lock recording %+v made a format that publishes neither compute them", locked)
		}
	}
	// Debian still does, whatever the lock says, because apt reads them.
	if got := newLegacyDigests("deb", LockedBlob{}); got.md5Hash == nil {
		t.Error("a Debian repository stopped computing digests apt reads")
	}
}

// An artifact already in a lock that records digests this format no longer
// derives must still be accepted. Treating an absent value as a disagreement
// refused to re-add or re-adopt anything already published — which is every
// artifact in a workspace that has published before.
func TestReAddingAgainstAnOlderLock(t *testing.T) {
	existing := LockedBlob{
		Filename: "demo.tar.gz", Size: 10, SHA256: "abc",
		MD5: "d41d8cd98f00b204e9800998ecf8427e", SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	}
	derived := LockedBlob{Filename: "demo.tar.gz", Size: 10, SHA256: "abc"}
	if legacyDigestConflict(existing, derived) {
		t.Error("an absent digest was read as contradicting a recorded one")
	}
	if legacyDigestConflict(derived, existing) {
		t.Error("a recorded digest was read as contradicting an absent one")
	}
	// A genuine contradiction is still one.
	wrong := existing
	wrong.MD5 = "00000000000000000000000000000000"
	if !legacyDigestConflict(existing, wrong) {
		t.Error("two different MD5s for the same bytes were accepted")
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

// The blob validator compares a recorded digest against a derived one, and it
// must apply the same rule as the lock writer: compare where both are known.
//
// This was missed when the writer was fixed, and every existing workspace
// reported its own artifacts as corrupt — "blob sha256:... disagrees with its
// lock" — because the lock recorded an MD5 the reader no longer derives.
func TestValidationDoesNotDemandDigestsItNoLongerDerives(t *testing.T) {
	recorded := LockedBlob{
		SHA256: "abc",
		MD5:    "d41d8cd98f00b204e9800998ecf8427e",
		SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	}
	derived := LockedBlob{SHA256: "abc"}
	if legacyDigestConflict(recorded, derived) {
		t.Fatal("a lock recording digests this format no longer derives was read as corrupt")
	}
	// A format that does derive them still has them checked.
	wrong := LockedBlob{SHA256: "abc", MD5: "00000000000000000000000000000000"}
	if !legacyDigestConflict(recorded, wrong) {
		t.Error("a derived MD5 that contradicts the lock was accepted")
	}
}
