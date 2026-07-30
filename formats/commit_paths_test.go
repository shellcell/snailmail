package formats

import (
	"testing"

	"github.com/shellcell/snailmail/formats/rpm"
)

// A commit path is what a host uses to decide whether it can make a revision live
// atomically, so it has to name everything that actually has to switch together.
// A signature that lagged its index by one revision is a repository a client
// refuses, not a cosmetic mismatch.
func TestASignedYumRepositorySwitchesItsSignatureToo(t *testing.T) {
	unsigned := rpmFormat{}.CommitPaths(Repository{})
	if len(unsigned) != 1 || unsigned[0] != rpm.RepomdPath {
		t.Errorf("unsigned commit paths = %v", unsigned)
	}
	signed := rpmFormat{}.CommitPaths(Repository{Signed: true})
	if len(signed) != 2 {
		t.Fatalf("signed commit paths = %v, want repomd.xml and its signature", signed)
	}
	var hasSignature bool
	for _, path := range signed {
		if path == rpm.SignaturePath {
			hasSignature = true
		}
	}
	if !hasSignature {
		t.Errorf("signed commit paths = %v, want %q among them", signed, rpm.SignaturePath)
	}
}

// The consequence, and the reason this matters: an object store commits one
// object, so a signed yum repository cannot be made live there — the same
// limitation Debian has, for the same reason. Reporting one path would have let a
// host accept it and publish a torn revision.
func TestSigningChangesWhetherAFormatFitsAnObjectStore(t *testing.T) {
	for _, format := range []string{"rpm", "deb"} {
		selected, err := For(format)
		if err != nil {
			t.Fatal(err)
		}
		signed := selected.CommitPaths(Repository{Suite: "stable", Signed: true})
		if len(signed) < 2 {
			t.Errorf("signed %s commits %d paths, want more than one", format, len(signed))
		}
	}
	// Helm is unaffected: provenance is published beside each chart at a path
	// fixed by that chart's version, so signing adds nothing that has to switch.
	helm, err := For("helm")
	if err != nil {
		t.Fatal(err)
	}
	if paths := helm.CommitPaths(Repository{Signed: true}); len(paths) != 1 {
		t.Errorf("signed helm commits %v, want only its index", paths)
	}
}
