package state

import (
	"github.com/shellcell/snailmail/formats"
	"os"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/factscache"
	"github.com/shellcell/snailmail/internal/testutil"
)

// A memo keyed by digest must never let corrupt bytes through: the digest is
// re-derived from the file on every call, and only content that matches its
// lock is allowed to consult previously derived facts.
func TestLockedBlobValidationRejectsCorruptBytesDespiteCachedFacts(t *testing.T) {
	factscache.Reset()
	t.Cleanup(factscache.Reset)

	root := t.TempDir()
	source, err := testutil.WriteWheel(t.TempDir(), "snail-demo", "1.2.3", ">=3.9")
	if err != nil {
		t.Fatal(err)
	}

	blob, err := PutArtifact(root, "pypi", source, formats.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	locked := ToLockedBlob(blob)

	// Prime the memo through a successful validation.
	if _, _, err := LoadBlob(root, "pypi", locked, formats.Identity{}); err != nil {
		t.Fatal(err)
	}
	if _, found := factscache.Lookup("pypi", locked.SHA256); !found {
		t.Fatal("expected verified facts to be memoised")
	}

	// Corrupt the stored object while keeping the lock's digest.
	stored := filepath.Join(root, ".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)
	if err := os.Chmod(stored, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, []byte("not a wheel at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadBlob(root, "pypi", locked, formats.Identity{}); err == nil {
		t.Fatal("corrupt CAS object was accepted because facts were cached")
	}
}
