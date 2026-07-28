package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/testutil"
)

// The blob path no longer runs the general workspace path check, so the os.Root
// handle is what keeps a CAS lookup inside the workspace. These hold that line.
func TestLoadBlobRejectsCASDirectorySymlinkedOutOfWorkspace(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	source, err := testutil.WriteWheel(t.TempDir(), "snail-demo", "1.2.3", ">=3.9")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := PutArtifact(root, "pypi", source)
	if err != nil {
		t.Fatal(err)
	}
	locked := ToLockedBlob(blob)

	// Move the whole shard outside the workspace and leave a symlink behind.
	shard := filepath.Join(root, ".snailmail", "cas", "sha256", locked.SHA256[:2])
	relocated := filepath.Join(outside, "shard")
	if err := os.Rename(shard, relocated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relocated, shard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadBlob(root, "pypi", locked); err == nil {
		t.Fatal("a CAS shard symlinked out of the workspace was accepted")
	}
}

func TestLoadBlobRejectsBlobThatIsItselfASymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	source, err := testutil.WriteWheel(t.TempDir(), "snail-demo", "1.2.3", ">=3.9")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := PutArtifact(root, "pypi", source)
	if err != nil {
		t.Fatal(err)
	}
	locked := ToLockedBlob(blob)

	stored := filepath.Join(root, ".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)
	relocated := filepath.Join(outside, "object")
	if err := os.Rename(stored, relocated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relocated, stored); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadBlob(root, "pypi", locked); err == nil {
		t.Fatal("a CAS object that is a symlink was accepted")
	}
}
