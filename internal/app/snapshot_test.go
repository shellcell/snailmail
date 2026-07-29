package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A snapshot shares inodes with the repository it was taken from.
//
// It is made so a container can mount the tree read-only while the real one is
// still being written to, and a repository can reach the 4 GiB verification
// limit. Copying instead of linking would rewrite every byte of that, and it
// would do it silently — os.Link only fails across filesystems, so a snapshot
// directory on another device turns into a full copy with nothing to see in the
// output. Asserting on the inode is the only way that stays caught.
func TestSnapshotLinksRatherThanCopies(t *testing.T) {
	output := filepath.Join(t.TempDir(), "repository")
	manifest := writeManagedTestRepository(t, output, "some published bytes")

	snapshot, err := snapshotRepository(context.Background(), output, manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(snapshot)

	for _, file := range manifest.Files {
		source, err := os.Stat(filepath.Join(output, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		linked, err := os.Stat(filepath.Join(snapshot, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(source, linked) {
			t.Errorf("snapshot of %q is a copy, not a link: the bytes were duplicated", file.Path)
		}
	}
}

// The snapshot is taken beside the repository, which is what guarantees the
// link above can be made at all: the system temp directory is frequently on
// another filesystem, and there is no error when it is — only a slow copy.
func TestSnapshotIsTakenBesideTheRepository(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "repository")
	manifest := writeManagedTestRepository(t, output, "some published bytes")

	snapshot, err := snapshotRepository(context.Background(), output, manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(snapshot)

	if filepath.Dir(snapshot) != filepath.Dir(output) {
		t.Fatalf("snapshot went to %q, want a sibling of %q", snapshot, output)
	}
	// Dot-prefixed, because a publication root is also what a site assembly
	// globs over, and this must not be picked up as a repository.
	if !strings.HasPrefix(filepath.Base(snapshot), ".") {
		t.Errorf("snapshot %q is not hidden from a publication glob", filepath.Base(snapshot))
	}
	// And it must not be inside the tree it is a snapshot of, which would make
	// the repository contain a copy of itself.
	if strings.HasPrefix(snapshot, output+string(os.PathSeparator)) {
		t.Errorf("snapshot %q is inside the repository it snapshots", snapshot)
	}
}
