package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

// The lock is parsed whole on every plan and every apply, so its size is what
// predicts where a workspace stops being comfortable. Reported from the file
// rather than estimated from the version count, because the file is what gets
// parsed.
func TestStatusReportsTheLockSizeItWouldParse(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi", "deb")
	result, err := StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 2 {
		t.Fatalf("got %d repositories", len(result.Repositories))
	}
	var summed int64
	for _, repository := range result.Repositories {
		if repository.LockBytes <= 0 {
			t.Errorf("%s reported %d lock bytes", repository.Name, repository.LockBytes)
		}
		summed += repository.LockBytes
		// Compared against the file on disk, so a future change that reports an
		// estimate instead is caught.
		manifest, err := state.LoadManifest(root)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(root, manifest.Repositories[repository.Name].Lock))
		if err != nil {
			t.Fatal(err)
		}
		if repository.LockBytes != info.Size() {
			t.Errorf("%s reported %d bytes, the file is %d", repository.Name, repository.LockBytes, info.Size())
		}
	}
	if result.LockBytes != summed {
		t.Errorf("workspace total %d, repositories sum to %d", result.LockBytes, summed)
	}
}

// A package-version binds one blob per architecture, and the same blob can be
// bound by several versions. Counting bindings would report storage that is not
// consumed twice, which is the opposite of useful when the number exists to
// predict a bill.
func TestRetainedArtifactsCountsDistinctBlobs(t *testing.T) {
	lock := state.RepositoryLock{PackageVersion: []state.PackageVersion{
		{Package: "demo", Version: "1.0.0", Blobs: []state.LockedBlob{
			{SHA256: "aa", Size: 100}, {SHA256: "bb", Size: 200},
		}},
		// The same bytes bound again by a later version — one artifact, not two.
		{Package: "demo", Version: "1.0.1", Blobs: []state.LockedBlob{
			{SHA256: "aa", Size: 100}, {SHA256: "cc", Size: 300},
		}},
	}}
	artifacts, bytes := retainedArtifacts(lock)
	if artifacts != 3 {
		t.Errorf("counted %d artifacts, want 3 distinct blobs", artifacts)
	}
	if bytes != 600 {
		t.Errorf("summed %d bytes, want 600 counting the shared blob once", bytes)
	}
}

// A configured repository with no packages yet is an ordinary state, not an
// error, and its lock may not have been written at all.
func TestAnUnwrittenLockReportsZeroRatherThanFailing(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi")
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, repository := range manifest.Repositories {
		if err := os.Remove(filepath.Join(root, repository.Lock)); err != nil {
			t.Fatal(err)
		}
		bytes, err := lockFileBytes(root, repository)
		if err != nil {
			t.Fatalf("a missing lock for %s failed rather than reporting zero: %v", name, err)
		}
		if bytes != 0 {
			t.Errorf("a missing lock reported %d bytes", bytes)
		}
	}
}
