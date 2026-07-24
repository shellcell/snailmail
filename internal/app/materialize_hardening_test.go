package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
)

func TestPublishVerifiedDirectoryRejectsSameLinkChangedTree(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "repository")
	writeManagedTestRepository(t, target, "initial")
	expectedLink, expectedTree, err := currentManagedRelease(target)
	if err != nil {
		t.Fatal(err)
	}
	rogue := filepath.Join(t.TempDir(), "rogue")
	writeManagedTestRepository(t, rogue, "rogue")
	currentRelease, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	rogueRelease, err := filepath.EvalSymlinks(rogue)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(currentRelease); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rogueRelease, currentRelease); err != nil {
		t.Fatal(err)
	}
	candidate, err := os.MkdirTemp(parent, ".repository.snailmail-release-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishRelease(target, candidate, expectedLink, expectedTree); err == nil {
		t.Fatal("expected same-link target tree change to reject publication")
	}
}

func TestPublishVerifiedDirectoryRecoversOrphanedInitialControl(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "repository")
	staged := filepath.Join(t.TempDir(), "staged")
	desired := writeManagedTestRepository(t, staged, "desired")
	orphan := filepath.Join(parent, ".repository.snailmail-release-orphan")
	seed := filepath.Join(parent, "seed")
	writeManagedTestRepository(t, seed, "orphan")
	seedRelease, err := filepath.EvalSymlinks(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(seedRelease, orphan); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(parent, ".repository.snailmail-control")
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", filepath.Base(orphan)), filepath.Join(control, "current")); err != nil {
		t.Fatal(err)
	}
	if err := PublishVerifiedDirectory(context.Background(), staged, target, "", desired.TreeSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphaned release was not removed")
	}
	manifest, err := VerifyRepository(target)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TreeSHA256 != desired.TreeSHA256 {
		t.Fatal("recovered publication has the wrong tree")
	}
}

func TestPublishVerifiedDirectoryPreservesUnverifiedOrphan(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "repository")
	staged := filepath.Join(t.TempDir(), "staged")
	desired := writeManagedTestRepository(t, staged, "desired")
	unrelated := filepath.Join(parent, ".repository.snailmail-release-important")
	if err := os.Mkdir(unrelated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unrelated, "important.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(parent, ".repository.snailmail-control")
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", filepath.Base(unrelated)), filepath.Join(control, "current")); err != nil {
		t.Fatal(err)
	}
	if err := PublishVerifiedDirectory(context.Background(), staged, target, "", desired.TreeSHA256); err == nil {
		t.Fatal("expected unverified orphan release to be rejected")
	}
	if content, err := os.ReadFile(filepath.Join(unrelated, "important.txt")); err != nil || string(content) != "keep" {
		t.Fatal("unverified orphan release was modified")
	}
}

func TestSnapshotVerifiedManifestRejectsChangedMeaning(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repository")
	expected := writeManagedTestRepository(t, repository, "content")
	release, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, buildgraph.ManifestFilename), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotVerifiedManifest(release, expected); err == nil {
		t.Fatal("expected changed management manifest to be rejected")
	}
}

func writeManagedTestRepository(t *testing.T, output, content string) buildgraph.RepositoryManifest {
	t.Helper()
	artifact, manifest, err := buildgraph.Finalize(domain.RepositoryArtifact{
		Format: "test",
		Files:  []domain.File{{Path: "index.txt", Content: []byte(content)}},
	}, time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := Materialize(context.Background(), output, artifact, nil); err != nil {
		t.Fatal(err)
	}
	return manifest
}
