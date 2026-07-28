package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Build and stage trees must not land in TMPDIR: it is commonly a tmpfs, so a
// large repository would be held in RAM, and it is a different filesystem from
// the local CAS, so linking artifacts into a build input degrades to copying
// every byte.
func TestPlanStagesInsideWorkspaceRatherThanTempDir(t *testing.T) {
	root := t.TempDir()
	isolatedTemp := t.TempDir()
	t.Setenv("TMPDIR", isolatedTemp)

	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "initialize workspace")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(isolatedTemp)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "snailmail") {
			t.Fatalf("planning left %q in TMPDIR", entry.Name())
		}
	}
	if _, err := os.Lstat(filepath.Join(root, ".snailmail", "stage")); err != nil {
		t.Fatalf("workspace staging directory was not created: %v", err)
	}
}

func TestStagingRootRejectsRelativeOverride(t *testing.T) {
	t.Setenv(StageDirectoryEnvironment, "relative/stage")
	if _, err := stagingRoot(t.TempDir()); err == nil {
		t.Fatal("expected a relative staging override to be rejected")
	}
}

func TestStagingRootHonorsAbsoluteOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "elsewhere")
	t.Setenv(StageDirectoryEnvironment, override)
	directory, err := stagingRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if directory != override {
		t.Fatalf("staging root = %q, want %q", directory, override)
	}
	if _, err := os.Lstat(override); err != nil {
		t.Fatalf("override directory was not created: %v", err)
	}
}
