package engine

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A repository that converts line endings stores a different blob than the
// bytes on disk. Comparing raw worktree bytes to the committed blob reported
// every authoritative file as changed, which made planning impossible in any
// such workspace; hashing by path applies the same clean filter to both sides.
func TestPlanAcceptsWorkspaceWithLineEndingConversion(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", root, "config", "core.autocrlf", "true").CombinedOutput(); err != nil {
		t.Fatalf("git config: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("*.toml text eol=crlf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "test-workspace"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "pypi", Format: "pypi", Output: filepath.ToSlash(filepath.Join("public", "pypi")),
	}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", "--",
		".gitattributes", ".gitignore", "snailmail.toml", "repos").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root,
		"-c", "user.name=snailmail-test", "-c", "user.email=test@example.invalid",
		"commit", "-m", "initialize converted workspace")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	// Re-materialise the worktree so Git applies eol=crlf: the committed blob
	// keeps LF while the file on disk gains CRLF, which is exactly the state
	// that made raw byte comparison report a spurious difference.
	for _, name := range []string{"snailmail.toml", filepath.Join("repos", "pypi.lock.toml")} {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command("git", "-C", root, "checkout", "--", ".").CombinedOutput(); err != nil {
		t.Fatalf("git checkout: %v: %s", err, output)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "snailmail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifest, []byte("\r\n")) {
		t.Fatal("worktree manifest was not converted to CRLF, so this case proves nothing")
	}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root}); err != nil {
		t.Fatalf("planning a line-ending-converting workspace failed: %v", err)
	}
}
