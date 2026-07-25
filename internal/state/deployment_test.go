package state

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitDeploymentsRestoresWorktreeOnGitFailure(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-b", "main").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := Init(root, InitOptions{Name: "deployment-test"}); err != nil {
		t.Fatal(err)
	}
	if err := Setup(root, SetupOptions{Name: "python", Format: "pypi", Output: "public/python"}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", ".gitignore", "snailmail.toml", "repos").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "initialize")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	base, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	indexPath, err := resolveGitPath(root, "index")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath+".lock", []byte("busy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = CommitDeployments(root, strings.Repeat("a", 64), base, []DeploymentRecord{{
		Repository: "python", PlanID: strings.Repeat("a", 64), ChangeID: "python:bbbbbbbbbbbb",
		TreeSHA256: strings.Repeat("b", 64), NativeRevision: "native", DeployedAt: "2026-07-25T00:00:00Z",
	}})
	if err == nil {
		t.Fatal("deployment commit unexpectedly ignored busy Git index")
	}
	if _, err := os.Lstat(filepath.Join(root, "deployments", "python.json")); !os.IsNotExist(err) {
		t.Fatalf("failed deployment commit left authoritative file: %v", err)
	}
}
