package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

// The first thing many people saw was a refusal. snailmail is git-backed by
// definition, so a workspace that is not a repository cannot work — and telling the
// operator to go and run git init made the tool's first interaction a failure.
func TestInitCreatesTheRepositoryAndTheFirstCommit(t *testing.T) {
	root := t.TempDir()
	result, err := InitWorkspaceReporting(InitWorkspaceRequest{Root: root, Name: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CreatedGitRepository || !result.Committed {
		t.Fatalf("init reported %+v", result)
	}
	if !state.IsGitRepository(root) {
		t.Error("no Git repository was created")
	}
	// A repository with no history fails every later command, so stopping at the
	// manifest would still leave the next one to fail.
	if !state.HasCommit(root) {
		t.Error("the new workspace was not committed, so the next command would fail")
	}
	if _, err := os.Stat(filepath.Join(root, "snailmail.toml")); err != nil {
		t.Errorf("no manifest: %v", err)
	}
}

// Somebody's existing repository is theirs. Initialising a workspace inside one
// must not commit into it, because what goes in their history is their decision.
func TestInitDoesNotCommitIntoAnExistingRepository(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	result, err := InitWorkspaceReporting(InitWorkspaceRequest{Root: root, Name: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if result.CreatedGitRepository || result.Committed {
		t.Errorf("init touched an existing repository: %+v", result)
	}
	if state.HasCommit(root) {
		t.Error("init committed into a repository it did not create")
	}
}

// The opt-out is for someone placing a workspace inside a repository they will
// create themselves, and it must still refuse rather than proceed without one.
func TestInitCanDeclineToCreateARepository(t *testing.T) {
	root := t.TempDir()
	_, err := InitWorkspaceReporting(InitWorkspaceRequest{Root: root, Name: "hello", SkipGit: true})
	if err == nil {
		t.Fatal("a workspace was initialised outside a Git repository")
	}
	if state.IsGitRepository(root) {
		t.Error("a repository was created despite the opt-out")
	}
}

// The whole point is that the next command works. This is the sequence a new user
// runs, and every step of it used to need git by hand.
func TestAFreshWorkspaceIsImmediatelyUsable(t *testing.T) {
	root := t.TempDir()
	if _, err := InitWorkspaceReporting(InitWorkspaceRequest{Root: root, Name: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "tools", Format: "raw", HostType: "local",
		Output: "public/tools", Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatalf("setup failed straight after init: %v", err)
	}
}
