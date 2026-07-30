package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

// withGitIdentity gives git someone to attribute a commit to.
//
// Set explicitly rather than relied upon: a container has no configured identity
// and cannot derive one from root@hostname, which is how CI found that init failed
// after writing the workspace. A test that passes only on a developer's laptop
// would have hidden it.
func withGitIdentity(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_AUTHOR_NAME", "snailmail tests")
	t.Setenv("GIT_AUTHOR_EMAIL", "tests@example.test")
	t.Setenv("GIT_COMMITTER_NAME", "snailmail tests")
	t.Setenv("GIT_COMMITTER_EMAIL", "tests@example.test")
}

// The first thing many people saw was a refusal. snailmail is git-backed by
// definition, so a workspace that is not a repository cannot work — and telling the
// operator to go and run git init made the tool's first interaction a failure.
func TestInitCreatesTheRepositoryAndTheFirstCommit(t *testing.T) {
	withGitIdentity(t)
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

// The case CI found. With no identity, git cannot attribute a commit — and failing
// here would leave the workspace written but unusable, which is worse than never
// having tried. init reports what is left instead, and never invents an identity:
// authorship is a claim it has no standing to make in somebody's history.
func TestInitDoesNotFailWhenGitHasNoIdentity(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL",
	} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	// Empty config files rather than a missing HOME, so git reads no name from
	// anywhere. It may still derive one from the account and hostname, which is what
	// a developer machine does and a container cannot.
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_SYSTEM", empty)

	result, err := InitWorkspaceReporting(InitWorkspaceRequest{Root: root, Name: "hello"})
	if err != nil {
		t.Fatalf("init failed instead of reporting what was left: %v", err)
	}
	if !result.CreatedGitRepository {
		t.Error("no repository was created")
	}
	if state.HasGitIdentity(root) {
		t.Skip("git derived an identity from the account, so the no-identity path cannot be exercised here")
	}
	if !result.CommitPending {
		t.Error("init did not report that the commit is still to be made")
	}
	if result.Committed {
		t.Error("init reported a commit it could not have made")
	}
	// The workspace is written and correct; only the commit is missing.
	if _, err := os.Stat(filepath.Join(root, "snailmail.toml")); err != nil {
		t.Errorf("the workspace was not written: %v", err)
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
	withGitIdentity(t)
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
