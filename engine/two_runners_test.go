package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/testutil"
)

// The workspace lock is a file inside the checkout, so it does not serialise two
// runners on separate machines. These tests establish what does.
//
// One thing found while writing them, and worth stating because it removes a whole
// class of worry: a local host's output path must be relative to its workspace, so
// two checkouts cannot publish to one directory at all. The shared-host case
// therefore only arises for object storage and Pages, where two runners can name
// the same bucket and prefix or the same repository and branch. That collision is
// tested where the protection lives, in the host adapter.
func runnerWorkspace(t *testing.T, name, output string) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: name}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "tools", Format: "raw", HostType: "local",
		Output: output, Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func addArtifact(t *testing.T, root, version string) {
	t.Helper()
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, "unused", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(input, "tool_"+version+"_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("payload "+version), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddArtifacts(AddArtifactsRequest{
		Root: root, Repository: "tools", Artifacts: []string{artifact},
	}); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, root, message string) {
	t.Helper()
	if output, err := exec.Command("git", "-C", root, "add", "-A").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root, "commit", "-m", message)
	commit.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
}

func planFor(t *testing.T, root string) string {
	t.Helper()
	name := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: name, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	return name
}

// A plan applied twice from one workspace must not publish twice. This is the
// same-machine version of the collision, and the one a retried CI job produces.
func TestApplyingOnePlanTwiceIsNotTwoPublications(t *testing.T) {
	root := runnerWorkspace(t, "runner", "public/tools")
	addArtifact(t, root, "1.0.0")
	commitAll(t, root, "configure")
	plan := planFor(t, root)

	firstResult, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: plan, StructuralOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstResult.Applied != 1 {
		t.Fatalf("first apply reported %+v", firstResult)
	}
	// The same plan again. Either it is refused or it is recognised as already
	// applied; what it must not be is a second publication.
	secondResult, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: plan, StructuralOnly: true,
	})
	if err != nil {
		t.Logf("re-applying refused: %v", err)
		return
	}
	if secondResult.Applied != 0 {
		t.Errorf("re-applying one plan reported %d further changes, want 0 with %d already current",
			secondResult.Applied, secondResult.Current)
	}
}

// The lock is a file in the checkout, so two operations in one workspace are
// serialised and two in separate checkouts are not. Worth pinning, because the
// error an operator sees in the first case says "another workspace operation is
// running", which would be misleading in the second.
func TestTheWorkspaceLockOnlyCoversOneCheckout(t *testing.T) {
	first := runnerWorkspace(t, "runner-a", "public/tools")
	second := runnerWorkspace(t, "runner-b", "public/tools")
	// Both committed, so a failure below is the lock rather than an unrelated
	// refusal to read an uncommitted workspace.
	commitAll(t, first, "configure a")
	commitAll(t, second, "configure b")
	release, err := state.AcquireWorkspaceLock(first)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// The same checkout is blocked.
	if _, err := StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: first}); err == nil {
		t.Error("a second operation in the same checkout was not blocked by the lock")
	}
	// A different checkout is not.
	if _, err := StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: second}); err != nil {
		t.Errorf("a different checkout was blocked by the first's lock: %v", err)
	}
}
