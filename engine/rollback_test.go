package engine

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
)

// rollbackHost is a host with a live revision that replaced an earlier one, which
// is the state a rollback exists for.
type rollbackHost struct {
	recordingHost
	restorable   bool
	restored     host.RestoreRef
	restoreCalls int
	expected     host.ExpectedRevision
	restoreErr   error
}

func (remote *rollbackHost) Capabilities(context.Context, host.Repository) (host.Capabilities, error) {
	return host.Capabilities{ConditionalCommit: true, ConditionalRestore: remote.restorable}, nil
}

func (remote *rollbackHost) Restore(_ context.Context, _ host.Repository, reference host.RestoreRef,
	expected host.ExpectedRevision) (host.PublishedRevision, error) {
	remote.restoreCalls++
	remote.restored = reference
	remote.expected = expected
	if remote.restoreErr != nil {
		return host.PublishedRevision{}, remote.restoreErr
	}
	return host.PublishedRevision{TreeSHA256: "bb" + strings.Repeat("0", 62)}, nil
}

func rollbackWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "rollback"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "local",
		Output: "public/python", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func livingHost(restorable bool) *rollbackHost {
	remote := &rollbackHost{restorable: restorable}
	remote.revision = host.PublishedRevision{
		NativeRevision: "etag-2", TreeSHA256: "aa" + strings.Repeat("0", 62),
		PlanID: "plan-2", ChangeID: "change-2",
		RestoreID: "restore-1", RestoreSHA256: "cc" + strings.Repeat("0", 62),
		RestoreRootSHA256: "dd" + strings.Repeat("0", 62),
	}
	return remote
}

func rollbackRequest(root string, remote host.Host) RollbackRepositoryRequest {
	return RollbackRepositoryRequest{
		Root: root, Repository: "python", Hosts: staticHostResolver{host: remote},
	}
}

// The gap this closes: a publication that succeeded and turned out to be wrong had
// no first-class undo.
func TestRollbackRestoresThePreviousPublication(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	result, err := RollbackRepository(context.Background(), rollbackRequest(root, remote))
	if err != nil {
		t.Fatal(err)
	}
	if remote.restoreCalls != 1 {
		t.Fatalf("restore was called %d times", remote.restoreCalls)
	}
	if result.From != remote.revision.TreeSHA256 {
		t.Errorf("rolled back from %q, want the live revision", result.From)
	}
	if result.To == "" || result.To == result.From {
		t.Errorf("rolled back to %q", result.To)
	}
}

// The reference must come from what the host reports, not from what this checkout
// believes, or a rollback run from a stale workspace restores the wrong thing.
func TestRollbackUsesTheReferenceTheLiveRevisionCarries(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	if _, err := RollbackRepository(context.Background(), rollbackRequest(root, remote)); err != nil {
		t.Fatal(err)
	}
	if remote.restored.ID != "restore-1" {
		t.Errorf("restore reference ID = %q", remote.restored.ID)
	}
	if remote.restored.FailedTree != remote.revision.TreeSHA256 {
		t.Errorf("restore names %q as the tree being replaced", remote.restored.FailedTree)
	}
	if remote.restored.DescriptorSHA256 != remote.revision.RestoreSHA256 ||
		remote.restored.RootSHA256 != remote.revision.RestoreRootSHA256 {
		t.Errorf("restore reference lost its digests: %+v", remote.restored)
	}
	// Conditional on what was observed, so a rollback racing a publication fails
	// rather than overwriting it.
	if remote.expected.TreeSHA256 != remote.revision.TreeSHA256 ||
		remote.expected.NativeRevision != remote.revision.NativeRevision {
		t.Errorf("rollback was not conditional on the observed revision: %+v", remote.expected)
	}
}

// A host that cannot verify the release it would restore must decline rather than
// point at something it has not checked. Local and rsync are both in this position.
func TestRollbackRefusesAHostThatCannotVerifyTheTarget(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(false)
	_, err := RollbackRepository(context.Background(), rollbackRequest(root, remote))
	if err == nil {
		t.Fatal("a rollback ran against a host that cannot verify its target")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("error = %v, want the reason stated", err)
	}
	// And it names the way forward, because an operator in this position needs one.
	if !strings.Contains(err.Error(), "publish forward") {
		t.Errorf("error = %v, want the alternative named", err)
	}
	if remote.restoreCalls != 0 {
		t.Error("restore was attempted anyway")
	}
}

// A first publication replaced nothing, so there is no earlier root to put back.
// Saying so beats restoring an empty repository.
func TestRollbackRefusesWhenNothingWasReplaced(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	remote.revision.RestoreID = ""
	_, err := RollbackRepository(context.Background(), rollbackRequest(root, remote))
	if err == nil || !strings.Contains(err.Error(), "replaced nothing") {
		t.Errorf("error = %v, want the missing earlier publication named", err)
	}
}

func TestRollbackRefusesAnUnpublishedRepository(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	remote.revision = host.PublishedRevision{}
	_, err := RollbackRepository(context.Background(), rollbackRequest(root, remote))
	if err == nil || !strings.Contains(err.Error(), "no published revision") {
		t.Errorf("error = %v", err)
	}
}

// A dry run has to report what would happen and touch nothing, since the whole
// point is deciding whether to.
func TestRollbackDryRunRestoresNothing(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	request := rollbackRequest(root, remote)
	request.DryRun = true
	result, err := RollbackRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if remote.restoreCalls != 0 {
		t.Error("a dry run restored")
	}
	if !result.DryRun || result.From == "" {
		t.Errorf("dry run reported %+v", result)
	}
}

// The lock still describes what was rolled back from, so the workspace and the
// world now disagree on purpose. That has to be said, or the next apply silently
// republishes what was just undone.
func TestRollbackSaysTheLockNowDisagrees(t *testing.T) {
	root := rollbackWorkspace(t)
	result, err := RollbackRepository(context.Background(), rollbackRequest(root, livingHost(true)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lock", "republish"} {
		if !strings.Contains(result.Note, want) {
			t.Errorf("note %q does not mention %q", result.Note, want)
		}
	}
}

// A failing restore is reported rather than swallowed, and names the repository.
func TestRollbackReportsAFailedRestore(t *testing.T) {
	root := rollbackWorkspace(t)
	remote := livingHost(true)
	remote.restoreErr = errors.New("bucket said no")
	_, err := RollbackRepository(context.Background(), rollbackRequest(root, remote))
	if err == nil || !strings.Contains(err.Error(), "python") {
		t.Errorf("error = %v, want the repository named", err)
	}
}
