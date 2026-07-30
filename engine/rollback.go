package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/state"
)

const rollbackSchemaVersion = 1

// Undoing a publication that succeeded.
//
// The tool had an answer for a publication that fails part way — apply restores
// the root the failed tree replaced — and none for one that works and turns out to
// be wrong. That is the case an operator is in at the worst moment, and the
// workaround was to revert the lock and publish forward again: a full build and
// apply cycle, and no help at all when the problem is that the new tree is broken
// rather than that its contents are wrong.
//
// This is deliberately one step. A published revision carries a restore reference
// naming the root it replaced, and collection protects that target for exactly this
// reason — so going back one publication is something the host can still verify.
// Going back further is not offered, because nothing keeps a chain of restore
// descriptors and the older releases may have been collected. Refusing is the
// honest answer; a rollback whose target cannot be checked is not a rollback.
type RollbackRepositoryRequest struct {
	Root       string
	Repository string
	// DryRun reports what would be restored without restoring it.
	DryRun bool
	Hosts  host.Resolver
}

type RollbackRepositoryResult struct {
	SchemaVersion int    `json:"schema_version"`
	Repository    string `json:"repository"`
	// From is the revision that was live, and To is the one it is rolled back to.
	From   string `json:"from"`
	To     string `json:"to"`
	DryRun bool   `json:"dry_run,omitempty"`
	// Note explains a rollback that did not happen, so a caller reporting the
	// result has a sentence rather than an empty structure.
	Note string `json:"note,omitempty"`
}

func RollbackRepository(ctx context.Context, request RollbackRepositoryRequest) (RollbackRepositoryResult, error) {
	if request.Repository == "" {
		return RollbackRepositoryResult{}, errors.New("rollback requires the repository to roll back")
	}
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return RollbackRepositoryResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	hosts := request.Hosts
	if hosts == nil {
		hosts = localHostResolver{}
	}
	hostIdentity, err := repositoryHostIdentity(repository)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	hostRepository := toHostRepository(root, manifest.Workspace.ID, hostIdentity, request.Repository, repository)
	selected, err := hosts.Resolve(ctx, hostRepository)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	// Asked rather than assumed. A local directory and an ssh host both decline to
	// restore because neither can establish that the release it would point back at
	// is still intact, and offering a rollback they cannot verify would be worse
	// than not offering one.
	capabilities, err := selected.Capabilities(ctx, hostRepository)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	if !capabilities.ConditionalRestore {
		return RollbackRepositoryResult{}, fmt.Errorf(
			"repository %q is published to a %s host, which cannot verify the revision a rollback would restore; "+
				"revert the lock in git and publish forward instead",
			request.Repository, repository.Host.Type)
	}
	observed, err := selected.Observe(ctx, hostRepository)
	if err != nil {
		return RollbackRepositoryResult{}, err
	}
	result := RollbackRepositoryResult{
		SchemaVersion: rollbackSchemaVersion, Repository: request.Repository,
		From: observed.TreeSHA256, DryRun: request.DryRun,
	}
	if observed.TreeSHA256 == "" {
		return RollbackRepositoryResult{}, fmt.Errorf(
			"repository %q has no published revision to roll back", request.Repository)
	}
	if observed.RestoreID == "" {
		// The first publication into an empty repository replaced nothing, so there
		// is no earlier root to put back.
		return RollbackRepositoryResult{}, fmt.Errorf(
			"the live revision of %q replaced nothing, so there is no earlier publication to roll back to",
			request.Repository)
	}
	// The reference the live revision already carries: which restore descriptor
	// belongs to it, and which tree it superseded. Built from what the host reports
	// rather than from the workspace, so a rollback is against what is actually
	// published and not against what this checkout believes.
	reference := host.RestoreRef{
		ID: observed.RestoreID, PlanID: observed.PlanID, ChangeID: observed.ChangeID,
		FailedTree: observed.TreeSHA256, DescriptorSHA256: observed.RestoreSHA256,
		RootSHA256: observed.RestoreRootSHA256,
	}
	if request.DryRun {
		result.Note = "dry run: nothing was restored"
		return result, nil
	}
	// Conditional on the revision just observed, so a rollback races with a
	// concurrent publication the same way a publication races with another: one of
	// them fails, and it is the one holding a stale view.
	restored, err := selected.Restore(ctx, hostRepository, reference, expectedFromObserved(observed))
	if err != nil {
		return RollbackRepositoryResult{}, fmt.Errorf("roll back %q: %w", request.Repository, err)
	}
	result.To = restored.TreeSHA256
	// Said plainly rather than left for status to imply. The lock still describes
	// the revision that was rolled back from, so the workspace and what is published
	// now disagree on purpose, and somebody has to reconcile them.
	result.Note = "the lock still describes the revision that was rolled back from; " +
		"revert or amend it and publish, or the next apply will republish what was just undone"
	return result, nil
}

// expectedFromObserved names every field of a revision, because a host compares
// all of them and a hand-written subset fails with two identical-looking values.
func expectedFromObserved(revision host.PublishedRevision) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: revision.NativeRevision, TreeSHA256: revision.TreeSHA256,
		PlanID: revision.PlanID, ChangeID: revision.ChangeID,
		ReleaseSHA256: revision.ReleaseSHA256, ManifestSHA256: revision.ManifestSHA256,
		RestoreID: revision.RestoreID, RestoreSHA256: revision.RestoreSHA256,
		RestoreRootSHA256: revision.RestoreRootSHA256,
	}
}
