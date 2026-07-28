package engine

import (
	"fmt"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/state"
)

type PruneRequest struct {
	Root       string
	Repository string
	Keep       int
}

type PruneResult struct {
	Repository string
	Keep       int
	Removed    int
}

func Prune(request PruneRequest) (PruneResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return PruneResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return PruneResult{}, err
	}
	if request.Keep < 1 {
		return PruneResult{}, fmt.Errorf("prune retention must keep at least one version")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return PruneResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return PruneResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return PruneResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	lock, err := state.LoadLock(root, repository)
	if err != nil {
		return PruneResult{}, err
	}
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return PruneResult{}, err
	}
	ledger, err := state.LoadLedgerHistory(root, request.Repository)
	if err != nil {
		return PruneResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return PruneResult{}, err
	}
	selected, err := formats.For(repository.Format)
	if err != nil {
		return PruneResult{}, fmt.Errorf("repository %q has unsupported format %q", request.Repository, repository.Format)
	}
	compare := state.VersionComparator(selected.CompareVersions)
	removed, err := state.PrunePlacements(&lock, request.Keep, compare)
	if err != nil {
		return PruneResult{}, fmt.Errorf("prune repository %q: %w", request.Repository, err)
	}
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return PruneResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return PruneResult{}, err
	}
	if removed != 0 {
		if err := state.WriteLock(root, repository, lock); err != nil {
			return PruneResult{}, err
		}
	}
	return PruneResult{Repository: request.Repository, Keep: request.Keep, Removed: removed}, nil
}
