package engine

import (
	"errors"
	"fmt"

	"github.com/shellcell/snailmail/internal/state"
)

type PlacementMutationRequest struct {
	Root       string
	Repository string
	Package    string
	Version    string
	Track      string
	Distro     string
	All        bool
}

type PlacementMutationResult struct {
	Repository string
	Package    string
	Version    string
	Track      string
	Distro     string
	Changed    int
	All        bool
}

func Promote(request PlacementMutationRequest) (PlacementMutationResult, error) {
	if request.Track == "" {
		request.Track = "stable"
	}
	return mutatePlacement(request, true)
}

func Yank(request PlacementMutationRequest) (PlacementMutationResult, error) {
	if request.All == (request.Track != "") {
		return PlacementMutationResult{}, errors.New("yank requires exactly one of a track or all placements")
	}
	return mutatePlacement(request, false)
}

func mutatePlacement(request PlacementMutationRequest, promote bool) (PlacementMutationResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return PlacementMutationResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return PlacementMutationResult{}, err
	}
	if request.Repository == "" || request.Package == "" || request.Version == "" {
		return PlacementMutationResult{}, errors.New("repository, package, and version are required")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return PlacementMutationResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return PlacementMutationResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return PlacementMutationResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	lock, err := state.LoadLock(root, repository)
	if err != nil {
		return PlacementMutationResult{}, err
	}
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return PlacementMutationResult{}, err
	}
	ledger, err := state.LoadLedgerHistory(root, request.Repository)
	if err != nil {
		return PlacementMutationResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return PlacementMutationResult{}, err
	}
	packageName := nativePackageName(repository.Format, request.Package)
	distro := request.Distro
	if repository.Format == "deb" && !request.All {
		if distro == "" {
			distro = repository.Suite
		}
	}
	changed := 0
	if promote {
		added, err := state.PromotePlacement(&lock, repository.Format, packageName, request.Version, request.Track, distro)
		if err != nil {
			return PlacementMutationResult{}, err
		}
		if added {
			changed = 1
		}
	} else {
		changed, err = state.YankPlacements(&lock, repository.Format, packageName, request.Version, request.Track, distro, request.All)
		if err != nil {
			return PlacementMutationResult{}, err
		}
	}
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return PlacementMutationResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return PlacementMutationResult{}, err
	}
	if changed != 0 {
		if err := state.WriteLock(root, repository, lock); err != nil {
			return PlacementMutationResult{}, err
		}
	}
	return PlacementMutationResult{
		Repository: request.Repository, Package: packageName, Version: request.Version,
		Track: request.Track, Distro: distro, Changed: changed, All: request.All,
	}, nil
}
