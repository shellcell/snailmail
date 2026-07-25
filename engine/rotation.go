package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
)

const defaultRotationRefresh = 30 * 24 * time.Hour

type RotateKeyRequest struct {
	Root           string
	Repository     string
	Successor      string
	Advance        bool
	MinimumRefresh time.Duration
	ExpiresIn      time.Duration
	Keys           signer.Generator
	now            time.Time
}

type RotateKeyResult struct {
	Repository      string
	PreviousKey     string
	SuccessorKey    string
	Phase           string
	ActiveKey       string
	TrustedKeys     []string
	EarliestAdvance string
	RequiresDeploy  bool
}

func RotateKey(ctx context.Context, request RotateKeyRequest) (RotateKeyResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return RotateKeyResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return RotateKeyResult{}, err
	}
	if err := state.ValidateRepositoryName(request.Repository); err != nil {
		return RotateKeyResult{}, err
	}
	now := request.now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC().Truncate(time.Second)
	if request.Advance {
		return advanceKeyRotation(root, request.Repository, now)
	}
	if err := state.ValidateRepositoryName(request.Successor); err != nil {
		return RotateKeyResult{}, fmt.Errorf("successor key name: %w", err)
	}
	minimumRefresh := request.MinimumRefresh
	if minimumRefresh == 0 {
		minimumRefresh = defaultRotationRefresh
	}
	if minimumRefresh < time.Duration(state.MinimumSigningRefreshSeconds)*time.Second || minimumRefresh > 365*24*time.Hour || minimumRefresh%time.Second != 0 {
		return RotateKeyResult{}, errors.New("minimum refresh must be a whole-second duration between seven days and one year")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return RotateKeyResult{}, err
	}
	defer unlock()
	allowedSuccessorFiles := []string{"keys/" + request.Successor + ".gpg", "keys/" + request.Successor + ".asc"}
	if _, err := state.RequireCleanGitAllowingUntracked(root, allowedSuccessorFiles); err != nil {
		return RotateKeyResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return RotateKeyResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists || repository.Format != "deb" || len(repository.SigningKeys) != 1 {
		return RotateKeyResult{}, errors.New("rotation requires a signed Debian repository")
	}
	if repository.SigningRotation != nil {
		rotation := repository.SigningRotation
		if rotation.SuccessorKey != request.Successor || rotation.MinimumRefreshSeconds != int64(minimumRefresh/time.Second) {
			return RotateKeyResult{}, errors.New("repository already has a different signing rotation")
		}
		deployment, err := state.LoadDeployment(root, request.Repository)
		if err != nil {
			return RotateKeyResult{}, err
		}
		desired, err := repositoryDeploymentSigningState(repository, manifest.Keys)
		if err != nil {
			return RotateKeyResult{}, err
		}
		requiresDeploy := !deploymentSigningMatches(deployment, desired)
		return rotationResult(request.Repository, repository, deployment, requiresDeploy), nil
	}
	if request.Successor == repository.SigningKeys[0] {
		return RotateKeyResult{}, errors.New("successor signing key must differ from the active key")
	}
	baseKey := manifest.Keys[repository.SigningKeys[0]]
	baseExpires, baseErr := time.Parse(time.RFC3339, baseKey.ExpiresAt)
	if baseErr != nil || baseExpires.Before(now.Add(minimumRefresh+2*time.Hour)) {
		return RotateKeyResult{}, errors.New("active signing key expires before the introduction window can complete")
	}
	stableState, err := repositoryDeploymentSigningState(repository, manifest.Keys)
	if err != nil {
		return RotateKeyResult{}, err
	}
	deployment, err := state.LoadDeployment(root, request.Repository)
	if err != nil {
		return RotateKeyResult{}, err
	}
	if deployment.NativeRevision == "" || !deploymentSigningMatches(deployment, stableState) {
		return RotateKeyResult{}, errors.New("rotation requires the stable signing state to be successfully deployed")
	}
	successorKey, exists := manifest.Keys[request.Successor]
	var prepared *preparedSigningKey
	rollbackPublic := func() {}
	committed := false
	defer func() {
		if committed || prepared == nil {
			return
		}
		rollbackPublic()
		if prepared.createdPrivate {
			_ = request.Keys.Delete(context.WithoutCancel(ctx), signer.Ref{Backend: prepared.key.Ref.Backend, ID: prepared.key.Ref.ID})
		}
	}()
	if !exists {
		if request.Keys == nil {
			return RotateKeyResult{}, errors.New("signing key generator is required for a new successor")
		}
		expiresIn := request.ExpiresIn
		if expiresIn == 0 {
			expiresIn = 2 * 365 * 24 * time.Hour
		}
		if expiresIn < 2*minimumRefresh+2*time.Hour {
			return RotateKeyResult{}, errors.New("new successor validity is shorter than introduction and overlap")
		}
		candidate, err := prepareSigningKey(ctx, manifest, request.Successor, now, expiresIn, request.Keys)
		if err != nil {
			return RotateKeyResult{}, err
		}
		prepared = &candidate
		rollbackPublic, err = persistPreparedSigningKey(root, candidate)
		if err != nil {
			return RotateKeyResult{}, err
		}
		successorKey = candidate.key
		manifest.Keys[request.Successor] = successorKey
	}
	successorCreated, createdErr := time.Parse(time.RFC3339, successorKey.CreatedAt)
	successorExpires, successorErr := time.Parse(time.RFC3339, successorKey.ExpiresAt)
	if successorErr != nil || successorExpires.Before(now.Add(2*minimumRefresh+2*time.Hour)) {
		return RotateKeyResult{}, errors.New("successor signing key expires before rotation overlap can complete")
	}
	if createdErr != nil || successorCreated.After(now.Add(minimumRefresh)) {
		return RotateKeyResult{}, errors.New("successor signing key is not valid by the end of the introduction window")
	}
	repository.SigningRotation = &state.SigningRotation{
		SuccessorKey: request.Successor, Phase: "introducing", MinimumRefreshSeconds: int64(minimumRefresh / time.Second),
	}
	manifest.Repositories[request.Repository] = repository
	if err := state.WriteManifest(root, manifest); err != nil {
		committed = manifestMatches(root, manifest)
		return RotateKeyResult{}, err
	}
	committed = true
	return rotationResult(request.Repository, repository, state.DeploymentRecord{}, true), nil
}

func advanceKeyRotation(root, repositoryName string, now time.Time) (RotateKeyResult, error) {
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return RotateKeyResult{}, err
	}
	defer unlock()
	if _, err := state.RequireCleanGit(root); err != nil {
		return RotateKeyResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return RotateKeyResult{}, err
	}
	repository, exists := manifest.Repositories[repositoryName]
	if !exists || len(repository.SigningKeys) != 1 {
		return RotateKeyResult{}, errors.New("repository has no signing rotation to advance")
	}
	deployment, err := state.LoadDeployment(root, repositoryName)
	if err != nil {
		return RotateKeyResult{}, err
	}
	if repository.SigningRotation == nil {
		desired, err := repositoryDeploymentSigningState(repository, manifest.Keys)
		if err != nil {
			return RotateKeyResult{}, err
		}
		requiresDeploy := !deploymentSigningMatches(deployment, desired)
		return rotationResult(repositoryName, repository, deployment, requiresDeploy), nil
	}
	desired, err := repositoryDeploymentSigningState(repository, manifest.Keys)
	if err != nil {
		return RotateKeyResult{}, err
	}
	if !deploymentSigningMatches(deployment, desired) {
		return RotateKeyResult{}, errors.New("current signing rotation state has not been successfully deployed")
	}
	trustSince, err := time.Parse(time.RFC3339, deployment.TrustSince)
	if err != nil {
		return RotateKeyResult{}, errors.New("deployment receipt has invalid trust timestamp")
	}
	earliest := trustSince.Add(time.Duration(repository.SigningRotation.MinimumRefreshSeconds) * time.Second)
	if now.Before(earliest) {
		return RotateKeyResult{}, fmt.Errorf("signing rotation cannot advance before %s", earliest.UTC().Format(time.RFC3339))
	}
	if err := validateRotationAdvanceValidity(repository, manifest.Keys, now); err != nil {
		return RotateKeyResult{}, err
	}
	rotation := repository.SigningRotation
	switch rotation.Phase {
	case "introducing":
		rotation.Phase = "activated"
	case "activated":
		repository.SigningKeys = []string{rotation.SuccessorKey}
		repository.SigningRotation = nil
	default:
		return RotateKeyResult{}, errors.New("repository has invalid signing rotation phase")
	}
	manifest.Repositories[repositoryName] = repository
	if err := state.WriteManifest(root, manifest); err != nil {
		return RotateKeyResult{}, err
	}
	return rotationResult(repositoryName, repository, deployment, true), nil
}

func validateRotationAdvanceValidity(repository state.Repository, keys map[string]state.SigningKey, now time.Time) error {
	rotation := repository.SigningRotation
	baseExpires, baseErr := time.Parse(time.RFC3339, keys[repository.SigningKeys[0]].ExpiresAt)
	successorExpires, successorErr := time.Parse(time.RFC3339, keys[rotation.SuccessorKey].ExpiresAt)
	if baseErr != nil || successorErr != nil {
		return errors.New("signing rotation key validity is invalid")
	}
	switch rotation.Phase {
	case "introducing":
		minimum := time.Duration(rotation.MinimumRefreshSeconds) * time.Second
		if baseExpires.Before(now.Add(2*time.Hour)) || successorExpires.Before(now.Add(minimum+2*time.Hour)) {
			return errors.New("signing keys cannot remain valid through activated overlap")
		}
	case "activated":
		if successorExpires.Before(now.Add(2 * time.Hour)) {
			return errors.New("successor signing key expires before retirement can be published")
		}
	}
	return nil
}

func rotationResult(repositoryName string, repository state.Repository, deployment state.DeploymentRecord, requiresDeploy bool) RotateKeyResult {
	active, trusted, phase, minimum, _ := repositorySigningState(repository)
	result := RotateKeyResult{
		Repository: repositoryName, ActiveKey: active, TrustedKeys: trusted, Phase: phase, RequiresDeploy: requiresDeploy,
	}
	if repository.SigningRotation != nil {
		result.PreviousKey = repository.SigningKeys[0]
		result.SuccessorKey = repository.SigningRotation.SuccessorKey
		if deployment.TrustSince != "" {
			if trustSince, err := time.Parse(time.RFC3339, deployment.TrustSince); err == nil {
				result.EarliestAdvance = trustSince.Add(time.Duration(minimum) * time.Second).UTC().Format(time.RFC3339)
			}
		}
	} else {
		result.Phase = "stable"
	}
	return result
}
