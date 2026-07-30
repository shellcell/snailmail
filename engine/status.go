package engine

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/shellcell/snailmail/internal/state"
)

const statusSchemaVersion = 1

type StatusWorkspaceRequest struct {
	Root string
}

type StatusWorkspaceResult struct {
	SchemaVersion    int    `json:"schema_version"`
	Workspace        string `json:"workspace"`
	GitRevision      string `json:"git_revision"`
	ObservationScope string `json:"observation_scope"`
	// LockBytes is every repository's lock added up, which is what a single git
	// operation has to carry.
	LockBytes    int64              `json:"lock_bytes"`
	Repositories []StatusRepository `json:"repositories"`
}

type StatusRepository struct {
	Name                    string `json:"name"`
	Format                  string `json:"format"`
	Track                   string `json:"track"`
	Suite                   string `json:"suite,omitempty"`
	Visibility              string `json:"visibility"`
	GatePolicy              string `json:"gate_policy"`
	RetainedPackageVersions int    `json:"retained_package_versions"`
	VisiblePackageVersions  int    `json:"visible_package_versions"`
	// LockBytes is the size of this repository's lock file.
	//
	// Reported because it is the number that predicts where a workspace stops
	// working. A lock is parsed whole on every plan and every apply, so its size
	// sets both the time that takes and the memory it needs — and at around 385
	// bytes per package-version, a repository large enough to be slow is large
	// enough to be worth splitting. Without this an operator has no way to see
	// which repository is responsible, or that they are approaching anything.
	LockBytes int64 `json:"lock_bytes"`
	// Artifacts is how many distinct blobs this repository's retained versions
	// bind, and ArtifactBytes their total size. A package-version can bind several
	// — one per architecture — so the count is not the version count.
	Artifacts     int   `json:"artifacts"`
	ArtifactBytes int64 `json:"artifact_bytes"`
	// DigestProvenance counts artifacts by how their SHA-256 was established, so
	// "which of these came from an index nobody signed" is answerable without
	// reading the lock. Keyed by level; absent levels are simply not present.
	DigestProvenance    map[string]int   `json:"digest_provenance,omitempty"`
	VisibleBindingState string           `json:"visible_binding_state"`
	VisiblePackages     []StatusPackage  `json:"visible_packages"`
	Deployment          StatusDeployment `json:"deployment"`
}

type StatusPackage struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	BlobSHA256 []string `json:"blob_sha256"`
	Binding    string   `json:"binding"`
}

type StatusDeployment struct {
	State          string `json:"state"`
	PlanID         string `json:"plan_id,omitempty"`
	TreeSHA256     string `json:"tree_sha256,omitempty"`
	NativeRevision string `json:"native_revision,omitempty"`
	DeployedAt     string `json:"deployed_at,omitempty"`
}

func StatusWorkspace(ctx context.Context, request StatusWorkspaceRequest) (StatusWorkspaceResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return StatusWorkspaceResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return StatusWorkspaceResult{}, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return StatusWorkspaceResult{}, err
	}
	revision, err := state.RequireCleanGitContext(ctx, root)
	if err != nil {
		return StatusWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return StatusWorkspaceResult{}, err
	}
	result := StatusWorkspaceResult{
		SchemaVersion: statusSchemaVersion, Workspace: manifest.Workspace.Name, GitRevision: revision,
		ObservationScope: "committed workspace evidence only", Repositories: make([]StatusRepository, 0, len(manifest.Repositories)),
	}
	for _, name := range state.RepositoryNames(manifest) {
		if err := ctx.Err(); err != nil {
			return StatusWorkspaceResult{}, err
		}
		repository := manifest.Repositories[name]
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return StatusWorkspaceResult{}, err
		}
		if err := state.ValidateLock(lock, name, repository.Format); err != nil {
			return StatusWorkspaceResult{}, err
		}
		records, err := state.LoadLedgerHistoryAtRevisionContext(ctx, root, name, revision)
		if err != nil {
			return StatusWorkspaceResult{}, err
		}
		if err := state.ValidatePublicationHistory(name, records); err != nil {
			return StatusWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, records); err != nil {
			return StatusWorkspaceResult{}, err
		}
		visible := visiblePackageVersions(lock, repository)
		missing := missingPublicationBindings(lock, repository, records)
		missingBindings := make(map[string]bool, len(missing))
		for _, binding := range missing {
			missingBindings[binding.Package+"\x00"+binding.Version] = true
		}
		lockBytes, err := lockFileBytes(root, repository)
		if err != nil {
			return StatusWorkspaceResult{}, err
		}
		result.LockBytes += lockBytes
		artifacts, artifactBytes := retainedArtifacts(lock)
		statusRepository := StatusRepository{
			LockBytes: lockBytes, Artifacts: artifacts, ArtifactBytes: artifactBytes,
			DigestProvenance: digestProvenanceCounts(lock),
			Name:             name, Format: repository.Format, Track: repository.Track, Suite: repository.Suite,
			Visibility: repository.Visibility, GatePolicy: repository.Gate,
			RetainedPackageVersions: len(lock.PackageVersion), VisiblePackageVersions: len(visible), VisibleBindingState: "complete",
			VisiblePackages: make([]StatusPackage, 0, len(visible)), Deployment: StatusDeployment{State: "unrecorded"},
		}
		if len(missing) != 0 {
			statusRepository.VisibleBindingState = "incomplete"
		}
		for _, packageVersion := range visible {
			digests := make([]string, 0, len(packageVersion.Blobs))
			for _, locked := range packageVersion.Blobs {
				digests = append(digests, locked.SHA256)
			}
			sort.Strings(digests)
			binding := "complete"
			if missingBindings[packageVersion.Package+"\x00"+packageVersion.Version] {
				binding = "incomplete"
			}
			statusRepository.VisiblePackages = append(statusRepository.VisiblePackages, StatusPackage{
				Name: packageVersion.Package, Version: packageVersion.Version, BlobSHA256: digests, Binding: binding,
			})
		}
		sort.Slice(statusRepository.VisiblePackages, func(left, right int) bool {
			if statusRepository.VisiblePackages[left].Name != statusRepository.VisiblePackages[right].Name {
				return statusRepository.VisiblePackages[left].Name < statusRepository.VisiblePackages[right].Name
			}
			return statusRepository.VisiblePackages[left].Version < statusRepository.VisiblePackages[right].Version
		})
		deployment, err := state.LoadDeployment(root, name)
		if err != nil {
			return StatusWorkspaceResult{}, err
		}
		if deployment.SchemaVersion != 0 {
			if err := state.ValidateDeploymentProvenanceContext(ctx, root, name, deployment); err != nil {
				return StatusWorkspaceResult{}, err
			}
			statusRepository.Deployment = StatusDeployment{
				State: "recorded", PlanID: deployment.PlanID, TreeSHA256: deployment.TreeSHA256,
				NativeRevision: deployment.NativeRevision, DeployedAt: deployment.DeployedAt,
			}
		}
		result.Repositories = append(result.Repositories, statusRepository)
	}
	if err := ctx.Err(); err != nil {
		return StatusWorkspaceResult{}, err
	}
	if err := state.AssertGitRevisionContext(ctx, root, revision); err != nil {
		return StatusWorkspaceResult{}, err
	}
	return result, nil
}

// lockFileBytes is how large a repository's lock is on disk.
//
// Measured rather than estimated from the version count, because the whole point
// is to report the thing that actually gets parsed. A lock that has not been
// written yet is zero rather than an error: a configured repository with no
// packages is an ordinary state.
func lockFileBytes(root string, repository state.Repository) (int64, error) {
	name, err := state.WorkspacePath(root, repository.Lock)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// retainedArtifacts counts the distinct blobs a lock binds, and their total size.
//
// Distinct by digest, because a package-version binds one blob per architecture
// and the same blob can be bound by several versions — counting bindings would
// report storage that is not consumed twice.
func retainedArtifacts(lock state.RepositoryLock) (int, int64) {
	seen := make(map[string]int64)
	for _, packageVersion := range lock.PackageVersion {
		for _, blob := range packageVersion.Blobs {
			seen[blob.SHA256] = blob.Size
		}
	}
	var total int64
	for _, size := range seen {
		total += size
	}
	return len(seen), total
}

// digestProvenanceCounts counts distinct artifacts by how their digest was
// established.
//
// Distinct by SHA-256 for the same reason retainedArtifacts is: one blob bound by
// several versions is one artifact, and counting bindings would report a workspace
// as holding more unauthenticated bytes than it does.
func digestProvenanceCounts(lock state.RepositoryLock) map[string]int {
	seen := make(map[string]state.DigestProvenance)
	for _, packageVersion := range lock.PackageVersion {
		for _, blob := range packageVersion.Blobs {
			seen[blob.SHA256] = state.DigestProvenanceOf(blob)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	counts := make(map[string]int, len(seen))
	for _, provenance := range seen {
		counts[string(provenance)]++
	}
	return counts
}
