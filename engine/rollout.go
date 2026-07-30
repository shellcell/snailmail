package engine

import (
	"context"
	"sort"

	"github.com/shellcell/snailmail/internal/state"
)

const rolloutSchemaVersion = 1

// RolloutWorkspaceRequest asks when each package version was published.
type RolloutWorkspaceRequest struct {
	Root string
	// Repository and Package narrow the answer. Empty means every one.
	Repository string
	Package    string
	// IncludeWithdrawn reports versions that were published and are no longer
	// served. They are omitted by default because the ordinary question is what
	// a client can install today.
	IncludeWithdrawn bool
}

type RolloutWorkspaceResult struct {
	SchemaVersion int              `json:"schema_version"`
	Workspace     string           `json:"workspace"`
	GitRevision   string           `json:"git_revision"`
	Releases      []RolloutRelease `json:"releases"`
}

// RolloutRelease is one package version and when it reached a client.
type RolloutRelease struct {
	Repository string `json:"repository"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	// PublishedAt is when this version was first recorded as published. A
	// version republished later — a rebuilt tree, a rotated key — keeps the date
	// it first reached a client, because that is what the question asks.
	PublishedAt string `json:"published_at"`
	// Publications is how many published trees have included this version. Every
	// publication re-records every version it serves, so this counts the trees a
	// version has been carried through rather than times it was re-released —
	// the version's own bytes are pinned and never change.
	Publications int `json:"publications"`
	// Served reports whether the repository still offers it. False means it was
	// published and then withdrawn: yanked, or pruned from desired state.
	Served     bool     `json:"served"`
	TreeSHA256 string   `json:"tree_sha256"`
	Artifacts  []string `json:"artifacts"`
}

// RolloutWorkspace reports when each published version reached a client.
//
// It is derived rather than stored. The publication ledger already records one
// append-only entry per publication with its plan, change, artifacts and time,
// so the date is a fact this reads back — and a second object holding the same
// thing would be a second source of truth that could disagree with the first.
//
// Read-only, and against committed evidence: the ledger is validated the same
// way `status` validates it, so a rollout cannot be reported from records that
// were never committed.
func RolloutWorkspace(ctx context.Context, request RolloutWorkspaceRequest) (RolloutWorkspaceResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return RolloutWorkspaceResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return RolloutWorkspaceResult{}, err
	}
	defer unlock()
	revision, err := state.RequireCleanGitContext(ctx, root)
	if err != nil {
		return RolloutWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return RolloutWorkspaceResult{}, err
	}
	result := RolloutWorkspaceResult{
		SchemaVersion: rolloutSchemaVersion, Workspace: manifest.Workspace.Name,
		GitRevision: revision, Releases: []RolloutRelease{},
	}
	for _, name := range state.RepositoryNames(manifest) {
		if err := ctx.Err(); err != nil {
			return RolloutWorkspaceResult{}, err
		}
		if request.Repository != "" && request.Repository != name {
			continue
		}
		repository := manifest.Repositories[name]
		records, err := state.LoadLedgerHistoryAtRevisionContext(ctx, root, name, revision)
		if err != nil {
			return RolloutWorkspaceResult{}, err
		}
		if err := state.ValidatePublicationHistory(name, records); err != nil {
			return RolloutWorkspaceResult{}, err
		}
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return RolloutWorkspaceResult{}, err
		}
		if err := state.ValidateLock(lock, name, repository.Format); err != nil {
			return RolloutWorkspaceResult{}, err
		}
		served := make(map[string]bool)
		for _, packageVersion := range visiblePackageVersions(lock, repository) {
			served[packageVersion.Package+"\x00"+packageVersion.Version] = true
		}
		result.Releases = append(result.Releases, rolloutReleases(name, records, served, request)...)
	}
	sort.Slice(result.Releases, func(left, right int) bool {
		if result.Releases[left].Repository != result.Releases[right].Repository {
			return result.Releases[left].Repository < result.Releases[right].Repository
		}
		if result.Releases[left].Package != result.Releases[right].Package {
			return result.Releases[left].Package < result.Releases[right].Package
		}
		return result.Releases[left].Version < result.Releases[right].Version
	})
	if err := state.AssertGitRevisionContext(ctx, root, revision); err != nil {
		return RolloutWorkspaceResult{}, err
	}
	return result, nil
}

// rolloutReleases folds a repository's ledger into one entry per version.
//
// The ledger is append-only and ordered, so the first record for a version is
// when it reached a client and any later one is a republication of the same
// version. Both are reported: a rebuilt tree is not the same event as a first
// release, and collapsing them would lose that.
func rolloutReleases(repository string, records []state.PublicationRecord,
	served map[string]bool, request RolloutWorkspaceRequest) []RolloutRelease {
	index := make(map[string]int)
	releases := make([]RolloutRelease, 0, len(records))
	for _, record := range records {
		if request.Package != "" && request.Package != record.Package {
			continue
		}
		identity := record.Package + "\x00" + record.Version
		if at, seen := index[identity]; seen {
			releases[at].Publications++
			// The newest tree is the one a client is served from now.
			releases[at].TreeSHA256 = record.TreeSHA256
			releases[at].Artifacts = append([]string(nil), record.BlobSHA256...)
			continue
		}
		index[identity] = len(releases)
		releases = append(releases, RolloutRelease{
			Repository: repository, Package: record.Package, Version: record.Version,
			PublishedAt: record.RecordedAt, Served: served[identity], Publications: 1,
			TreeSHA256: record.TreeSHA256,
			Artifacts:  append([]string(nil), record.BlobSHA256...),
		})
	}
	if request.IncludeWithdrawn {
		return releases
	}
	offered := releases[:0]
	for _, release := range releases {
		if release.Served {
			offered = append(offered, release)
		}
	}
	return offered
}
