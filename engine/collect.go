package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/state"
)

const collectSchemaVersion = 1

// CollectWorkspaceRequest asks a host to remove state its publications have
// superseded.
type CollectWorkspaceRequest struct {
	Root string
	// Repository narrows the work to one. Empty collects every repository whose
	// host can.
	Repository string
	// Keep is how many recent publications to retain beyond what a host protects
	// on its own. Zero keeps only the minimum: the live revision and whatever its
	// restore rolls back to.
	Keep int
	// Apply performs the deletion. Without it this reports what would be removed
	// and removes nothing, which is the default because the alternative is a
	// command that deletes published state when someone was curious.
	Apply bool
	Hosts host.Resolver
}

type CollectWorkspaceResult struct {
	SchemaVersion int                 `json:"schema_version"`
	Workspace     string              `json:"workspace"`
	GitRevision   string              `json:"git_revision"`
	Applied       bool                `json:"applied"`
	Removed       int                 `json:"removed"`
	RemovedBytes  int64               `json:"removed_bytes"`
	Repositories  []CollectRepository `json:"repositories"`
}

// CollectRepository is what one repository's host reported.
type CollectRepository struct {
	Name string `json:"name"`
	// Collectable is false where the host keeps nothing to collect — a local
	// directory, or Pages, where unreachable objects are git's business. Reported
	// rather than omitted, so a reader is not left wondering whether it was skipped
	// or had nothing.
	Collectable   bool   `json:"collectable"`
	Removed       int    `json:"removed"`
	RemovedBytes  int64  `json:"removed_bytes"`
	KeptRevisions int    `json:"kept_revisions"`
	Note          string `json:"note,omitempty"`
}

// CollectWorkspace removes published state that later publications superseded.
//
// The policy is here and the deletion is in the host, because each knows something
// the other cannot. Which publications happened, and in what order, is in the
// ledger; what is actually present in a bucket is not. So this derives the trees
// worth keeping and the host decides what that means for its own layout — and
// protects the live revision and its restore target independently, because a
// workspace whose ledger is behind must not be able to delete what is being
// served.
//
// Read-only against committed evidence, like status and rollout: the ledger is
// validated the same way, so nothing is collected on the strength of records that
// were never committed.
func CollectWorkspace(ctx context.Context, request CollectWorkspaceRequest) (CollectWorkspaceResult, error) {
	if request.Keep < 0 {
		return CollectWorkspaceResult{}, fmt.Errorf("keep %d is not a number of publications", request.Keep)
	}
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return CollectWorkspaceResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return CollectWorkspaceResult{}, err
	}
	defer unlock()
	revision, err := state.RequireCleanGitContext(ctx, root)
	if err != nil {
		return CollectWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return CollectWorkspaceResult{}, err
	}
	hosts := request.Hosts
	if hosts == nil {
		hosts = localHostResolver{}
	}
	result := CollectWorkspaceResult{
		SchemaVersion: collectSchemaVersion, Workspace: manifest.Workspace.Name,
		GitRevision: revision, Applied: request.Apply, Repositories: []CollectRepository{},
	}
	for _, name := range state.RepositoryNames(manifest) {
		if err := ctx.Err(); err != nil {
			return CollectWorkspaceResult{}, err
		}
		if request.Repository != "" && request.Repository != name {
			continue
		}
		repository := manifest.Repositories[name]
		reported, err := collectRepository(ctx, collectContext{
			root: root, name: name, repository: repository, revision: revision,
			hosts: hosts, keep: request.Keep, apply: request.Apply,
			workspaceID: manifest.Workspace.ID,
		})
		if err != nil {
			return CollectWorkspaceResult{}, fmt.Errorf("repository %q: %w", name, err)
		}
		result.Repositories = append(result.Repositories, reported)
		result.Removed += reported.Removed
		result.RemovedBytes += reported.RemovedBytes
	}
	if request.Repository != "" && len(result.Repositories) == 0 {
		return CollectWorkspaceResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	return result, nil
}

type collectContext struct {
	root        string
	name        string
	repository  state.Repository
	revision    string
	workspaceID string
	hosts       host.Resolver
	keep        int
	apply       bool
}

func collectRepository(ctx context.Context, request collectContext) (CollectRepository, error) {
	reported := CollectRepository{Name: request.name}
	hostIdentity, err := repositoryHostIdentity(request.repository)
	if err != nil {
		return reported, err
	}
	hostRepository := toHostRepository(request.root, request.workspaceID, hostIdentity, request.name, request.repository)
	selected, err := request.hosts.Resolve(ctx, hostRepository)
	if err != nil {
		return reported, err
	}
	collector, ok := selected.(host.Collector)
	if !ok {
		// Not a failure. A local directory leaves nothing behind and Pages leaves it
		// to git, so there is genuinely nothing here to collect.
		reported.Note = "host keeps no superseded state"
		return reported, nil
	}
	reported.Collectable = true
	keepTrees, err := recentPublishedTrees(ctx, request.root, request.name, request.revision, request.keep)
	if err != nil {
		return reported, err
	}
	collected, err := collector.Collect(ctx, hostRepository, host.Retention{
		KeepTrees: keepTrees, DryRun: !request.apply,
	})
	if err != nil {
		return reported, err
	}
	reported.Removed = collected.Removed
	reported.RemovedBytes = collected.RemovedBytes
	reported.KeptRevisions = collected.KeptRevisions
	return reported, nil
}

// recentPublishedTrees is the newest keep distinct trees the ledger records.
//
// Distinct, because every publication re-records every version it serves, so one
// tree appears in many entries. Newest by ledger order rather than by timestamp:
// the ledger is append-only and a clock is not a reliable ordering across machines.
func recentPublishedTrees(ctx context.Context, root, name, revision string, keep int) ([]string, error) {
	if keep == 0 {
		return nil, nil
	}
	records, err := state.LoadLedgerHistoryAtRevisionContext(ctx, root, name, revision)
	if err != nil {
		return nil, err
	}
	if err := state.ValidatePublicationHistory(name, records); err != nil {
		return nil, err
	}
	return newestDistinctTrees(records, keep), nil
}

// newestDistinctTrees picks the newest keep revisions out of a ledger.
//
// Separated from the loading so the selection can be tested without a workspace,
// which is where the reasoning is: distinct revisions rather than records, ledger
// order rather than timestamps, and a sorted result.
func newestDistinctTrees(records []state.PublicationRecord, keep int) []string {
	if keep <= 0 {
		return nil
	}
	seen := make(map[string]bool)
	trees := make([]string, 0, keep)
	for index := len(records) - 1; index >= 0 && len(trees) < keep; index-- {
		tree := records[index].TreeSHA256
		if tree == "" || seen[tree] {
			continue
		}
		seen[tree] = true
		trees = append(trees, tree)
	}
	// Sorted so the retention passed to a host is a function of its contents rather
	// than of ledger order, which keeps a dry run reproducible.
	sort.Strings(trees)
	return trees
}
