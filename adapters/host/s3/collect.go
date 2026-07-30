package s3host

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

// releasePrefix is where every revision's immutable copy lives, relative to the
// repository. Collection works entirely within it.
const releasePrefix = ".snailmail/releases/"

// Collect removes release directories no longer needed.
//
// An object store keeps every revision it has ever published: a publication writes
// a whole tree under .snailmail/releases/<tree>/ and nothing ever removes the
// previous one. A project publishing daily accumulates a copy a day, and is never
// told.
//
// What survives:
//
//   - Every tree the retention names, which is the caller's ledger-derived set.
//   - The live revision, read from the root object here rather than trusted from
//     the caller. A caller that computed its set from a stale ledger would
//     otherwise delete what is being served.
//   - Whatever the live revision's restore reference depends on. Restore validates
//     the release it is rolling back to before putting its root back, so removing
//     that release turns a recoverable failure into an unrecoverable one.
//
// It removes nothing unless it can establish all three. A collection that cannot
// tell what is live is a collection that must not run.
func (adapter *Adapter) Collect(ctx context.Context, repository host.Repository, retention host.Retention) (host.CollectResult, error) {
	if err := adapter.validateRepository(repository); err != nil {
		return host.CollectResult{}, err
	}
	if _, err := singleRootPath(repository); err != nil {
		return host.CollectResult{}, err
	}
	keep, err := adapter.protectedTrees(ctx, repository, retention)
	if err != nil {
		return host.CollectResult{}, err
	}
	prefix := objectKey(repository, releasePrefix)
	// Trailing separator matters: without it a repository whose prefix is a prefix
	// of another's name would list the other's releases and offer to delete them.
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	result := host.CollectResult{DryRun: retention.DryRun, KeptRevisions: len(keep)}
	seen := make(map[string]bool)
	after := ""
	for {
		page, err := adapter.client.List(ctx, ListRequest{Prefix: prefix, After: after})
		if err != nil {
			return host.CollectResult{}, infrastructure("list S3 releases", err)
		}
		for _, object := range page.Objects {
			tree, ok := treeFromReleaseKey(prefix, object.Key)
			if !ok {
				// A key under the release prefix that does not name a revision is
				// left alone. Something other than this adapter put it there, and
				// deleting what it does not recognise is not collection.
				continue
			}
			seen[tree] = true
			if keep[tree] {
				continue
			}
			result.Removed++
			result.RemovedBytes += object.Size
			if retention.DryRun {
				continue
			}
			// Unconditional: a release object is immutable, so there is no revision
			// to guard against, and a conditional delete would only fail where a
			// concurrent collection had already removed it.
			if err := adapter.client.Delete(ctx, object.Key, Conditions{}); err != nil && !errors.Is(err, ErrNotFound) {
				return host.CollectResult{}, infrastructure("delete superseded S3 release object", err)
			}
		}
		if page.More == "" {
			break
		}
		after = page.More
	}
	// Counted from what is present rather than from the retention, so the number
	// describes the bucket and not the request.
	kept := 0
	for tree := range seen {
		if keep[tree] {
			kept++
		}
	}
	result.KeptRevisions = kept

	// Release directories are only half of what accumulates, and for helm and rpm
	// they are the smaller half.
	orphans, err := adapter.collectOrphanedObjects(ctx, repository, keep, retention)
	if err != nil {
		return host.CollectResult{}, err
	}
	result.Removed += orphans.Removed
	result.RemovedBytes += orphans.RemovedBytes
	return result, nil
}

// collectOrphanedObjects removes canonical-path objects no surviving revision
// names.
//
// The two publication shapes accumulate differently. A staged repository — PyPI,
// anything with a root rewrite — writes every file inside the release directory, so
// collecting release directories collects everything and there is nothing here to
// do. A canonical-path repository — helm, unsigned rpm — writes its artifacts at
// the paths clients fetch them from, outside any release directory, because their
// indexes name those paths and rewriting an rpm would invalidate its signature.
// Nothing has ever removed those. A chart deleted from the workspace a year ago is
// still a billable object, and collecting release directories never touches it.
//
// What is referenced is read from the manifests of the revisions that survive,
// which is the only record of which files a revision published. If any of those
// manifests cannot be read the whole collection is refused: an unreadable manifest
// means an unknown reference set, and deleting against an unknown reference set
// deletes live artifacts.
func (adapter *Adapter) collectOrphanedObjects(ctx context.Context, repository host.Repository,
	keep map[string]bool, retention host.Retention) (host.CollectResult, error) {
	if repository.RootRewriter != nil {
		// Staged: every published file already lives under a release directory, so
		// there is nothing at a canonical path to orphan.
		return host.CollectResult{}, nil
	}
	referenced, err := adapter.referencedObjectKeys(ctx, repository, keep)
	if err != nil {
		return host.CollectResult{}, err
	}
	prefix := objectKey(repository, "")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	reserved := objectKey(repository, ".snailmail")
	var result host.CollectResult
	after := ""
	for {
		page, err := adapter.client.List(ctx, ListRequest{Prefix: prefix, After: after})
		if err != nil {
			return host.CollectResult{}, infrastructure("list S3 objects", err)
		}
		for _, object := range page.Objects {
			// Everything snailmail owns is under .snailmail, and release collection
			// above is what governs it.
			if object.Key == reserved || strings.HasPrefix(object.Key, reserved+"/") {
				continue
			}
			if referenced[object.Key] {
				continue
			}
			result.Removed++
			result.RemovedBytes += object.Size
			if retention.DryRun {
				continue
			}
			if err := adapter.client.Delete(ctx, object.Key, Conditions{}); err != nil && !errors.Is(err, ErrNotFound) {
				return host.CollectResult{}, infrastructure("delete orphaned S3 object", err)
			}
		}
		if page.More == "" {
			break
		}
		after = page.More
	}
	return result, nil
}

// referencedObjectKeys is every canonical key the surviving revisions publish.
//
// Read from each release descriptor, which records the file set of its revision and
// is keyed by tree — unlike the build-graph manifest, which is stored by its own
// digest and so cannot be found from a tree alone. loadRelease validates the
// descriptor against the tree it claims, so a descriptor that has been tampered
// with fails here rather than producing a short reference set, which is the
// dangerous direction.
func (adapter *Adapter) referencedObjectKeys(ctx context.Context, repository host.Repository,
	keep map[string]bool) (map[string]bool, error) {
	referenced := make(map[string]bool)
	for tree := range keep {
		release, _, err := adapter.loadRelease(ctx, repository, tree)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				// A revision that must survive but whose descriptor is gone. Its file
				// set is unknowable, so any canonical object might be one of its
				// artifacts and none of them can be attributed.
				return nil, &host.Error{Kind: host.ErrorIndeterminate, Operation: "collect orphaned S3 objects",
					Err: fmt.Errorf("revision %s has no release descriptor, so the files it publishes cannot be established", tree)}
			}
			return nil, err
		}
		for _, file := range release.Files {
			// objectKey rather than publishedFileKey: this is where a client fetches
			// the file from, which is what must survive. The release directory's copy
			// is under .snailmail and is governed by release collection above. The
			// root is included by the same rule, and has to be — for helm the live
			// index.yaml sits at a canonical path, and omitting it here would collect
			// the very object being served.
			referenced[objectKey(repository, file.Path)] = true
		}
	}
	return referenced, nil
}

// protectedTrees is every tree digest that must survive.
//
// Derived from the object store as well as from the caller, because the caller's
// set comes from a ledger that may be behind what is actually published — a plan
// applied by another machine, or a restore that has not been recorded yet.
func (adapter *Adapter) protectedTrees(ctx context.Context, repository host.Repository, retention host.Retention) (map[string]bool, error) {
	keep := make(map[string]bool, len(retention.KeepTrees)+2)
	for _, tree := range retention.KeepTrees {
		if !hexdigest.ValidSHA256(tree) {
			return nil, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "collect S3 releases",
				Err: fmt.Errorf("retention names %q, which is not a tree digest", tree)}
		}
		keep[tree] = true
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		// Refused rather than continued: without knowing what is live, every
		// deletion is a guess.
		return nil, err
	}
	if observed.TreeSHA256 == "" {
		// An unmanaged or empty repository. There is a root nobody here published,
		// or none at all, so nothing under the release prefix can be attributed and
		// nothing is removed.
		return nil, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "collect S3 releases",
			Err: errors.New("repository has no managed revision, so no release can be identified as superseded")}
	}
	keep[observed.TreeSHA256] = true
	if observed.RestoreID == "" {
		return keep, nil
	}
	restore, _, err := adapter.loadRestore(ctx, repository, observed.RestoreID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// The live revision names a restore whose descriptor is gone. That is a
			// repository that cannot roll back, and not something to compound by
			// deleting more.
			return nil, &host.Error{Kind: host.ErrorIndeterminate, Operation: "collect S3 releases",
				Err: errors.New("live revision names a restore reference that is missing")}
		}
		return nil, err
	}
	// The tree the live revision replaced. Restore reads that release's file set
	// before putting its root back, so it has to outlive the revision that
	// superseded it.
	if restore.BeforeTreeSHA256 != "" {
		keep[restore.BeforeTreeSHA256] = true
	}
	return keep, nil
}

// treeFromReleaseKey reads the revision a release object belongs to out of its
// key, and reports whether the key is one this adapter wrote.
func treeFromReleaseKey(prefix, key string) (string, bool) {
	remainder := strings.TrimPrefix(key, prefix)
	if remainder == key {
		return "", false
	}
	tree, rest, found := strings.Cut(remainder, "/")
	if !found || rest == "" || !hexdigest.ValidSHA256(tree) {
		return "", false
	}
	return tree, true
}
