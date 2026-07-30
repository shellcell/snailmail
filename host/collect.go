package host

import "context"

// Collector is implemented by a host that accumulates state a later publication
// supersedes.
//
// Optional rather than part of Host, because most hosts do not. A local directory
// exchanges one directory entry and leaves nothing behind; GitHub Pages moves a
// ref to an orphan commit, where anything unreachable is git's problem and git
// already has a collector. An object store is the one that keeps every revision it
// has ever published, because it has no notion of reachability — so it is the one
// that has to be told.
//
// Discovered by type assertion, the way a format's root rewrite is: a host that
// does not implement this has nothing to collect, which is a different statement
// from a host that failed to collect.
type Collector interface {
	// Collect removes superseded state, keeping everything the retention names.
	//
	// It must never remove what a live revision or a pending restore depends on,
	// and when it cannot establish what those are it must remove nothing. Deleting
	// too little costs storage; deleting too much costs a repository.
	Collect(context.Context, Repository, Retention) (CollectResult, error)
}

// Retention says what a collection must keep.
//
// Named trees rather than a count, because the caller knows things a host cannot:
// which publications the ledger records, and in what order. A host knows only what
// is present, and what is present includes revisions that were never successfully
// published.
type Retention struct {
	// KeepTrees are tree digests that must survive, whatever else is removed. The
	// caller is responsible for including the live revision and anything a restore
	// reference depends on; a host also protects those independently, because a
	// caller that forgot would otherwise break a repository.
	KeepTrees []string
	// DryRun reports what would be removed without removing it. The result is
	// otherwise identical, so a caller can show an operator the size of a deletion
	// before making it.
	DryRun bool
}

// CollectResult is what a collection did, or would have done.
type CollectResult struct {
	// Removed and RemovedBytes count what was deleted. Under a dry run they count
	// what would have been.
	Removed      int   `json:"removed"`
	RemovedBytes int64 `json:"removed_bytes"`
	// KeptRevisions is how many revisions survived, so a caller can report that a
	// collection kept what it was told to rather than only what it removed.
	KeptRevisions int  `json:"kept_revisions"`
	DryRun        bool `json:"dry_run,omitempty"`
}
