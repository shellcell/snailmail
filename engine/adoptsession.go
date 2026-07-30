package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/shellcell/snailmail/internal/state"
)

// An adopt session is the workspace state every adoption needs, opened once.
//
// Adopting one artifact by hand can afford to establish everything from scratch:
// check the git repository, take the workspace lock, load the manifest, the lock
// and the publication ledger, then write the lock at the end. Importing a
// repository adopts thousands, and doing that per artifact was measured at 35 ms
// each regardless of repository size — three git invocations, a lock acquire, and
// a full lock write with fsync, none of which the second artifact needs repeated.
// At the 63,440-artifact Debian suite that is 37 minutes before a byte is
// downloaded, and it grows with the lock.
//
// So the prologue and the write are separated from the per-artifact work. A caller
// holding a session adopts into it and flushes when it chooses; a caller without
// one gets the original behaviour, where every adoption is complete on its own.
type adoptSession struct {
	root       string
	repository state.Repository
	lock       state.RepositoryLock
	ledger     []state.PublicationRecord
	name       string
	// dirty records whether anything has been added since the last flush, so a
	// flush that would rewrite an unchanged lock does nothing.
	dirty bool
}

// openAdoptSession establishes everything an adoption needs and takes the
// workspace lock, which the returned function releases.
func openAdoptSession(ctx context.Context, root, repositoryName string) (*adoptSession, func(), error) {
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return nil, nil, err
	}
	session, err := loadAdoptSession(ctx, root, repositoryName)
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return session, unlock, nil
}

// loadAdoptSession reads the workspace state, with the workspace lock already held.
func loadAdoptSession(ctx context.Context, root, repositoryName string) (*adoptSession, error) {
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return nil, err
	}
	if state.BlobConfiguration(manifest).Type != "local" {
		return nil, errors.New("adopt requires a local blob store; migrate blobs explicitly after review")
	}
	repository, exists := manifest.Repositories[repositoryName]
	if !exists {
		return nil, fmt.Errorf("repository %q is not configured", repositoryName)
	}
	lock, err := state.LoadLock(root, repository)
	if err != nil {
		return nil, err
	}
	if err := state.ValidateLock(lock, repositoryName, repository.Format); err != nil {
		return nil, err
	}
	ledger, err := state.LoadLedgerHistoryContext(ctx, root, repositoryName)
	if err != nil {
		return nil, err
	}
	if err := state.ValidatePublicationHistory(repositoryName, ledger); err != nil {
		return nil, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return nil, err
	}
	return &adoptSession{
		root: root, repository: repository, lock: lock, ledger: ledger, name: repositoryName,
	}, nil
}

// flush writes the lock if anything has been adopted into it since the last one.
//
// Called at a checkpoint rather than only at the end, so an import interrupted
// part way leaves a consistent lock holding what it managed — the property
// per-artifact writing gave for free, kept at a fraction of the cost.
func (session *adoptSession) flush() error {
	if !session.dirty {
		return nil
	}
	if err := state.WriteLock(session.root, session.repository, session.lock); err != nil {
		return err
	}
	session.dirty = false
	return nil
}
