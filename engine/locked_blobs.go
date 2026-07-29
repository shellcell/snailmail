package engine

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

// maxConcurrentBlobLoads bounds how many artifacts are read at once.
//
// Reading one means hashing every byte of it and then inspecting it, and for
// Debian inspection means decompressing the whole data archive to check every
// path in it against traversal. Measured on a 6 MB package: 2ms to hash and
// 36ms to inspect, so this is processor-bound and the bound follows the
// processors rather than being a guess.
var maxConcurrentBlobLoads = min(runtime.NumCPU(), 8)

type loadedBlob struct {
	blob   domain.Blob
	source string
}

// loadLockedBlobs reads and verifies every artifact a repository publishes.
//
// Concurrently, because each artifact is independent: the bytes are read from a
// content-addressed store, the facts are derived from those bytes alone, and
// nothing written for one is read by another. Doing this serially made a
// publication wait on decompressing one package before starting the next, for
// no reason other than the order a loop happened to be written in.
//
// Nothing is skipped or remembered across runs. Every byte is hashed against
// the lock and every artifact is inspected, every time — which is the property
// this project's value rests on, and the reason the facts memo is deliberately
// per-process. This makes that work overlap; it does not make it optional.
//
// Results keep the lock's order, so a repository builds identically however the
// goroutines were scheduled.
func loadLockedBlobs(ctx context.Context, root string, repository state.Repository,
	active []state.PackageVersion, selected formats.Format, blobStore blob.Store, fetcher source.Fetcher) ([]loadedBlob, error) {
	type request struct {
		locked   state.LockedBlob
		identity formats.Identity
		name     string
		version  string
	}
	var requests []request
	for _, packageVersion := range active {
		for _, locked := range packageVersion.Blobs {
			requests = append(requests, request{
				locked:   locked,
				identity: formats.IdentityFor(selected, packageVersion.Package, packageVersion.Version),
				name:     packageVersion.Package,
				version:  packageVersion.Version,
			})
		}
	}
	if len(requests) == 0 {
		return nil, nil
	}

	loaded := make([]loadedBlob, len(requests))
	failures := make([]error, len(requests))
	slots := make(chan struct{}, min(maxConcurrentBlobLoads, len(requests)))
	var reading sync.WaitGroup
	for index, item := range requests {
		reading.Add(1)
		go func(index int, item request) {
			defer reading.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if err := ctx.Err(); err != nil {
				failures[index] = err
				return
			}
			found, source, err := ensureBlob(ctx, root, repository.Format, item.locked, blobStore, item.identity, fetcher)
			if err != nil {
				failures[index] = err
				return
			}
			// The bytes have to be the package the lock says they are. A blob
			// that inspects as something else means the lock and the store
			// disagree, which is exactly what pinning by digest exists to catch.
			if nativePackageName(repository.Format, found.Facts.Name) != item.name || found.Facts.Version != item.version {
				failures[index] = fmt.Errorf("blob %s disagrees with package version %s@%s", item.locked.SHA256, item.name, item.version)
				return
			}
			loaded[index] = loadedBlob{blob: found, source: source}
		}(index, item)
	}
	reading.Wait()
	// The first failure in lock order, so a repeated build names the same
	// artifact however the goroutines were scheduled.
	for _, err := range failures {
		if err != nil {
			return nil, err
		}
	}
	return loaded, nil
}
