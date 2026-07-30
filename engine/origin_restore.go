package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

// ensureBlob resolves a locked blob, falling back to the origin the lock records
// when it is nowhere else to be found.
//
// A workspace keeps its content-addressed bytes outside Git, so a fresh clone
// holds the lock and none of the artifacts. Without a shared blob store that
// clone cannot build anything, which forces object storage on workspaces whose
// artifacts are already durably hosted somewhere public. Adoption already
// recorded where each artifact came from and pinned its digest, so that record
// is enough to fetch it again.
//
// This is not trust on arrival. The digest was committed and reviewed, and the
// refetched bytes are admitted through the same verification as every other
// source, so an origin that now serves something else fails instead of
// publishing.
func ensureBlob(ctx context.Context, root, format string, locked state.LockedBlob, store blob.Store, supplied formats.Identity, fetcher source.Fetcher) (domain.Blob, string, error) {
	loaded, name, err := state.EnsureBlob(ctx, root, format, locked, store, supplied)
	if err == nil {
		return loaded, name, nil
	}
	// Only absence is recoverable. A blob that is present and wrong is a
	// different signal, and quietly replacing it from the network would hide
	// exactly the tampering the digest exists to reveal.
	if fetcher == nil || locked.Origin == nil || !blobIsAbsent(err) {
		return domain.Blob{}, "", err
	}
	restored, restoredName, restoreErr := restoreBlobFromOrigin(ctx, root, format, locked, supplied, fetcher)
	if restoreErr != nil {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s is absent and could not be restored from %s: %w",
			locked.SHA256, locked.Origin.URL, restoreErr)
	}
	return restored, restoredName, nil
}

// blobIsAbsent reports whether the blob was missing rather than unusable.
func blobIsAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, blob.ErrNotFound)
}

func restoreBlobFromOrigin(ctx context.Context, root, format string, locked state.LockedBlob, supplied formats.Identity, fetcher source.Fetcher) (domain.Blob, string, error) {
	origin, err := url.Parse(locked.Origin.URL)
	if err != nil || source.ValidatePublicURL(origin) != nil {
		return domain.Blob{}, "", errors.New("recorded origin is not a public HTTPS URL")
	}
	// The same bound adoption applies. Nothing can carry an origin without
	// having been adopted, so no blob reachable here was ever larger.
	response, err := fetcher.Fetch(ctx, origin.String(), maximumArtifactBytes())
	if err != nil {
		return domain.Blob{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return domain.Blob{}, "", err
	}
	if response.StatusCode == http.StatusNotFound {
		return domain.Blob{}, "", blob.ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return domain.Blob{}, "", fmt.Errorf("origin returned HTTP %d", response.StatusCode)
	}
	if response.URL != "" {
		finalURL, parseErr := url.Parse(response.URL)
		if parseErr != nil || source.ValidateRedirectURL(finalURL) != nil {
			return domain.Blob{}, "", errors.New("origin redirected to an unsafe URL")
		}
	}
	// InstallBlob hashes what is written and keeps it only if it matches the
	// locked digest, so the size check here only avoids writing an obviously
	// wrong body.
	if int64(len(response.Body)) != locked.Size {
		return domain.Blob{}, "", blob.ErrCorrupt
	}
	return state.InstallBlob(root, format, locked, supplied, func(destination io.Writer) error {
		_, writeErr := destination.Write(response.Body)
		return writeErr
	})
}
