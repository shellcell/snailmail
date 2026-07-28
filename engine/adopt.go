package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

const maximumAdoptBytes = 128 << 20

type AdoptArtifactRequest struct {
	Root       string
	Repository string
	URL        string
	SHA256     string
	Filename   string
	// Name and Version supply identity for a format whose artifacts carry none.
	Name         string
	Version      string
	Track        string
	Distro       string
	DryRun       bool
	PublicOrigin bool
	Fetcher      source.Fetcher
}

type AdoptArtifactResult struct {
	Repository string `json:"repository"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	Filename   string `json:"filename"`
	SHA256     string `json:"sha256"`
	OriginURL  string `json:"origin_url"`
	Changed    bool   `json:"changed"`
	DryRun     bool   `json:"dry_run"`
}

func AdoptArtifact(ctx context.Context, request AdoptArtifactRequest) (AdoptArtifactResult, error) {
	if request.Fetcher == nil {
		return AdoptArtifactResult{}, errors.New("adopt fetcher is required")
	}
	if !request.PublicOrigin {
		return AdoptArtifactResult{}, errors.New("adopt requires confirmation that the persisted origin URL is public and contains no secrets")
	}
	decoded, err := hex.DecodeString(request.SHA256)
	if err != nil || len(decoded) != sha256.Size || request.SHA256 != strings.ToLower(request.SHA256) {
		return AdoptArtifactResult{}, errors.New("adopt requires a lowercase SHA-256 pin")
	}
	originURL, err := url.Parse(request.URL)
	if err != nil || source.ValidatePublicURL(originURL) != nil {
		return AdoptArtifactResult{}, errors.New("adopt URL must be a safe public HTTPS URL")
	}
	filename := request.Filename
	if filename == "" {
		filename = path.Base(originURL.Path)
	}
	if filename == "" || filename == "." || filepath.Base(filename) != filename || strings.ContainsAny(filename, "\x00\r\n/\\") {
		return AdoptArtifactResult{}, errors.New("adopt requires a safe artifact filename")
	}
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.RequireGitRepositoryContext(ctx, root); err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.RequireCompleteGitHistoryContext(ctx, root); err != nil {
		return AdoptArtifactResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if state.BlobConfiguration(manifest).Type != "local" {
		return AdoptArtifactResult{}, errors.New("adopt requires a local blob store; migrate blobs explicitly after review")
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return AdoptArtifactResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	lock, err := state.LoadLock(root, repository)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return AdoptArtifactResult{}, err
	}
	ledger, err := state.LoadLedgerHistoryContext(ctx, root, request.Repository)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.ValidatePublicationHistory(request.Repository, ledger); err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return AdoptArtifactResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	response, err := request.Fetcher.Fetch(ctx, originURL.String(), maximumAdoptBytes)
	if err != nil {
		return AdoptArtifactResult{}, fmt.Errorf("fetch adopted artifact: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return AdoptArtifactResult{}, fmt.Errorf("adopted artifact returned HTTP %d", response.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return AdoptArtifactResult{}, err
	}
	if response.URL != "" {
		finalURL, parseErr := url.Parse(response.URL)
		if parseErr != nil || source.ValidateRedirectURL(finalURL) != nil {
			return AdoptArtifactResult{}, errors.New("adopt fetcher returned an unsafe final URL")
		}
	}
	actualDigest := sha256.Sum256(response.Body)
	if hex.EncodeToString(actualDigest[:]) != request.SHA256 {
		return AdoptArtifactResult{}, errors.New("adopted artifact does not match the required SHA-256")
	}
	blob, err := state.InspectArtifactBytes(repository.Format, filename, response.Body, adoptIdentity(repository.Format, request))
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return AdoptArtifactResult{}, err
	}
	packageName := nativePackageName(repository.Format, blob.Facts.Name)
	track := request.Track
	if track == "" {
		track = repository.Track
	}
	distro := defaultPlacementDistro(repository, request.Distro)
	locked := state.ToLockedBlob(blob)
	locked.Origin = &state.ArtifactOrigin{Kind: "https", URL: originURL.String()}
	added, err := state.AddBlob(&lock, repository.Format, track, distro, locked, packageName, blob.Facts.Version)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	originChanged, err := state.SetBlobOrigin(&lock, packageName, blob.Facts.Version, filename, blob.SHA256, *locked.Origin)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	changed := added || originChanged
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return AdoptArtifactResult{}, err
	}
	result := AdoptArtifactResult{
		Repository: request.Repository, Package: packageName, Version: blob.Facts.Version,
		Filename: filename, SHA256: blob.SHA256, OriginURL: originURL.String(), Changed: changed, DryRun: request.DryRun,
	}
	if request.DryRun {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return AdoptArtifactResult{}, err
	}
	temporaryDirectory, err := os.MkdirTemp("", ".snailmail-adopt-*")
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	defer os.RemoveAll(temporaryDirectory)
	temporaryName := filepath.Join(temporaryDirectory, filename)
	if err := os.WriteFile(temporaryName, response.Body, 0o600); err != nil {
		return AdoptArtifactResult{}, err
	}
	stored, err := state.PutArtifact(root, repository.Format, temporaryName, adoptIdentity(repository.Format, request))
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	if stored.SHA256 != blob.SHA256 {
		return AdoptArtifactResult{}, errors.New("adopted artifact changed before CAS storage")
	}
	if err := ctx.Err(); err != nil {
		return AdoptArtifactResult{}, err
	}
	if !changed {
		return result, nil
	}
	if err := state.WriteLock(root, repository, lock); err != nil {
		return AdoptArtifactResult{}, err
	}
	return result, nil
}

// adoptIdentity supplies identity for a format whose artifacts carry none.
// Adoption selects one artifact by digest from a URL, so a raw artifact still
// needs a name and version; they come from the same flags `add` uses.
//
// What the operator typed is passed through unfiltered so a format that reads
// identity from the bytes rejects it. Filtering here would silently discard the
// flags instead, leaving an operator believing they had renamed an artifact.
func adoptIdentity(_ string, request AdoptArtifactRequest) formats.Identity {
	return formats.Identity{Name: request.Name, Version: request.Version}
}
