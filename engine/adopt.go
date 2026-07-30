package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

// DefaultMaxArtifactBytes bounds a single fetched artifact.
//
// It used to be 128 MiB because the artifact was held whole in memory, which made
// it a memory limit wearing the costume of a policy about package size — and real
// packages exceeded it. 0ad-data in Debian bookworm is over 128 MiB, so importing
// that suite skipped it.
//
// Adoption now spools to a file, so the cost of a large artifact is disk and time
// rather than resident memory, and the limit can reflect what it is actually for:
// stopping a server from handing over something absurd, not stopping a legitimate
// package from being adopted. Two gigabytes is past every package in the
// distributions this reads and still bounded.
const DefaultMaxArtifactBytes = 2 << 30

const MaxArtifactBytesEnvironment = "SNAILMAIL_MAX_ARTIFACT_BYTES"

// maximumArtifactBytes is the limit in force. A value that is not a positive number
// is ignored rather than treated as zero, because a typo must not refuse every
// artifact.
func maximumArtifactBytes() int64 {
	given := os.Getenv(MaxArtifactBytesEnvironment)
	if given == "" {
		return DefaultMaxArtifactBytes
	}
	parsed, err := strconv.ParseInt(given, 10, 64)
	if err != nil || parsed <= 0 {
		return DefaultMaxArtifactBytes
	}
	return parsed
}

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
	// Provenance is how the caller established SHA256. Empty means the operator
	// supplied it, which is what adopt has always required of a person and what
	// every lock written before this field recorded.
	Provenance state.DigestProvenance
	Fetcher    source.Fetcher

	// session, when set, is an open adopt session the caller owns: it already
	// holds the workspace lock and the loaded state, and it decides when the lock
	// is written. Unexported because it is not a choice a caller outside this
	// package can make — import sets it to avoid re-establishing the workspace
	// once per artifact, which is otherwise the dominant cost of an import.
	session *adoptSession
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
	// A digest is required, with one exception, and it is stated rather than
	// inferred: the caller may omit it only by declaring the pin computed. That is
	// for a format whose index cannot state one at all — Alpine, whose C: field
	// digests a control section rather than a file. Making the exception a
	// consequence of the provenance the caller asked for means a lock can never
	// hold a computed pin that nothing recorded as computed.
	computing := request.SHA256 == "" && request.Provenance == state.ProvenanceComputed
	if !computing {
		decoded, err := hex.DecodeString(request.SHA256)
		if err != nil || len(decoded) != sha256.Size || request.SHA256 != strings.ToLower(request.SHA256) {
			return AdoptArtifactResult{}, errors.New("adopt requires a lowercase SHA-256 pin")
		}
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
	session := request.session
	if session == nil {
		opened, closeSession, err := openAdoptSession(ctx, root, request.Repository)
		if err != nil {
			return AdoptArtifactResult{}, err
		}
		defer closeSession()
		session = opened
	}
	repository, lock, ledger := session.repository, &session.lock, session.ledger
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Spooled to a file rather than held in memory. The artifact is going to disk
	// anyway — it is hashed, inspected and then stored content-addressed — so
	// accumulating it first bought nothing and made the size limit a memory limit.
	temporaryDirectory, err := os.MkdirTemp("", ".snailmail-adopt-*")
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	defer os.RemoveAll(temporaryDirectory)
	temporaryName := filepath.Join(temporaryDirectory, filename)
	spooled, err := os.OpenFile(temporaryName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	defer spooled.Close()
	response, err := fetchArtifact(ctx, request.Fetcher, originURL.String(), spooled)
	if err != nil {
		if errors.Is(err, source.ErrLimit) {
			// Naming the remedy, because the alternative reads as "this package is
			// too big" when what it means is "this machine was told to hold less".
			return AdoptArtifactResult{}, fmt.Errorf(
				"%s is larger than the %d byte artifact limit; raise %s to adopt it: %w",
				filename, maximumArtifactBytes(), MaxArtifactBytesEnvironment, err)
		}
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
	if _, err := spooled.Seek(0, io.SeekStart); err != nil {
		return AdoptArtifactResult{}, err
	}
	blob, err := state.InspectArtifactFile(repository.Format, filename, spooled, response.Size,
		adoptIdentity(repository.Format, request))
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	// When computing, there is nothing to compare against: the digest recorded is of
	// the bytes that arrived, which is exactly what ProvenanceComputed says and no
	// more. Everywhere else the stated digest is the gate.
	if !computing && blob.SHA256 != request.SHA256 {
		return AdoptArtifactResult{}, errors.New("adopted artifact does not match the required SHA-256")
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
	// Stamped when the artifact is adopted, not when it is published: a lock is
	// reviewed and applied later, and re-applying it must not move the date.
	locked.Added = state.LockTime(time.Now())
	provenance := request.Provenance
	if provenance == "" {
		provenance = state.ProvenanceOperator
	}
	if !state.ValidProvenance(provenance) {
		return AdoptArtifactResult{}, fmt.Errorf("digest provenance %q is not one snailmail records", provenance)
	}
	locked.Origin = &state.ArtifactOrigin{Kind: "https", URL: originURL.String(), Provenance: provenance}
	added, err := state.AddBlob(lock, repository.Format, track, distro, locked, packageName, blob.Facts.Version)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	originChanged, err := state.SetBlobOrigin(lock, packageName, blob.Facts.Version, filename, blob.SHA256, *locked.Origin)
	if err != nil {
		return AdoptArtifactResult{}, err
	}
	changed := added || originChanged
	if err := state.ValidateLock(*lock, request.Repository, repository.Format); err != nil {
		return AdoptArtifactResult{}, err
	}
	if err := state.ValidatePublishedBindings(*lock, ledger); err != nil {
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
	session.dirty = true
	// A caller that owns the session decides when to write, so an import pays for
	// one lock write per checkpoint rather than one per artifact.
	if request.session != nil {
		return result, nil
	}
	if err := session.flush(); err != nil {
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
// fetchArtifact writes an artifact to dst, streaming when the fetcher can.
//
// The capability is optional and discovered by type assertion, the way a host's
// collector is, so a fetcher that only returns bytes keeps working — every test
// fake in this repository is one. The fallback still writes to dst, so everything
// downstream reads from the file either way and there is one path to maintain.
func fetchArtifact(ctx context.Context, fetcher source.Fetcher, address string, dst *os.File) (source.Response, error) {
	limit := maximumArtifactBytes()
	if streaming, ok := fetcher.(source.StreamingFetcher); ok {
		return streaming.FetchTo(ctx, address, limit, dst)
	}
	response, err := fetcher.Fetch(ctx, address, limit)
	if err != nil {
		return response, err
	}
	if response.StatusCode != http.StatusOK {
		return response, nil
	}
	if _, err := dst.Write(response.Body); err != nil {
		return source.Response{}, err
	}
	response.Size = int64(len(response.Body))
	response.Body = nil
	return response, nil
}

func adoptIdentity(_ string, request AdoptArtifactRequest) formats.Identity {
	return formats.Identity{Name: request.Name, Version: request.Version}
}
