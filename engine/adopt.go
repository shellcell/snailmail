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
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

// DefaultMaxArtifactBytes bounds a single fetched artifact, which is held whole in
// memory while it is hashed and inspected.
//
// It is a memory bound rather than a policy about package size, and until adoption
// streams it cannot be otherwise. That distinction matters because real packages
// exceed it: 0ad-data in Debian bookworm is over 128 MiB, so importing that suite
// skips it. A constant would make such a package unadoptable at any setting, which
// is a refusal an operator cannot act on.
const DefaultMaxArtifactBytes = 128 << 20

// MaxArtifactBytesEnvironment raises or lowers the limit for one invocation.
//
// The same escape hatch the lock limit has, for the same reason: someone who has
// read the message and knows their machine can hold a larger artifact should be
// able to proceed. Raising it costs memory proportional to the largest artifact,
// which is the trade being made explicit rather than hidden.
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
	response, err := request.Fetcher.Fetch(ctx, originURL.String(), maximumArtifactBytes())
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
	actualDigest := sha256.Sum256(response.Body)
	// When computing, there is nothing to compare against: the digest recorded is of
	// the bytes that arrived, which is exactly what ProvenanceComputed says and no
	// more. Everywhere else the stated digest is the gate.
	if !computing && hex.EncodeToString(actualDigest[:]) != request.SHA256 {
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
func adoptIdentity(_ string, request AdoptArtifactRequest) formats.Identity {
	return formats.Identity{Name: request.Name, Version: request.Version}
}
