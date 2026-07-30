package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

const importSchemaVersion = 1

// ImportRepositoryRequest reads a published repository into a workspace.
type ImportRepositoryRequest struct {
	Root string
	// Repository is the configured repository to import into. Its format decides
	// how the index is read.
	Repository string
	// URL is the published repository to read.
	URL string
	// Project narrows a PyPI import to one project. A simple index lists projects
	// and not their files, so importing every project means a request per project;
	// this imports one at a time, which is also how someone adopting a repository
	// piecemeal wants it.
	Project string
	// Track and Distro place what is imported, exactly as adopt does.
	Track  string
	Distro string
	// PublicOrigin confirms the recorded origin URLs carry no secrets. Required,
	// because an import records one origin per artifact and a URL with a token in
	// it would be committed to a reviewed lock.
	PublicOrigin bool
	// DryRun reports what would be imported without recording anything.
	DryRun  bool
	Limit   int
	Fetcher source.Fetcher
}

type ImportRepositoryResult struct {
	SchemaVersion int    `json:"schema_version"`
	Repository    string `json:"repository"`
	IndexURL      string `json:"index_url"`
	// Listed is how many artifacts the index named, before anything was filtered.
	Listed   int              `json:"listed"`
	Imported []ImportArtifact `json:"imported"`
	Skipped  []ImportSkipped  `json:"skipped"`
	DryRun   bool             `json:"dry_run,omitempty"`
}

type ImportArtifact struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Origin   string `json:"origin_url"`
}

// ImportSkipped is one artifact the index named that was not imported, with the
// reason. Reported rather than silently dropped: an import that took nine of ten
// artifacts and said nothing would be discovered later, by a client.
type ImportSkipped struct {
	Filename string `json:"filename"`
	Reason   string `json:"reason"`
}

// ImportRepository reads a published repository and records its artifacts.
//
// Every prospective user already has a repository somewhere, and without this the
// only way in is to re-adopt every artifact by hand. This enumerates a published
// index and adopts what it names.
//
// Adoption itself is not reimplemented — each artifact goes through AdoptArtifact,
// which fetches it, checks the bytes against the digest the index published,
// records the origin, and writes the lock. So an import inherits adopt's
// guarantees rather than a parallel set that could differ, and an interrupted
// import leaves a consistent lock holding what it managed.
//
// Only artifacts whose index publishes a SHA-256 are imported. The rest are
// reported as skipped. That line is deliberate: snailmail's guarantee is that a
// locked artifact is pinned to a digest someone stated in advance, and computing
// one from bytes an unauthenticated index handed over would record a pin that
// proves only that the download was self-consistent.
func ImportRepository(ctx context.Context, request ImportRepositoryRequest) (ImportRepositoryResult, error) {
	if request.Fetcher == nil {
		return ImportRepositoryResult{}, errors.New("import fetcher is required")
	}
	if !request.PublicOrigin {
		return ImportRepositoryResult{}, errors.New(
			"import records one origin URL per artifact into a reviewed lock, so it requires confirmation that they are public and contain no secrets")
	}
	if request.Repository == "" {
		return ImportRepositoryResult{}, errors.New("import requires the repository to import into")
	}
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return ImportRepositoryResult{}, err
	}
	format, err := importFormat(root, request.Repository)
	if err != nil {
		return ImportRepositoryResult{}, err
	}
	if format != "pypi" {
		// Named rather than silently ignored. deb and Helm indexes are already
		// parsed by doctor, so extending this is reading work rather than design
		// work — but claiming to import a format that is not read yet would be worse
		// than saying so.
		return ImportRepositoryResult{}, fmt.Errorf(
			"import reads PyPI repositories; repository %q is %s", request.Repository, format)
	}
	files, indexURL, err := importPyPIFiles(ctx, request)
	if err != nil {
		return ImportRepositoryResult{}, err
	}
	result := ImportRepositoryResult{
		SchemaVersion: importSchemaVersion, Repository: request.Repository,
		IndexURL: indexURL, Listed: len(files), DryRun: request.DryRun,
		Imported: []ImportArtifact{}, Skipped: []ImportSkipped{},
	}
	limit := request.Limit
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return ImportRepositoryResult{}, err
		}
		if limit > 0 && len(result.Imported) >= limit {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename, Reason: "beyond the requested limit",
			})
			continue
		}
		if file.SHA256 == "" {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename,
				Reason:   "the index publishes no SHA-256, so the artifact cannot be pinned to a stated digest",
			})
			continue
		}
		artifactURL, err := resolveDoctorReference(indexURL, file.URL)
		if err != nil {
			result.Skipped = append(result.Skipped, ImportSkipped{Filename: file.Filename, Reason: err.Error()})
			continue
		}
		adopted, err := AdoptArtifact(ctx, AdoptArtifactRequest{
			Root: root, Repository: request.Repository, URL: artifactURL.String(),
			SHA256: file.SHA256, Filename: file.Filename, Track: request.Track,
			Distro: request.Distro, DryRun: request.DryRun, PublicOrigin: true,
			// The index stated this digest and adopt checks the bytes against it,
			// which is the strongest a simple index supports: there is nothing here
			// to verify a signature against, and no root document naming the page.
			Provenance: state.ProvenanceIndexStated,
			Fetcher:    request.Fetcher,
		})
		if err != nil {
			// One artifact failing does not abandon the rest. A repository being
			// imported is someone else's, and a single unreachable file or one whose
			// bytes disagree with its published digest is a fact about that
			// repository worth reporting alongside everything that did work.
			result.Skipped = append(result.Skipped, ImportSkipped{Filename: file.Filename, Reason: err.Error()})
			continue
		}
		result.Imported = append(result.Imported, ImportArtifact{
			Package: adopted.Package, Version: adopted.Version, Filename: adopted.Filename,
			SHA256: adopted.SHA256, Origin: adopted.OriginURL,
		})
	}
	return result, nil
}

// importFormat reads the configured repository's format, so an import is told what
// it is reading rather than guessing from a URL.
func importFormat(root, repository string) (string, error) {
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return "", err
	}
	configured, exists := manifest.Repositories[repository]
	if !exists {
		return "", fmt.Errorf("repository %q is not configured; run setup first", repository)
	}
	return configured.Format, nil
}

// importPyPIFiles fetches a project page and returns the files it names.
func importPyPIFiles(ctx context.Context, request ImportRepositoryRequest) ([]pypi.SimpleFile, string, error) {
	if request.Project == "" {
		return nil, "", errors.New(
			"import needs the project to read, because a simple index lists projects rather than their files: pass --project")
	}
	base, err := parseDoctorURL(request.URL)
	if err != nil {
		return nil, "", err
	}
	indexURL, err := doctorIndexURL(base, "pypi", DoctorRequest{Project: request.Project})
	if err != nil {
		return nil, "", err
	}
	response, err := request.Fetcher.Fetch(ctx, indexURL.String(), maximumIndexBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	pageName, files, err := pypi.ParseSimpleProject(response.ContentType, response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	// A page naming a different project is a server serving one project's content
	// at another's URL, and following it would import someone else's artifacts
	// under the name that was asked for.
	//
	// Only a PEP 691 JSON page carries its name; the legacy HTML page does not, so
	// ParseSimpleProject returns an empty name and this cannot be checked there.
	// That is a limit of the older format rather than of the check, and it is worth
	// saying plainly instead of leaving a guard that looks stronger than it is.
	if pageName != "" && pypi.NormalizeName(pageName) != pypi.NormalizeName(request.Project) {
		return nil, "", fmt.Errorf("%s names project %q rather than %q", indexURL, pageName, request.Project)
	}
	supported := make([]pypi.SimpleFile, 0, len(files))
	for _, file := range files {
		if file.Supported {
			supported = append(supported, file)
		}
	}
	// Ordered by filename so an import is reproducible and a dry run reports what
	// the real thing will do.
	sort.Slice(supported, func(left, right int) bool { return supported[left].Filename < supported[right].Filename })
	return supported, indexURL.String(), nil
}
