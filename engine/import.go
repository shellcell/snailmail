package engine

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/formats/apk"
	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/formats/rpm"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

const importSchemaVersion = 1

// maximumPackagesBytes bounds a Debian Packages index, which is far larger than
// the other formats' indexes: Debian main for one architecture is tens of
// megabytes uncompressed. doctor already reads it at this size.
const maximumPackagesBytes = 64 << 20

// ImportRepositoryRequest reads a published repository into a workspace.
type ImportRepositoryRequest struct {
	Root string
	// Repository is the configured repository to import into. Its format decides
	// how the index is read.
	Repository string
	// URL is the published repository to read.
	URL string
	// MinimumProvenance refuses any artifact whose digest was established more
	// weakly than this. Empty accepts whatever the format's index supports, which is
	// the strongest that format offers.
	MinimumProvenance state.DigestProvenance

	// Suite, Component and Architecture select which Debian index to read. Each
	// defaults to what the repository's Release names first, which is what apt
	// would pick given the same URL.
	Suite        string
	Component    string
	Architecture string
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

// importableFile is one artifact an index names, in the terms every format can
// state: where it is, what its digest is said to be, and what it is called.
//
// URLs rather than one URL because a Helm index entry may list several mirrors of
// the same chart; the first that serves is the origin recorded, since that is where
// it can be refetched from.
type importableFile struct {
	Filename string
	URLs     []string
	SHA256   string
	// Provenance is how strongly this format's index states the digest. Set by the
	// enumerator, because it is a property of the index rather than of the fetch.
	Provenance state.DigestProvenance
	// Ambiguous marks an artifact the index names more than once with different
	// entries, which cannot be imported because there is no single answer to what
	// it is.
	Ambiguous bool
}

// importEnumerator reads a published index and returns the artifacts it names.
type importEnumerator func(context.Context, ImportRepositoryRequest) ([]importableFile, string, error)

var importEnumerators = map[string]importEnumerator{
	"pypi": importPyPIFiles,
	"helm": importHelmFiles,
	"deb":  importDebFiles,
	"rpm":  importRPMFiles,
	"apk":  importAPKFiles,
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
	enumerate, known := importEnumerators[format]
	if !known {
		// Named rather than silently ignored. Claiming to import a format whose index
		// is not read yet would be worse than saying which one it is.
		return ImportRepositoryResult{}, fmt.Errorf(
			"import does not read %s repositories yet; repository %q is %s",
			format, request.Repository, format)
	}
	files, indexURL, err := enumerate(ctx, request)
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
		// Ambiguity is reported before the limit, because it is a fact about the
		// repository rather than about how much of it was asked for. A limited
		// import that hid it would report a clean index that is not one.
		if file.Ambiguous {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename,
				Reason:   "the index lists this name and version more than once, so which artifact it is cannot be established",
			})
			continue
		}
		if file.SHA256 == "" && file.Provenance != state.ProvenanceComputed {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename,
				Reason:   "the index publishes no SHA-256, so the artifact cannot be pinned to a stated digest",
			})
			continue
		}
		// The floor, so a workspace that will not accept unauthenticated bytes says so
		// once rather than inspecting each artifact after the fact. Checked before the
		// fetch: an artifact that would be refused is not worth downloading.
		if request.MinimumProvenance != "" && !file.Provenance.AtLeast(request.MinimumProvenance) {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename,
				Reason: fmt.Sprintf("this index establishes its digest as %s, below the required %s",
					file.Provenance, request.MinimumProvenance),
			})
			continue
		}
		if limit > 0 && len(result.Imported) >= limit {
			result.Skipped = append(result.Skipped, ImportSkipped{
				Filename: file.Filename, Reason: "beyond the requested limit",
			})
			continue
		}
		adopted, err := adoptFirstReachable(ctx, root, request, indexURL, file)
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

// adoptFirstReachable adopts an artifact from the first URL that serves it.
//
// A Helm index entry may list several mirrors of one chart. The origin recorded is
// the URL that actually served, because that is where a later check or refetch has
// to go — recording the first listed would record somewhere that may never have
// worked.
func adoptFirstReachable(ctx context.Context, root string, request ImportRepositoryRequest,
	indexURL string, file importableFile) (AdoptArtifactResult, error) {
	var lastErr error
	for _, reference := range file.URLs {
		artifactURL, err := resolveDoctorReference(indexURL, reference)
		if err != nil {
			lastErr = err
			continue
		}
		adopted, err := AdoptArtifact(ctx, AdoptArtifactRequest{
			Root: root, Repository: request.Repository, URL: artifactURL.String(),
			SHA256: file.SHA256, Filename: file.Filename, Track: request.Track,
			Distro: request.Distro, DryRun: request.DryRun, PublicOrigin: true,
			Provenance: file.Provenance, Fetcher: request.Fetcher,
		})
		if err == nil {
			return adopted, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("the index names no URL for this artifact")
	}
	return AdoptArtifactResult{}, lastErr
}

// importPyPIFiles fetches a project page and returns the files it names.
func importPyPIFiles(ctx context.Context, request ImportRepositoryRequest) ([]importableFile, string, error) {
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
	importable := make([]importableFile, 0, len(files))
	for _, file := range files {
		if !file.Supported {
			continue
		}
		importable = append(importable, importableFile{
			Filename: file.Filename, URLs: []string{file.URL}, SHA256: file.SHA256,
			// The index stated the digest and adopt checks the bytes against it,
			// which is the strongest a simple index supports: nothing here signs the
			// page, and no root document names it.
			Provenance: state.ProvenanceIndexStated,
		})
	}
	sort.Slice(importable, func(left, right int) bool { return importable[left].Filename < importable[right].Filename })
	return importable, indexURL.String(), nil
}

// importHelmFiles fetches index.yaml and returns the charts it names.
//
// One index covers every chart, so unlike PyPI there is no per-project page and
// nothing to narrow by: importing a Helm repository imports the repository.
func importHelmFiles(ctx context.Context, request ImportRepositoryRequest) ([]importableFile, string, error) {
	base, err := parseDoctorURL(request.URL)
	if err != nil {
		return nil, "", err
	}
	indexURL, err := doctorIndexURL(base, "helm", DoctorRequest{})
	if err != nil {
		return nil, "", err
	}
	response, err := request.Fetcher.Fetch(ctx, indexURL.String(), maximumIndexBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	charts, err := helm.ParseRepositoryIndex(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	importable := make([]importableFile, 0, len(charts))
	for _, chart := range charts {
		if chart.Ambiguous {
			// Two entries claim this name and version. Neither can be trusted to be
			// the chart, so it is left out and named rather than resolved by picking
			// one — the same rule as an artifact whose bytes disagree with its digest.
			importable = append(importable, importableFile{
				Filename: chart.Name + "-" + chart.Version + ".tgz", Ambiguous: true,
			})
			continue
		}
		// A chart's filename is not stated by the index, and adopt derives identity
		// from it, so it is composed the way Helm names a packaged chart. Composing
		// rather than taking the URL's basename keeps a mirror that serves the same
		// chart under a different name from renaming the package.
		importable = append(importable, importableFile{
			Filename: chart.Name + "-" + chart.Version + ".tgz",
			URLs:     append([]string(nil), chart.URLs...),
			SHA256:   chart.Digest,
			// index.yaml states each chart's digest and nothing signs the index, so
			// this is the same level a simple index reaches.
			Provenance: state.ProvenanceIndexStated,
		})
	}
	sort.Slice(importable, func(left, right int) bool { return importable[left].Filename < importable[right].Filename })
	return importable, indexURL.String(), nil
}

// importDebFiles reads a suite's Packages index and returns the artifacts it names.
//
// The digest of every artifact comes from Packages, and the digest of Packages
// comes from Release — so this fetches Release first, finds the entry for the
// wanted index, and refuses to read a Packages that does not match the size and
// SHA-256 Release states for it. That check is what ProvenanceIndexChain claims,
// and recording the level without performing it would make the lock say something
// untrue.
//
// Release itself is not authenticated here. InRelease and Release.gpg sign it, and
// verifying that is what would raise this to ProvenanceSignedIndex; until then the
// root of trust is the transport, and the lock says so.
func importDebFiles(ctx context.Context, request ImportRepositoryRequest) ([]importableFile, string, error) {
	// The URL given to import is the repository root — what an apt line names —
	// rather than a path inside it, so it is used as given with a trailing
	// separator. debRepositoryBase is doctor's helper for the other case, where the
	// URL points at a Release or a suite and the root has to be derived.
	base, err := parseDoctorURL(request.URL)
	if err != nil {
		return nil, "", err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	suite := request.Suite
	if suite == "" {
		return nil, "", errors.New(
			"import needs the suite to read, because a Debian repository serves several: pass --suite")
	}
	releaseURL, err := resolveDoctorReference(base.String(), "dists/"+suite+"/Release")
	if err != nil {
		return nil, "", err
	}
	releaseResponse, err := request.Fetcher.Fetch(ctx, releaseURL.String(), maximumIndexBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", releaseURL, err)
	}
	release, err := deb.ParseRepositoryRelease(releaseResponse.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", releaseURL, err)
	}
	component := request.Component
	if component == "" && len(release.Components) != 0 {
		component = release.Components[0]
	}
	architecture := request.Architecture
	if architecture == "" {
		for _, candidate := range release.Architectures {
			// "all" is architecture-independent content rather than a machine to
			// install on, so it is not what someone importing means by default.
			if candidate != "all" {
				architecture = candidate
				break
			}
		}
	}
	if component == "" || architecture == "" {
		return nil, "", fmt.Errorf("%s names no component or architecture to read; pass --component and --architecture", releaseURL)
	}
	wanted := component + "/binary-" + architecture + "/Packages"
	listed := findReleaseFile(release, wanted)
	if listed == nil {
		return nil, "", fmt.Errorf("%s does not list %s", releaseURL, wanted)
	}
	packagesURL, err := resolveDoctorReference(releaseURL.String(), listed.Path)
	if err != nil {
		return nil, "", err
	}
	packagesResponse, err := request.Fetcher.Fetch(ctx, packagesURL.String(), maximumPackagesBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", packagesURL, err)
	}
	// The chain, and the reason this import can claim index-chain rather than
	// index-stated: what Release says about Packages has to hold before anything
	// Packages says about an artifact is worth recording.
	if int64(len(packagesResponse.Body)) != listed.Size || digest(packagesResponse.Body) != listed.SHA256 {
		return nil, "", fmt.Errorf("%s does not match the size and SHA-256 that %s states for it",
			packagesURL, releaseURL)
	}
	content, err := deb.DecompressRepositoryPackages(listed.Path, packagesResponse.Body)
	if err != nil {
		return nil, "", fmt.Errorf("decompress %s: %w", packagesURL, err)
	}
	packages, err := deb.ParseRepositoryPackages(content)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", packagesURL, err)
	}
	importable := make([]importableFile, 0, len(packages))
	for _, entry := range packages {
		// Filename is a pool path relative to the repository root rather than to
		// the index, which is why this resolves against base and not packagesURL.
		artifactURL, err := resolveDoctorReference(base.String(), entry.Filename)
		if err != nil {
			continue
		}
		importable = append(importable, importableFile{
			Filename:   path.Base(entry.Filename),
			URLs:       []string{artifactURL.String()},
			SHA256:     entry.SHA256,
			Provenance: state.ProvenanceIndexChain,
		})
	}
	sort.Slice(importable, func(left, right int) bool { return importable[left].Filename < importable[right].Filename })
	return importable, packagesURL.String(), nil
}

// importRPMFiles reads a yum repository: repomd.xml names primary.xml.gz, and
// primary.xml names every package with its digest and location.
//
// The same chain as Debian, so the same provenance. repomd states the digest of
// primary, and checking it is what makes index-chain an accurate claim rather than
// a label. Unlike Debian there is no suite to choose: a yum repository root is one
// repository, which is why this takes no extra flags.
func importRPMFiles(ctx context.Context, request ImportRepositoryRequest) ([]importableFile, string, error) {
	base, err := parseDoctorURL(request.URL)
	if err != nil {
		return nil, "", err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	repomdURL, err := resolveDoctorReference(base.String(), rpm.RepomdPath)
	if err != nil {
		return nil, "", err
	}
	repomdResponse, err := request.Fetcher.Fetch(ctx, repomdURL.String(), rpm.MaximumRepomdBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", repomdURL, err)
	}
	metadata, err := rpm.ParseRepomd(repomdResponse.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", repomdURL, err)
	}
	primary, found := rpm.FindMetadata(metadata, "primary")
	if !found {
		return nil, "", fmt.Errorf("%s declares no primary index, so nothing names the packages", repomdURL)
	}
	if primary.SHA256 == "" {
		// repomd may state sha1 or md5 for its indexes. Following one would mean
		// claiming a chain snailmail did not actually check.
		return nil, "", fmt.Errorf("%s states no SHA-256 for the primary index, so the chain to it cannot be checked", repomdURL)
	}
	primaryURL, err := resolveDoctorReference(base.String(), primary.Location)
	if err != nil {
		return nil, "", err
	}
	primaryResponse, err := request.Fetcher.Fetch(ctx, primaryURL.String(), maximumPackagesBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", primaryURL, err)
	}
	// The chain. What repomd says about primary has to hold before anything primary
	// says about a package is worth recording.
	if primary.Size != 0 && int64(len(primaryResponse.Body)) != primary.Size {
		return nil, "", fmt.Errorf("%s is %d bytes, but %s states %d",
			primaryURL, len(primaryResponse.Body), repomdURL, primary.Size)
	}
	if digest(primaryResponse.Body) != primary.SHA256 {
		return nil, "", fmt.Errorf("%s does not match the SHA-256 that %s states for it", primaryURL, repomdURL)
	}
	content, err := rpm.DecompressPrimary(primary.Location, primaryResponse.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", primaryURL, err)
	}
	packages, err := rpm.ParsePrimary(content)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", primaryURL, err)
	}
	importable := make([]importableFile, 0, len(packages))
	for _, entry := range packages {
		// Locations in primary.xml are relative to the repository root rather than
		// to repodata, which is why this resolves against base and not primaryURL.
		artifactURL, err := resolveDoctorReference(base.String(), entry.Location)
		if err != nil {
			continue
		}
		importable = append(importable, importableFile{
			Filename:   path.Base(entry.Location),
			URLs:       []string{artifactURL.String()},
			SHA256:     entry.SHA256,
			Provenance: state.ProvenanceIndexChain,
			Ambiguous:  entry.Ambiguous,
		})
	}
	sort.Slice(importable, func(left, right int) bool { return importable[left].Filename < importable[right].Filename })
	return importable, primaryURL.String(), nil
}

// importAPKFiles reads an Alpine repository's APKINDEX.tar.gz.
//
// Alone among the formats read here, this one cannot produce a pinned digest. The
// index states C:Q1<base64>, which is the SHA-1 of a package's control section
// rather than of the file — verified against Alpine's own archive, where the two
// disagree for every package because they are digests of different things. So each
// artifact is marked ProvenanceComputed and its SHA-256 is taken from the bytes
// that arrive, which is the honest description of what the pin is worth.
func importAPKFiles(ctx context.Context, request ImportRepositoryRequest) ([]importableFile, string, error) {
	base, err := parseDoctorURL(request.URL)
	if err != nil {
		return nil, "", err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	indexURL, err := resolveDoctorReference(base.String(), "APKINDEX.tar.gz")
	if err != nil {
		return nil, "", err
	}
	response, err := request.Fetcher.Fetch(ctx, indexURL.String(), apk.MaximumIndexBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	packages, err := apk.ParseIndex(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", indexURL, err)
	}
	importable := make([]importableFile, 0, len(packages))
	for _, entry := range packages {
		// APKINDEX does not state a filename; apk derives it from the name and
		// version, which is why both are refused above if they could build a path.
		artifactURL, err := resolveDoctorReference(base.String(), entry.Filename())
		if err != nil {
			continue
		}
		importable = append(importable, importableFile{
			Filename:   entry.Filename(),
			URLs:       []string{artifactURL.String()},
			Provenance: state.ProvenanceComputed,
			Ambiguous:  entry.Ambiguous,
		})
	}
	sort.Slice(importable, func(left, right int) bool { return importable[left].Filename < importable[right].Filename })
	return importable, indexURL.String(), nil
}

// findReleaseFile locates a Packages entry, trying each compression Release may
// list it under. Debian publishes the same index several ways and states a digest
// for each, so any of them is a sound root — the uncompressed form is simply the
// one least likely to be present.
func findReleaseFile(release deb.RepositoryRelease, wanted string) *deb.ReleaseFile {
	for _, suffix := range []string{".xz", ".gz", "", ".zst"} {
		for index := range release.Files {
			if release.Files[index].Path == wanted+suffix {
				return &release.Files[index]
			}
		}
	}
	return nil
}
