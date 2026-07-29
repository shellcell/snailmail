package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
)

var reproducibleEpoch = time.Unix(0, 0).UTC()

const DefaultDebianVerificationImage = "docker.io/library/debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
const DefaultHelmVerificationImage = "docker.io/alpine/helm@sha256:e7ecbf4a200dea73d64bfb8cb0936829164945f2b4d02a0274093073ee8d264f"

type BuildPyPIRequest struct {
	// Listing describes the repository for its browsable page. Zero when a
	// build is invoked outside a workspace, where no name or endpoint exists.
	Listing formats.Repository
	// Published maps an artifact digest to when it was locked, for the
	// listing: this path rebuilds by scanning files, which cannot say.
	Published   map[string]time.Time
	Input       string
	Output      string
	GeneratedAt time.Time
}

type BuildResult struct {
	Format            string              `json:"format"`
	Output            string              `json:"output"`
	TreeSHA256        string              `json:"tree_sha256"`
	ManifestSHA256    string              `json:"manifest_sha256"`
	ProjectCount      int                 `json:"project_count"`
	PackageCount      int                 `json:"package_count"`
	DistributionCount int                 `json:"distribution_count"`
	Signing           []state.PlanSigning `json:"-"`
}

type BuildDebRequest struct {
	// Listing describes the repository for its browsable page. Zero when a
	// build is invoked outside a workspace, where no name or endpoint exists.
	Listing formats.Repository
	// Published maps an artifact digest to when it was locked, for the
	// listing: this path rebuilds by scanning files, which cannot say.
	Published     map[string]time.Time
	Input         string
	Output        string
	Suite         string
	Component     string
	Architectures []string
	GeneratedAt   time.Time
}

type BuildHelmRequest struct {
	// Listing describes the repository for its browsable page. Zero when a
	// build is invoked outside a workspace, where no name or endpoint exists.
	Listing formats.Repository
	// Published maps an artifact digest to when it was locked, for the
	// listing: this path rebuilds by scanning files, which cannot say.
	Published   map[string]time.Time
	Input       string
	Output      string
	GeneratedAt time.Time
}

type VerifyPyPIRequest struct {
	Repository     string
	Python         string
	StructuralOnly bool
}

type VerifyDebRequest struct {
	// VerifyAllVersions installs every retained version rather than the
	// newest and oldest of each package on each architecture. The sample is
	// the default because the cost of the alternative grows with history.
	VerifyAllVersions bool
	Repository        string
	Runner            string
	Image             string
	MaxWorkspaceBytes int64
	StructuralOnly    bool
}

type VerifyHelmRequest struct {
	Repository     string
	Runner         string
	Image          string
	StructuralOnly bool
}

type VerifyResult struct {
	Format         string `json:"format"`
	TreeSHA256     string `json:"tree_sha256"`
	FileCount      int    `json:"file_count"`
	InstalledCases int    `json:"installed_cases"`
	// Manifest is the verified file list, returned so a caller that has just
	// verified a tree does not have to re-verify it to enumerate its contents.
	Manifest buildgraph.RepositoryManifest `json:"-"`
}

type RepositoryInfo struct {
	Format     string `json:"format"`
	TreeSHA256 string `json:"tree_sha256"`
	FileCount  int    `json:"file_count"`
}

// BuildPyPI builds and atomically materializes a deterministic PEP 503 tree.
func BuildPyPI(ctx context.Context, request BuildPyPIRequest) (BuildResult, error) {
	if request.Input == "" || request.Output == "" {
		return BuildResult{}, fmt.Errorf("input and output directories are required")
	}
	input, err := filepath.Abs(request.Input)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve input directory: %w", err)
	}
	output, err := filepath.Abs(request.Output)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if pathsOverlap(input, output) {
		return BuildResult{}, fmt.Errorf("input and output directories must not contain each other")
	}
	snapshot, err := app.ScanPyPI(ctx, input)
	if err != nil {
		return BuildResult{}, err
	}
	defer snapshot.Close()
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = reproducibleEpoch
	}
	artifact, err := buildThroughFormat("pypi", snapshot.Blobs, request.Listing, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, snapshot.Sources); err != nil {
		return BuildResult{}, err
	}
	manifestSHA256, err := state.HashFile(filepath.Join(output, buildgraph.ManifestFilename))
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
		ManifestSHA256:    manifestSHA256,
		ProjectCount:      uniqueProjects(manifest),
		DistributionCount: len(snapshot.Blobs),
	}, nil
}

func BuildDeb(ctx context.Context, request BuildDebRequest) (BuildResult, error) {
	return buildDeb(ctx, request, nil)
}

func buildDeb(ctx context.Context, request BuildDebRequest, transform func(domain.RepositoryArtifact) (domain.RepositoryArtifact, error)) (BuildResult, error) {
	if request.Input == "" || request.Output == "" {
		return BuildResult{}, fmt.Errorf("input and output directories are required")
	}
	input, err := filepath.Abs(request.Input)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve input directory: %w", err)
	}
	output, err := filepath.Abs(request.Output)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if pathsOverlap(input, output) {
		return BuildResult{}, fmt.Errorf("input and output directories must not contain each other")
	}
	snapshot, err := app.ScanDeb(ctx, input)
	if err != nil {
		return BuildResult{}, err
	}
	defer snapshot.Close()
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = reproducibleEpoch
	}
	artifact, err := buildThroughFormat("deb", snapshot.Blobs, debListing(request), generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if transform != nil {
		artifact, err = transform(artifact)
		if err != nil {
			return BuildResult{}, err
		}
	}
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, snapshot.Sources); err != nil {
		return BuildResult{}, err
	}
	manifestSHA256, err := state.HashFile(filepath.Join(output, buildgraph.ManifestFilename))
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
		ManifestSHA256:    manifestSHA256,
		PackageCount:      uniquePackages(manifest),
		DistributionCount: len(snapshot.Blobs),
	}, nil
}

// transform is where signing happens, for the same reason the Debian path takes
// one: the signatures have to be part of the tree before it is finalized, or
// the manifest would describe a repository different from the one published.
func BuildHelm(ctx context.Context, request BuildHelmRequest) (BuildResult, error) {
	return buildHelm(ctx, request, nil)
}

func buildHelm(ctx context.Context, request BuildHelmRequest, transform func(domain.RepositoryArtifact) (domain.RepositoryArtifact, error)) (BuildResult, error) {
	if request.Input == "" || request.Output == "" {
		return BuildResult{}, fmt.Errorf("input and output directories are required")
	}
	input, err := filepath.Abs(request.Input)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve input directory: %w", err)
	}
	output, err := filepath.Abs(request.Output)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if pathsOverlap(input, output) {
		return BuildResult{}, fmt.Errorf("input and output directories must not contain each other")
	}
	snapshot, err := app.ScanHelm(ctx, input)
	if err != nil {
		return BuildResult{}, err
	}
	defer snapshot.Close()
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = reproducibleEpoch
	}
	artifact, err := buildThroughFormat("helm", snapshot.Blobs, request.Listing, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if transform != nil {
		artifact, err = transform(artifact)
		if err != nil {
			return BuildResult{}, err
		}
	}
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, snapshot.Sources); err != nil {
		return BuildResult{}, err
	}
	manifestSHA256, err := state.HashFile(filepath.Join(output, buildgraph.ManifestFilename))
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
		ManifestSHA256:    manifestSHA256,
		PackageCount:      uniqueProjects(manifest),
		DistributionCount: len(snapshot.Blobs),
	}, nil
}

func VerifyPyPI(ctx context.Context, request VerifyPyPIRequest) (VerifyResult, error) {
	var manifest buildgraph.RepositoryManifest
	var err error
	installed := 0
	if request.StructuralOnly {
		manifest, err = app.VerifyRepository(request.Repository)
	} else {
		manifest, installed, err = app.VerifyPyPIClient(ctx, request.Repository, request.Python)
		if err != nil {
			return VerifyResult{}, err
		}
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "pypi"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
		Manifest:       manifest,
	}, nil
}

func VerifyDeb(ctx context.Context, request VerifyDebRequest) (VerifyResult, error) {
	var manifest buildgraph.RepositoryManifest
	var err error
	installed := 0
	if request.StructuralOnly {
		manifest, err = app.VerifyRepository(request.Repository)
	} else {
		image := request.Image
		if image == "" {
			image = DefaultDebianVerificationImage
		}
		maximum := request.MaxWorkspaceBytes
		if maximum == 0 {
			maximum = 4 << 30
		}
		manifest, installed, err = app.VerifyDebClient(ctx, request.Repository, request.Runner, image, maximum, versionScope(request.VerifyAllVersions))
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "deb"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
		Manifest:       manifest,
	}, nil
}

func VerifyHelm(ctx context.Context, request VerifyHelmRequest) (VerifyResult, error) {
	var manifest buildgraph.RepositoryManifest
	var err error
	verified := 0
	if request.StructuralOnly {
		manifest, err = app.VerifyRepository(request.Repository)
	} else {
		image := request.Image
		if image == "" {
			image = DefaultHelmVerificationImage
		}
		manifest, verified, err = app.VerifyHelmClient(ctx, request.Repository, request.Runner, image)
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "helm"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: verified,
		Manifest:       manifest,
	}, nil
}

func InspectRepository(repository string) (RepositoryInfo, error) {
	manifest, err := app.VerifyRepository(repository)
	if err != nil {
		return RepositoryInfo{}, err
	}
	return RepositoryInfo{Format: manifest.Format, TreeSHA256: manifest.TreeSHA256, FileCount: len(manifest.Files)}, nil
}

func pathsOverlap(left, right string) bool {
	return contains(left, right) || contains(right, left)
}

func contains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func uniqueProjects(manifest buildgraph.RepositoryManifest) int {
	projects := make(map[string]bool)
	for _, verification := range manifest.VerificationCases {
		projects[verification.Project] = true
	}
	return len(projects)
}

func uniquePackages(manifest buildgraph.RepositoryManifest) int {
	packages := make(map[string]bool)
	for _, verification := range manifest.VerificationCases {
		packages[verification.Package] = true
	}
	return len(packages)
}

type VerifyRawRequest struct {
	Repository string
}

// VerifyRaw checks a raw repository's listing, checksums and artifact bytes.
// There is no ecosystem client to invoke, so structural verification is the
// whole check and there is no separate client mode.
func VerifyRaw(request VerifyRawRequest) (VerifyResult, error) {
	manifest, err := app.VerifyRepository(request.Repository)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "raw"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format: manifest.Format, TreeSHA256: manifest.TreeSHA256,
		FileCount: len(manifest.Files), InstalledCases: len(manifest.VerificationCases),
		Manifest: manifest,
	}, nil
}

// DefaultRPMVerificationImage is the client that proves a yum repository is
// installable. Fedora rather than a minimal base because dnf, and the rpm
// database it needs, are already there.
const DefaultRPMVerificationImage = "docker.io/library/fedora@sha256:f1a3fab47bcb3c3ddf3135d5ee7ba8b7b25f2e809a47440936212a3a50957f3d"

type VerifyRPMRequest struct {
	// VerifyAllVersions installs every retained version rather than the
	// newest and oldest of each package on each architecture. The sample is
	// the default because the cost of the alternative grows with history.
	VerifyAllVersions bool
	Repository        string
	Runner            string
	Image             string
	StructuralOnly    bool
}

// VerifyRPM checks a yum repository's indexes, and unless asked for structure
// alone, has a real dnf install from it.
func VerifyRPM(ctx context.Context, request VerifyRPMRequest) (VerifyResult, error) {
	var manifest buildgraph.RepositoryManifest
	var err error
	installed := 0
	if request.StructuralOnly {
		manifest, err = app.VerifyRepository(request.Repository)
	} else {
		image := request.Image
		if image == "" {
			image = DefaultRPMVerificationImage
		}
		manifest, installed, err = app.VerifyRPMClient(ctx, request.Repository, request.Runner, image, versionScope(request.VerifyAllVersions))
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "rpm"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
		Manifest:       manifest,
	}, nil
}

// DefaultAPKVerificationImage is the client that proves an Alpine repository is
// installable.
const DefaultAPKVerificationImage = "docker.io/library/alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"

type VerifyAPKRequest struct {
	// VerifyAllVersions installs every retained version rather than the
	// newest and oldest of each package on each architecture. The sample is
	// the default because the cost of the alternative grows with history.
	VerifyAllVersions bool
	Repository        string
	Runner            string
	Image             string
	StructuralOnly    bool
}

// VerifyAPK checks an Alpine repository's index, and unless asked for structure
// alone, has a real apk install from it.
func VerifyAPK(ctx context.Context, request VerifyAPKRequest) (VerifyResult, error) {
	var manifest buildgraph.RepositoryManifest
	var err error
	installed := 0
	if request.StructuralOnly {
		manifest, err = app.VerifyRepository(request.Repository)
	} else {
		image := request.Image
		if image == "" {
			image = DefaultAPKVerificationImage
		}
		manifest, installed, err = app.VerifyAPKClient(ctx, request.Repository, request.Runner, image, versionScope(request.VerifyAllVersions))
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if err := requireFormatID(manifest.Format, "apk"); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
		Manifest:       manifest,
	}, nil
}

// versionScope turns the flag an operator sets into the policy the verifiers
// take. Sampling is the default; asking for everything is the deliberate act.
func versionScope(all bool) app.VersionScope {
	if all {
		return app.AllVersions
	}
	return app.SampledVersions
}

// buildThroughFormat renders a repository the way every other path does: the
// format's own Build, which lays out the index and the browsable page together.
//
// These three builders scan a directory rather than read a lock, because that
// is what `snailmail build` is given. What they produce is otherwise the same,
// and going through the same door is what keeps it so.
func buildThroughFormat(name string, blobs []domain.Blob, listing formats.Repository, generatedAt time.Time) (domain.RepositoryArtifact, error) {
	selected, err := formats.For(name)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return selected.Build(blobs, formats.BuildOptions{Repository: listing, GeneratedAt: generatedAt})
}

// debListing carries the suite a Debian repository is built for, which its
// index needs and the other two formats have no equivalent of.
func debListing(request BuildDebRequest) formats.Repository {
	listing := request.Listing
	listing.Suite, listing.Component, listing.Architectures = request.Suite, request.Component, request.Architectures
	return listing
}

// requireFormatID checks that a directory holds the format it was asked about.
//
// The identity comes from the registry rather than from the format's own
// package, so the engine needs to know only the name the operator typed.
func requireFormatID(published, name string) error {
	selected, err := formats.For(name)
	if err != nil {
		return err
	}
	if published != selected.ID() {
		return fmt.Errorf("repository format is %q, not %q", published, selected.ID())
	}
	return nil
}
