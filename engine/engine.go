package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
)

var reproducibleEpoch = time.Unix(0, 0).UTC()

const DefaultDebianVerificationImage = "docker.io/library/debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
const DefaultHelmVerificationImage = "docker.io/alpine/helm@sha256:e7ecbf4a200dea73d64bfb8cb0936829164945f2b4d02a0274093073ee8d264f"

type BuildPyPIRequest struct {
	Input       string
	Output      string
	GeneratedAt time.Time
}

type BuildResult struct {
	Format            string
	Output            string
	TreeSHA256        string
	ProjectCount      int
	PackageCount      int
	DistributionCount int
}

type BuildDebRequest struct {
	Input         string
	Output        string
	Suite         string
	Component     string
	Architectures []string
	GeneratedAt   time.Time
}

type BuildHelmRequest struct {
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
	Format         string
	TreeSHA256     string
	FileCount      int
	InstalledCases int
}

type RepositoryInfo struct {
	Format     string
	TreeSHA256 string
	FileCount  int
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
	artifact, err := pypi.Build(snapshot.Blobs)
	if err != nil {
		return BuildResult{}, err
	}
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = reproducibleEpoch
	}
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, snapshot.Sources); err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
		ProjectCount:      uniqueProjects(manifest),
		DistributionCount: len(snapshot.Blobs),
	}, nil
}

func BuildDeb(ctx context.Context, request BuildDebRequest) (BuildResult, error) {
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
	artifact, err := deb.Build(snapshot.Blobs, deb.BuildOptions{
		Suite:         request.Suite,
		Component:     request.Component,
		Architectures: request.Architectures,
		GeneratedAt:   generatedAt,
	})
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
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
		PackageCount:      uniquePackages(manifest),
		DistributionCount: len(snapshot.Blobs),
	}, nil
}

func BuildHelm(ctx context.Context, request BuildHelmRequest) (BuildResult, error) {
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
	artifact, err := helm.Build(snapshot.Blobs, helm.BuildOptions{GeneratedAt: generatedAt})
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
	return BuildResult{
		Format:            manifest.Format,
		Output:            output,
		TreeSHA256:        manifest.TreeSHA256,
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
	if manifest.Format != pypi.FormatID {
		return VerifyResult{}, fmt.Errorf("repository format is %q, not %q", manifest.Format, pypi.FormatID)
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
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
		manifest, installed, err = app.VerifyDebClient(ctx, request.Repository, request.Runner, image, maximum)
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if manifest.Format != deb.FormatID {
		return VerifyResult{}, fmt.Errorf("repository format is %q, not %q", manifest.Format, deb.FormatID)
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: installed,
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
	if manifest.Format != helm.FormatID {
		return VerifyResult{}, fmt.Errorf("repository format is %q, not %q", manifest.Format, helm.FormatID)
	}
	return VerifyResult{
		Format:         manifest.Format,
		TreeSHA256:     manifest.TreeSHA256,
		FileCount:      len(manifest.Files),
		InstalledCases: verified,
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
