package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/state"
)

const phase1EngineVersion = "phase1-v1"

type InitWorkspaceRequest struct {
	Root string
	Name string
}

type SetupRepositoryRequest struct {
	Root          string
	Name          string
	Format        string
	Output        string
	Suite         string
	Component     string
	Architectures []string
}

type AddArtifactsRequest struct {
	Root       string
	Repository string
	Artifacts  []string
	Track      string
}

type AddArtifactsResult struct {
	Repository string
	Added      int
	Skipped    int
	Packages   []string
}

type PlanWorkspaceRequest struct {
	Root        string
	Output      string
	GeneratedAt time.Time
	CreatedAt   time.Time
	ExpiresIn   time.Duration
}

type PlanWorkspaceResult struct {
	PlanID  string
	Output  string
	Changes int
}

type ApplyWorkspaceRequest struct {
	Root              string
	Plan              string
	Now               time.Time
	StructuralOnly    bool
	Python            string
	Runner            string
	DebianImage       string
	HelmImage         string
	MaxWorkspaceBytes int64
}

type ApplyWorkspaceResult struct {
	PlanID  string
	Applied int
	Current int
}

func InitWorkspace(request InitWorkspaceRequest) error {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return err
	}
	return state.Init(root, state.InitOptions{Name: request.Name})
}

func SetupRepository(request SetupRepositoryRequest) error {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return err
	}
	return state.Setup(root, state.SetupOptions{
		Name: request.Name, Format: request.Format, Output: request.Output,
		Suite: request.Suite, Component: request.Component, Architectures: request.Architectures,
	})
}

func AddArtifacts(request AddArtifactsRequest) (AddArtifactsResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	if len(request.Artifacts) == 0 {
		return AddArtifactsResult{}, errors.New("at least one artifact is required")
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return AddArtifactsResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	lock, err := state.LoadLock(root, repository)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	ledger, err := state.LoadLedger(root, request.Repository)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return AddArtifactsResult{}, err
	}
	result := AddArtifactsResult{Repository: request.Repository}
	packages := make(map[string]bool)
	for _, artifact := range request.Artifacts {
		blob, err := state.PutArtifact(root, repository.Format, artifact)
		if err != nil {
			return AddArtifactsResult{}, err
		}
		distro := ""
		if repository.Format == "deb" {
			distro = repository.Suite
		}
		added, err := state.AddBlob(&lock, repository.Format, request.Track, distro, state.ToLockedBlob(blob), blob.Facts.Name, blob.Facts.Version)
		if err != nil {
			return AddArtifactsResult{}, err
		}
		if added {
			result.Added++
		} else {
			result.Skipped++
		}
		packages[blob.Facts.Name+"@"+blob.Facts.Version] = true
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return AddArtifactsResult{}, err
	}
	if result.Added != 0 {
		if err := state.WriteLock(root, repository, lock); err != nil {
			return AddArtifactsResult{}, err
		}
	}
	for packageVersion := range packages {
		result.Packages = append(result.Packages, packageVersion)
	}
	sort.Strings(result.Packages)
	return result, nil
}

func PlanWorkspace(ctx context.Context, request PlanWorkspaceRequest) (PlanWorkspaceResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	manifestDigest, err := state.HashFile(filepath.Join(root, state.ManifestFilename))
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	createdAt := request.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = createdAt
	}
	expiresIn := request.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 2 * time.Hour
	}
	if expiresIn <= 0 {
		return PlanWorkspaceResult{}, errors.New("plan expiry must be positive")
	}
	payload := state.PlanPayload{
		EngineVersion: phase1EngineVersion, GitRevision: state.GitRevision(root), ManifestSHA256: manifestDigest,
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339), CreatedAt: createdAt.UTC().Format(time.RFC3339),
		ExpiresAt: createdAt.Add(expiresIn).UTC().Format(time.RFC3339),
	}
	changes := 0
	for _, name := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[name]
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		ledger, err := state.LoadLedger(root, name)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return PlanWorkspaceResult{}, err
		}
		lockDigest, err := state.HashFile(filepath.Join(root, filepath.FromSlash(repository.Lock)))
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		desired, err := buildLockedRepository(ctx, root, name, repository, lock, generatedAt, "")
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		observed, err := observedTree(root, repository.Output)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		action := "noop"
		if observed != desired.TreeSHA256 {
			action = "update"
			if observed == "" {
				action = "create"
			}
			changes++
		}
		payload.Repositories = append(payload.Repositories, state.PlanRepository{
			Name: name, Format: repository.Format, LockSHA256: lockDigest, Output: repository.Output,
			ObservedTreeSHA256: observed, DesiredTreeSHA256: desired.TreeSHA256,
			ChangeID: name + ":" + desired.TreeSHA256[:12], Action: action,
		})
	}
	plan, err := state.FinalizePlan(payload)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	output := request.Output
	if output == "" {
		output = filepath.Join(root, "snailmail-plan.json")
	} else if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := state.WritePlan(output, plan); err != nil {
		return PlanWorkspaceResult{}, err
	}
	return PlanWorkspaceResult{PlanID: plan.PlanID, Output: output, Changes: changes}, nil
}

func ApplyWorkspace(ctx context.Context, request ApplyWorkspaceRequest) (ApplyWorkspaceResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	planName := request.Plan
	if !filepath.IsAbs(planName) {
		planName = filepath.Join(root, planName)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	if plan.Payload.EngineVersion != phase1EngineVersion {
		return ApplyWorkspaceResult{}, errors.New("plan engine version is incompatible")
	}
	now := request.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt, err := time.Parse(time.RFC3339, plan.Payload.ExpiresAt)
	if err != nil || !now.Before(expiresAt) {
		return ApplyWorkspaceResult{}, errors.New("plan has expired")
	}
	if state.GitRevision(root) != plan.Payload.GitRevision {
		return ApplyWorkspaceResult{}, errors.New("stale plan: Git revision changed")
	}
	manifestDigest, err := state.HashFile(filepath.Join(root, state.ManifestFilename))
	if err != nil || manifestDigest != plan.Payload.ManifestSHA256 {
		return ApplyWorkspaceResult{}, errors.New("stale plan: manifest changed")
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	generatedAt, err := time.Parse(time.RFC3339, plan.Payload.GeneratedAt)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	result := ApplyWorkspaceResult{PlanID: plan.PlanID}
	for _, planned := range plan.Payload.Repositories {
		repository, exists := manifest.Repositories[planned.Name]
		if !exists || repository.Format != planned.Format || repository.Output != planned.Output {
			return result, fmt.Errorf("stale plan: repository %q configuration changed", planned.Name)
		}
		lockDigest, err := state.HashFile(filepath.Join(root, filepath.FromSlash(repository.Lock)))
		if err != nil || lockDigest != planned.LockSHA256 {
			return result, fmt.Errorf("stale plan: repository %q lock changed", planned.Name)
		}
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return result, err
		}
		ledger, err := state.LoadLedger(root, planned.Name)
		if err != nil {
			return result, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return result, err
		}
		observed, err := observedTree(root, repository.Output)
		if err != nil {
			return result, err
		}
		if observed != planned.ObservedTreeSHA256 && observed != planned.DesiredTreeSHA256 {
			return result, fmt.Errorf("stale plan: repository %q target changed", planned.Name)
		}
		if observed == planned.DesiredTreeSHA256 {
			if err := state.AppendPublicationRecords(root, planned.Name, plan.PlanID, planned.ChangeID, planned.DesiredTreeSHA256, now.UTC().Format(time.RFC3339), lock); err != nil {
				return result, err
			}
			result.Current++
			continue
		}
		stage, err := os.MkdirTemp("", ".snailmail-apply-*")
		if err != nil {
			return result, err
		}
		stageOutput := filepath.Join(stage, "repository")
		staged, buildErr := buildLockedRepository(ctx, root, planned.Name, repository, lock, generatedAt, stageOutput)
		if buildErr == nil && staged.TreeSHA256 != planned.DesiredTreeSHA256 {
			buildErr = errors.New("stale plan: rebuilt tree digest changed")
		}
		if buildErr == nil {
			buildErr = verifyStaged(ctx, repository.Format, stageOutput, request)
		}
		if buildErr != nil {
			_ = os.RemoveAll(stage)
			return result, buildErr
		}
		if err := state.AppendPublicationRecords(root, planned.Name, plan.PlanID, planned.ChangeID, planned.DesiredTreeSHA256, now.UTC().Format(time.RFC3339), lock); err != nil {
			_ = os.RemoveAll(stage)
			return result, err
		}
		finalOutput := filepath.Join(root, filepath.FromSlash(repository.Output))
		published, err := buildLockedRepository(ctx, root, planned.Name, repository, lock, generatedAt, finalOutput)
		_ = os.RemoveAll(stage)
		if err != nil {
			return result, err
		}
		if published.TreeSHA256 != planned.DesiredTreeSHA256 {
			return result, errors.New("published tree differs from verified plan")
		}
		result.Applied++
	}
	return result, nil
}

func buildLockedRepository(ctx context.Context, root, name string, repository state.Repository, lock state.RepositoryLock, generatedAt time.Time, output string) (BuildResult, error) {
	input, err := os.MkdirTemp("", ".snailmail-locked-input-*")
	if err != nil {
		return BuildResult{}, err
	}
	defer os.RemoveAll(input)
	active := activePackageVersions(lock)
	for _, packageVersion := range active {
		for _, locked := range packageVersion.Blobs {
			blob, source, err := state.LoadBlob(root, repository.Format, locked)
			if err != nil {
				return BuildResult{}, err
			}
			if blob.Facts.Name != packageVersion.Package || blob.Facts.Version != packageVersion.Version {
				return BuildResult{}, fmt.Errorf("blob %s disagrees with package version %s@%s", locked.SHA256, packageVersion.Package, packageVersion.Version)
			}
			directory := filepath.Join(input, locked.SHA256)
			if err := os.MkdirAll(directory, 0o755); err != nil {
				return BuildResult{}, err
			}
			target := filepath.Join(directory, locked.Filename)
			if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
				if err := linkOrCopy(source, target); err != nil {
					return BuildResult{}, err
				}
			}
		}
	}
	if len(active) == 0 {
		return BuildResult{}, fmt.Errorf("repository %q has no active placements", name)
	}
	cleanupOutput := false
	if output == "" {
		temporary, err := os.MkdirTemp("", ".snailmail-plan-build-*")
		if err != nil {
			return BuildResult{}, err
		}
		defer os.RemoveAll(temporary)
		output = filepath.Join(temporary, "repository")
		cleanupOutput = true
	}
	_ = cleanupOutput
	switch repository.Format {
	case "pypi":
		return BuildPyPI(ctx, BuildPyPIRequest{Input: input, Output: output, GeneratedAt: generatedAt})
	case "deb":
		return BuildDeb(ctx, BuildDebRequest{Input: input, Output: output, Suite: repository.Suite, Component: repository.Component, Architectures: repository.Architectures, GeneratedAt: generatedAt})
	case "helm":
		return BuildHelm(ctx, BuildHelmRequest{Input: input, Output: output, GeneratedAt: generatedAt})
	default:
		return BuildResult{}, fmt.Errorf("unsupported repository format %q", repository.Format)
	}
}

func activePackageVersions(lock state.RepositoryLock) []state.PackageVersion {
	active := make(map[string]bool)
	for _, placement := range lock.Placement {
		active[placement.Package+"\x00"+placement.Version] = true
	}
	var result []state.PackageVersion
	for _, packageVersion := range lock.PackageVersion {
		if active[packageVersion.Package+"\x00"+packageVersion.Version] {
			result = append(result, packageVersion)
		}
	}
	return result
}

func observedTree(root, output string) (string, error) {
	name := filepath.Join(root, filepath.FromSlash(output))
	if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	info, err := InspectRepository(name)
	if err != nil {
		return "", fmt.Errorf("inspect target %q: %w", output, err)
	}
	return info.TreeSHA256, nil
}

func verifyStaged(ctx context.Context, format, repository string, request ApplyWorkspaceRequest) error {
	switch format {
	case "pypi":
		_, err := VerifyPyPI(ctx, VerifyPyPIRequest{Repository: repository, Python: request.Python, StructuralOnly: request.StructuralOnly})
		return err
	case "deb":
		_, err := VerifyDeb(ctx, VerifyDebRequest{Repository: repository, Runner: request.Runner, Image: request.DebianImage, MaxWorkspaceBytes: request.MaxWorkspaceBytes, StructuralOnly: request.StructuralOnly})
		return err
	case "helm":
		_, err := VerifyHelm(ctx, VerifyHelmRequest{Repository: repository, Runner: request.Runner, Image: request.HelmImage, StructuralOnly: request.StructuralOnly})
		return err
	default:
		return fmt.Errorf("unsupported repository format %q", format)
	}
}

func linkOrCopy(source, target string) error {
	if err := os.Link(source, target); err == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		_ = input.Close()
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeOutputErr := output.Close()
	closeInputErr := input.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeOutputErr != nil {
		return closeOutputErr
	}
	return closeInputErr
}

func workspaceRoot(root string) (string, error) {
	if root == "" {
		root = "."
	}
	return filepath.Abs(root)
}

func PlanSummary(plan state.Plan) string {
	var lines []string
	for _, repository := range plan.Payload.Repositories {
		lines = append(lines, fmt.Sprintf("%s %s %s", repository.Action, repository.Format, repository.Name))
	}
	return strings.Join(lines, "\n")
}
