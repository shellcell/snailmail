package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/app"
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
	if err := state.RequireGitRepository(root); err != nil {
		return err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return err
	}
	defer unlock()
	return state.Init(root, state.InitOptions{Name: request.Name})
}

func SetupRepository(request SetupRepositoryRequest) error {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return err
	}
	defer unlock()
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
	if err := state.RequireGitRepository(root); err != nil {
		return AddArtifactsResult{}, err
	}
	if len(request.Artifacts) == 0 {
		return AddArtifactsResult{}, errors.New("at least one artifact is required")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	defer unlock()
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
	if err := state.ValidateLock(lock, request.Repository, repository.Format); err != nil {
		return AddArtifactsResult{}, err
	}
	ledger, err := state.LoadLedgerHistory(root, request.Repository)
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
		packageName := nativePackageName(repository.Format, blob.Facts.Name)
		added, err := state.AddBlob(&lock, repository.Format, request.Track, distro, state.ToLockedBlob(blob), packageName, blob.Facts.Version)
		if err != nil {
			return AddArtifactsResult{}, err
		}
		if added {
			result.Added++
		} else {
			result.Skipped++
		}
		packages[packageName+"@"+blob.Facts.Version] = true
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
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	defer unlock()
	gitRevision, err := state.RequireCleanGit(root)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	manifestPath, err := state.WorkspacePath(root, state.ManifestFilename)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	manifestDigest, err := state.HashFile(manifestPath)
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
		EngineVersion: phase1EngineVersion, GitRevision: gitRevision, ManifestSHA256: manifestDigest,
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
		if err := state.ValidateLock(lock, name, repository.Format); err != nil {
			return PlanWorkspaceResult{}, err
		}
		ledger, err := state.LoadLedgerHistory(root, name)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return PlanWorkspaceResult{}, err
		}
		lockPath, err := state.WorkspacePath(root, repository.Lock)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		lockDigest, err := state.HashFile(lockPath)
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
		output = filepath.Join(root, "snailmail.snailmail-plan.json")
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
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	defer unlock()
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
	if err := validateApplyPlan(plan); err != nil {
		return ApplyWorkspaceResult{}, err
	}
	plannedLedgerRepositories := make([]string, 0, len(plan.Payload.Repositories))
	for _, repository := range plan.Payload.Repositories {
		if repository.Action != "noop" {
			plannedLedgerRepositories = append(plannedLedgerRepositories, repository.Name)
		}
	}
	ledgerCommitted, err := state.ValidatePlanGit(root, plan.Payload.GitRevision, plan.PlanID, plannedLedgerRepositories)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	manifestPath, err := state.WorkspacePath(root, state.ManifestFilename)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	manifestDigest, err := state.HashFile(manifestPath)
	if err != nil || manifestDigest != plan.Payload.ManifestSHA256 {
		return ApplyWorkspaceResult{}, errors.New("stale plan: manifest changed")
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	if len(plan.Payload.Repositories) != len(manifest.Repositories) {
		return ApplyWorkspaceResult{}, errors.New("plan does not cover every configured repository")
	}
	generatedAt, err := time.Parse(time.RFC3339, plan.Payload.GeneratedAt)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	type applyRepository struct {
		planned    state.PlanRepository
		repository state.Repository
		lock       state.RepositoryLock
		stageRoot  string
		stage      string
		current    bool
	}
	var prepared []applyRepository
	seenRepositories := make(map[string]bool)
	for _, planned := range plan.Payload.Repositories {
		if seenRepositories[planned.Name] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan contains duplicate repository %q", planned.Name)
		}
		seenRepositories[planned.Name] = true
		repository, exists := manifest.Repositories[planned.Name]
		if !exists || repository.Format != planned.Format || repository.Output != planned.Output {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q configuration changed", planned.Name)
		}
		lockPath, err := state.WorkspacePath(root, repository.Lock)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		lockDigest, err := state.HashFile(lockPath)
		if err != nil || lockDigest != planned.LockSHA256 {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q lock changed", planned.Name)
		}
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if err := state.ValidateLock(lock, planned.Name, repository.Format); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		ledger, err := state.LoadLedgerHistory(root, planned.Name)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		observed, err := observedTree(root, repository.Output)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if observed != planned.ObservedTreeSHA256 && observed != planned.DesiredTreeSHA256 {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q target changed", planned.Name)
		}
		expectedAction := "noop"
		if planned.ObservedTreeSHA256 != planned.DesiredTreeSHA256 {
			expectedAction = "update"
			if planned.ObservedTreeSHA256 == "" {
				expectedAction = "create"
			}
		}
		if planned.Action != expectedAction || planned.ChangeID != planned.Name+":"+planned.DesiredTreeSHA256[:12] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q has inconsistent action metadata", planned.Name)
		}
		item := applyRepository{planned: planned, repository: repository, lock: lock, current: observed == planned.DesiredTreeSHA256}
		if observed == planned.DesiredTreeSHA256 {
			prepared = append(prepared, item)
			continue
		}
		stage, err := os.MkdirTemp("", ".snailmail-apply-*")
		if err != nil {
			return ApplyWorkspaceResult{}, err
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
			for _, previous := range prepared {
				_ = os.RemoveAll(previous.stageRoot)
			}
			return ApplyWorkspaceResult{}, buildErr
		}
		item.stageRoot, item.stage = stage, stageOutput
		prepared = append(prepared, item)
	}
	defer func() {
		for _, item := range prepared {
			_ = os.RemoveAll(item.stageRoot)
		}
	}()
	ledgerRepositories := plannedLedgerRepositories
	ledgerRevision := ""
	if ledgerCommitted {
		ledgerRevision, err = state.RequireCleanGit(root)
		if err != nil {
			return ApplyWorkspaceResult{}, errors.New("committed publication ledgers do not match the plan")
		}
		if err := state.ValidatePublicationCommitPaths(root, ledgerRevision, ledgerRepositories); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		for _, item := range prepared {
			if item.planned.Action == "noop" {
				continue
			}
			if err := state.ValidateCommittedPublicationLedger(
				root, plan.Payload.GitRevision, ledgerRevision, item.planned.Name, plan.PlanID, item.planned.ChangeID,
				item.planned.DesiredTreeSHA256, plan.Payload.CreatedAt, activeLock(item.lock),
			); err != nil {
				return ApplyWorkspaceResult{}, err
			}
		}
	}
	for _, item := range prepared {
		if item.planned.Action == "noop" {
			continue
		}
		publishedLock := activeLock(item.lock)
		if err := state.PreparePublicationRecords(
			root, plan.Payload.GitRevision, item.planned.Name, plan.PlanID, item.planned.ChangeID,
			item.planned.DesiredTreeSHA256, plan.Payload.CreatedAt, publishedLock,
		); err != nil {
			return ApplyWorkspaceResult{}, err
		}
	}
	if !ledgerCommitted && len(ledgerRepositories) != 0 {
		ledgerRevision, err = state.CommitPublicationLedgers(root, plan.PlanID, plan.Payload.GitRevision, ledgerRepositories)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if err := state.ValidatePublicationCommitPaths(root, ledgerRevision, ledgerRepositories); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		for _, item := range prepared {
			if item.planned.Action == "noop" {
				continue
			}
			if err := state.ValidateCommittedPublicationLedger(
				root, plan.Payload.GitRevision, ledgerRevision, item.planned.Name, plan.PlanID, item.planned.ChangeID,
				item.planned.DesiredTreeSHA256, plan.Payload.CreatedAt, activeLock(item.lock),
			); err != nil {
				return ApplyWorkspaceResult{}, err
			}
		}
	} else if !ledgerCommitted {
		ledgerRevision = plan.Payload.GitRevision
	}
	needsPublication := false
	for _, item := range prepared {
		if !item.current {
			needsPublication = true
			break
		}
	}
	if needsPublication {
		unlockGit, err := state.AcquireGitRevisionLock(root, ledgerRevision)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		defer unlockGit()
	} else if err := state.AssertGitRevision(root, ledgerRevision); err != nil {
		return ApplyWorkspaceResult{}, err
	}
	result := ApplyWorkspaceResult{PlanID: plan.PlanID}
	for _, item := range prepared {
		if item.current {
			result.Current++
			continue
		}
		if err := state.AssertGitRevision(root, ledgerRevision); err != nil {
			return result, err
		}
		finalOutput, err := state.WorkspacePath(root, item.repository.Output)
		if err != nil {
			return result, err
		}
		if err := app.PublishVerifiedDirectory(ctx, item.stage, finalOutput, item.planned.ObservedTreeSHA256, item.planned.DesiredTreeSHA256); err != nil {
			return result, err
		}
		if err := state.AssertGitRevision(root, ledgerRevision); err != nil {
			return result, err
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
			if nativePackageName(repository.Format, blob.Facts.Name) != packageVersion.Package || blob.Facts.Version != packageVersion.Version {
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
	if output == "" {
		temporary, err := os.MkdirTemp("", ".snailmail-plan-build-*")
		if err != nil {
			return BuildResult{}, err
		}
		defer os.RemoveAll(temporary)
		output = filepath.Join(temporary, "repository")
	}
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

func activeLock(lock state.RepositoryLock) state.RepositoryLock {
	lock.PackageVersion = activePackageVersions(lock)
	return lock
}

func observedTree(root, output string) (string, error) {
	name, err := state.WorkspacePath(root, output)
	if err != nil {
		return "", err
	}
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
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	}
	return absolute, nil
}

func nativePackageName(format, name string) string {
	if format == "pypi" {
		return pypi.NormalizeName(name)
	}
	return name
}

func validateApplyPlan(plan state.Plan) error {
	if !validSHA256(plan.Payload.ManifestSHA256) {
		return errors.New("plan has an invalid manifest digest")
	}
	createdAt, err := time.Parse(time.RFC3339, plan.Payload.CreatedAt)
	if err != nil {
		return errors.New("plan has an invalid creation time")
	}
	expiresAt, err := time.Parse(time.RFC3339, plan.Payload.ExpiresAt)
	if err != nil || !expiresAt.After(createdAt) {
		return errors.New("plan has an invalid expiry")
	}
	if _, err := time.Parse(time.RFC3339, plan.Payload.GeneratedAt); err != nil {
		return errors.New("plan has an invalid generation time")
	}
	seen := make(map[string]bool)
	for _, repository := range plan.Payload.Repositories {
		if err := state.ValidateRepositoryName(repository.Name); err != nil {
			return err
		}
		if seen[repository.Name] {
			return fmt.Errorf("plan contains duplicate repository %q", repository.Name)
		}
		seen[repository.Name] = true
		if repository.Action != "create" && repository.Action != "update" && repository.Action != "noop" {
			return fmt.Errorf("plan repository %q has invalid action %q", repository.Name, repository.Action)
		}
		if !validSHA256(repository.LockSHA256) || !validSHA256(repository.DesiredTreeSHA256) ||
			(repository.ObservedTreeSHA256 != "" && !validSHA256(repository.ObservedTreeSHA256)) {
			return fmt.Errorf("plan repository %q has an invalid digest", repository.Name)
		}
		if repository.ChangeID != repository.Name+":"+repository.DesiredTreeSHA256[:12] {
			return fmt.Errorf("plan repository %q has an invalid change ID", repository.Name)
		}
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func PlanSummary(plan state.Plan) string {
	var lines []string
	for _, repository := range plan.Payload.Repositories {
		lines = append(lines, fmt.Sprintf("%s %s %s", repository.Action, repository.Format, repository.Name))
	}
	return strings.Join(lines, "\n")
}
