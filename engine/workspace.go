package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	localhost "github.com/shellcell/snailmail/adapters/host/local"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/state"
)

const phase1EngineVersion = "phase2-v1"

type InitWorkspaceRequest struct {
	Root string
	Name string
}

type SetupRepositoryRequest struct {
	Root              string
	Name              string
	Format            string
	Output            string
	HostType          string
	Visibility        string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	CanonicalEndpoint string
	UsePathStyle      bool
	Suite             string
	Component         string
	Architectures     []string
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
	Root             string
	Output           string
	GeneratedAt      time.Time
	CreatedAt        time.Time
	ExpiresIn        time.Duration
	VerificationMode string
	Hosts            host.Resolver
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
	Hosts             host.Resolver
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
		HostType: request.HostType, Visibility: request.Visibility, Bucket: request.Bucket,
		Prefix: request.Prefix, Region: request.Region, Endpoint: request.Endpoint,
		CanonicalEndpoint: request.CanonicalEndpoint, UsePathStyle: request.UsePathStyle,
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
	payload.VerificationMode = request.VerificationMode
	if payload.VerificationMode == "" {
		payload.VerificationMode = "structural"
	}
	if payload.VerificationMode != "structural" && payload.VerificationMode != "client" {
		return PlanWorkspaceResult{}, errors.New("verification mode must be structural or client")
	}
	changes := 0
	hosts := request.Hosts
	if hosts == nil {
		hosts = localHostResolver{}
	}
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
		hostRepository := toHostRepository(root, name, repository)
		selectedHost, err := hosts.Resolve(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		capabilities, err := selectedHost.Capabilities(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		if !capabilities.FaithfulPreview || !capabilities.ConditionalCommit {
			return PlanWorkspaceResult{}, fmt.Errorf("repository %q host cannot provide verified conditional publication", name)
		}
		observed, err := selectedHost.Observe(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		action := "noop"
		if observed.TreeSHA256 != desired.TreeSHA256 || (hostRepository.Type == "s3" && observed.ManifestSHA256 != desired.ManifestSHA256) {
			action = "update"
			if observed.NativeRevision == "" {
				action = "create"
			}
			changes++
		}
		hostIdentity, err := repositoryHostIdentity(repository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		installDocDigest, err := repositoryInstallDocDigest(root, name, repository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		payload.Repositories = append(payload.Repositories, state.PlanRepository{
			Name: name, Format: repository.Format, LockSHA256: lockDigest,
			Host: repository.Host, Visibility: repository.Visibility, HostIdentitySHA256: hostIdentity,
			CanonicalEndpoint: hostRepository.CanonicalEndpoint, ObservedRevision: observed.NativeRevision,
			ObservedPlanID: observed.PlanID, ObservedChangeID: observed.ChangeID,
			ObservedReleaseSHA256: observed.ReleaseSHA256, ObservedManifestSHA256: observed.ManifestSHA256,
			ObservedRestoreID: observed.RestoreID, ObservedRestoreSHA256: observed.RestoreSHA256,
			ObservedRestoreRootSHA256: observed.RestoreRootSHA256,
			FaithfulPreview:           capabilities.FaithfulPreview, ConditionalCommit: capabilities.ConditionalCommit,
			ConditionalRestore: capabilities.ConditionalRestore,
			InstallDocSHA256:   installDocDigest,
			ObservedTreeSHA256: observed.TreeSHA256, DesiredTreeSHA256: desired.TreeSHA256, DesiredManifestSHA256: desired.ManifestSHA256,
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
	if request.StructuralOnly && plan.Payload.VerificationMode != "structural" {
		return ApplyWorkspaceResult{}, errors.New("apply verification mode does not match the reviewed plan")
	}
	request.StructuralOnly = plan.Payload.VerificationMode == "structural"
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
		planned        state.PlanRepository
		repository     state.Repository
		lock           state.RepositoryLock
		host           host.Host
		hostRepository host.Repository
		observed       host.PublishedRevision
		hostStage      host.StagedPublication
		stageRoot      string
		stage          string
		current        bool
	}
	var prepared []applyRepository
	hosts := request.Hosts
	if hosts == nil {
		hosts = localHostResolver{}
	}
	seenRepositories := make(map[string]bool)
	for _, planned := range plan.Payload.Repositories {
		if seenRepositories[planned.Name] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan contains duplicate repository %q", planned.Name)
		}
		seenRepositories[planned.Name] = true
		repository, exists := manifest.Repositories[planned.Name]
		if !exists || repository.Format != planned.Format {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q configuration changed", planned.Name)
		}
		hostIdentity, err := repositoryHostIdentity(repository)
		if err != nil || hostIdentity != planned.HostIdentitySHA256 || repository.Host != planned.Host || repository.Visibility != planned.Visibility {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q host changed", planned.Name)
		}
		hostRepository := toHostRepository(root, planned.Name, repository)
		if hostRepository.CanonicalEndpoint != planned.CanonicalEndpoint {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q canonical endpoint changed", planned.Name)
		}
		installDocDigest, err := repositoryInstallDocDigest(root, planned.Name, repository)
		if err != nil || installDocDigest != planned.InstallDocSHA256 {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q install document changed", planned.Name)
		}
		selectedHost, err := hosts.Resolve(ctx, hostRepository)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		capabilities, err := selectedHost.Capabilities(ctx, hostRepository)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if capabilities.FaithfulPreview != planned.FaithfulPreview || capabilities.ConditionalCommit != planned.ConditionalCommit || capabilities.ConditionalRestore != planned.ConditionalRestore {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q host capabilities changed", planned.Name)
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
		observed, err := selectedHost.Observe(ctx, hostRepository)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		matchesObserved := revisionMatchesPlanObservation(observed, planned)
		matchesApplied := planned.Action != "noop" && observed.TreeSHA256 == planned.DesiredTreeSHA256 &&
			(repository.Host.Type != "s3" || (observed.PlanID == plan.PlanID && observed.ChangeID == planned.ChangeID && observed.ManifestSHA256 == planned.DesiredManifestSHA256))
		if !matchesObserved && !matchesApplied {
			if observed.TreeSHA256 == planned.ObservedTreeSHA256 {
				return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q native revision changed", planned.Name)
			}
			if observed.TreeSHA256 == planned.DesiredTreeSHA256 {
				return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q desired tree was published by another change", planned.Name)
			}
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q target changed", planned.Name)
		}
		expectedAction := "noop"
		if planned.ObservedTreeSHA256 != planned.DesiredTreeSHA256 || (repository.Host.Type == "s3" && planned.ObservedManifestSHA256 != planned.DesiredManifestSHA256) {
			expectedAction = "update"
			if planned.ObservedRevision == "" {
				expectedAction = "create"
			}
		}
		if planned.Action != expectedAction || planned.ChangeID != planned.Name+":"+planned.DesiredTreeSHA256[:12] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q has inconsistent action metadata", planned.Name)
		}
		current := observed.TreeSHA256 == planned.DesiredTreeSHA256 && (repository.Host.Type != "s3" || observed.ManifestSHA256 == planned.DesiredManifestSHA256)
		item := applyRepository{
			planned: planned, repository: repository, lock: lock, host: selectedHost,
			hostRepository: hostRepository, observed: observed, current: current,
		}
		if item.current && (request.StructuralOnly || planned.Action == "noop") {
			prepared = append(prepared, item)
			continue
		}
		stage, err := os.MkdirTemp("", ".snailmail-apply-*")
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		stageOutput := filepath.Join(stage, "repository")
		staged, buildErr := buildLockedRepository(ctx, root, planned.Name, repository, lock, generatedAt, stageOutput)
		if buildErr == nil && (staged.TreeSHA256 != planned.DesiredTreeSHA256 || staged.ManifestSHA256 != planned.DesiredManifestSHA256) {
			buildErr = errors.New("stale plan: rebuilt tree digest changed")
		}
		if buildErr == nil {
			structuralRequest := request
			structuralRequest.StructuralOnly = true
			buildErr = verifyStaged(ctx, repository.Format, stageOutput, structuralRequest)
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
	defer func() {
		for _, item := range prepared {
			if item.hostStage.ID != "" {
				cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				_ = item.host.Abort(cleanupCtx, item.hostRepository, item.hostStage)
				cancelCleanup()
			}
		}
	}()
	for index := range prepared {
		item := &prepared[index]
		if item.current {
			continue
		}
		files, err := stagedHostFiles(item.stage)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		item.hostStage, err = item.host.Stage(ctx, item.hostRepository, host.StageRequest{
			PlanID: plan.PlanID, ChangeID: item.planned.ChangeID, Directory: item.stage,
			TreeSHA256: item.planned.DesiredTreeSHA256, Files: files,
			CommitPaths: repositoryCommitPaths(item.repository),
		})
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if request.StructuralOnly {
			continue
		}
		if item.hostRepository.Type == "local" {
			if err := verifyStaged(ctx, item.repository.Format, item.stage, request); err != nil {
				return ApplyWorkspaceResult{}, err
			}
			continue
		}
		if item.repository.Format != "pypi" {
			return ApplyWorkspaceResult{}, fmt.Errorf("host preview verification is not implemented for format %q", item.repository.Format)
		}
		if _, _, err := app.VerifyPyPIClientEndpoint(ctx, item.stage, item.hostStage.PreviewEndpoint, request.Python); err != nil {
			return ApplyWorkspaceResult{}, err
		}
	}
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
			return ApplyWorkspaceResult{}, fmt.Errorf("commit publication ledgers for %v: %w", ledgerRepositories, err)
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
			if !request.StructuralOnly && item.planned.Action != "noop" {
				if err := verifyCanonicalClient(ctx, root, item.repository, item.stage, item.hostRepository.CanonicalEndpoint, request); err != nil {
					if item.hostRepository.Type == "s3" && item.observed.RestoreID != "" {
						restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
						_, restoreErr := item.host.Restore(restoreCtx, item.hostRepository, host.RestoreRef{
							ID: item.observed.RestoreID, PlanID: item.observed.PlanID,
							ChangeID: item.observed.ChangeID, FailedTree: item.observed.TreeSHA256,
							DescriptorSHA256: item.observed.RestoreSHA256, RootSHA256: item.observed.RestoreRootSHA256,
						}, expectedRevisionFromPublished(item.observed))
						cancelRestore()
						if restoreErr != nil {
							return result, fmt.Errorf("canonical retry probe failed: %v; restore failed: %w", err, restoreErr)
						}
						result.Current--
					}
					return result, err
				}
			}
			continue
		}
		if err := state.AssertGitRevision(root, ledgerRevision); err != nil {
			return result, err
		}
		committed, err := item.host.Commit(ctx, item.hostRepository, item.hostStage, expectedRevisionFromPlan(item.planned))
		if err != nil {
			return result, err
		}
		result.Applied++
		canonical, observeErr := item.host.Observe(ctx, item.hostRepository)
		if observeErr != nil || canonical.TreeSHA256 != item.planned.DesiredTreeSHA256 || canonical.NativeRevision != committed.Revision.NativeRevision ||
			(item.hostRepository.Type == "s3" && canonical != committed.Revision) {
			probeErr := observeErr
			if probeErr == nil {
				probeErr = errors.New("canonical host observation does not match committed tree")
			}
			if committed.RestoreRef != nil {
				restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
				_, restoreErr := item.host.Restore(restoreCtx, item.hostRepository, *committed.RestoreRef, expectedRevisionFromPublished(committed.Revision))
				cancelRestore()
				if restoreErr != nil {
					return result, fmt.Errorf("canonical probe failed: %v; restore failed: %w", probeErr, restoreErr)
				}
				result.Applied--
			}
			return result, fmt.Errorf("canonical probe failed: %w", probeErr)
		}
		if !request.StructuralOnly {
			if probeErr := verifyCanonicalClient(ctx, root, item.repository, item.stage, committed.CanonicalEndpoint, request); probeErr != nil {
				if committed.RestoreRef != nil {
					restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
					_, restoreErr := item.host.Restore(restoreCtx, item.hostRepository, *committed.RestoreRef, expectedRevisionFromPublished(committed.Revision))
					cancelRestore()
					if restoreErr != nil {
						return result, fmt.Errorf("canonical client probe failed: %v; restore failed: %w", probeErr, restoreErr)
					}
					result.Applied--
				}
				return result, fmt.Errorf("canonical client probe failed: %w", probeErr)
			}
		}
		if err := state.AssertGitRevision(root, ledgerRevision); err != nil {
			return result, err
		}
	}
	return result, nil
}

func verifyCanonicalClient(ctx context.Context, root string, repository state.Repository, staged, endpoint string, request ApplyWorkspaceRequest) error {
	if repository.Host.Type == "local" {
		output, err := state.WorkspacePath(root, repository.Host.Path)
		if err != nil {
			return err
		}
		return verifyStaged(ctx, repository.Format, output, request)
	}
	if repository.Format != "pypi" {
		return fmt.Errorf("canonical client verification is not implemented for format %q", repository.Format)
	}
	_, _, err := app.VerifyPyPIClientEndpoint(ctx, staged, endpoint, request.Python)
	return err
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

type localHostResolver struct{}

func (localHostResolver) Resolve(_ context.Context, repository host.Repository) (host.Host, error) {
	if repository.Type != "local" {
		return nil, fmt.Errorf("host type %q requires a configured host resolver", repository.Type)
	}
	return localhost.New(), nil
}

func toHostRepository(root, name string, repository state.Repository) host.Repository {
	canonicalEndpoint := repository.Host.CanonicalEndpoint
	if repository.Host.Type == "local" {
		canonicalEndpoint = repository.Host.Path
	}
	return host.Repository{
		Name: name, Format: repository.Format, Type: repository.Host.Type,
		Visibility: repository.Visibility, WorkspaceRoot: root, Path: repository.Host.Path,
		Bucket: repository.Host.Bucket, Prefix: repository.Host.Prefix, Region: repository.Host.Region,
		Endpoint: repository.Host.Endpoint, CanonicalEndpoint: canonicalEndpoint,
		UsePathStyle: repository.Host.UsePathStyle,
	}
}

func repositoryHostIdentity(repository state.Repository) (string, error) {
	content, err := json.Marshal(struct {
		Format     string           `json:"format"`
		Visibility string           `json:"visibility"`
		Host       state.HostConfig `json:"host"`
	}{Format: repository.Format, Visibility: repository.Visibility, Host: repository.Host})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func repositoryInstallDocDigest(root, name string, repository state.Repository) (string, error) {
	if repository.Host.Type != "s3" || repository.Format != "pypi" {
		return "", nil
	}
	if err := state.ValidateInstallDocument(root, name, repository); err != nil {
		return "", err
	}
	filename, err := state.WorkspacePath(root, filepath.ToSlash(filepath.Join("docs", "install-"+name+".md")))
	if err != nil {
		return "", err
	}
	return state.HashFile(filename)
}

func stagedHostFiles(directory string) ([]host.File, error) {
	manifest, err := app.VerifyRepository(directory)
	if err != nil {
		return nil, err
	}
	files := make([]host.File, 0, len(manifest.Files)+1)
	for _, file := range manifest.Files {
		files = append(files, host.File{Path: file.Path, Size: file.Size, SHA256: file.SHA256})
	}
	management := filepath.Join(directory, "snailmail.repository.json")
	info, err := os.Lstat(management)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("staged management manifest is not a regular file")
	}
	digest, err := state.HashFile(management)
	if err != nil {
		return nil, err
	}
	files = append(files, host.File{Path: "snailmail.repository.json", Size: info.Size(), SHA256: digest})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files, nil
}

func repositoryCommitPaths(repository state.Repository) []string {
	switch repository.Format {
	case "pypi":
		return []string{"simple/index.html"}
	case "helm":
		return []string{"index.yaml"}
	case "deb":
		return []string{filepath.ToSlash(filepath.Join("dists", repository.Suite, "Release"))}
	default:
		return nil
	}
}

func validateApplyPlan(plan state.Plan) error {
	if !validSHA256(plan.Payload.ManifestSHA256) {
		return errors.New("plan has an invalid manifest digest")
	}
	if plan.Payload.VerificationMode != "structural" && plan.Payload.VerificationMode != "client" {
		return errors.New("plan has an invalid verification mode")
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
			!validSHA256(repository.HostIdentitySHA256) ||
			(repository.ObservedTreeSHA256 != "" && !validSHA256(repository.ObservedTreeSHA256)) {
			return fmt.Errorf("plan repository %q has an invalid digest", repository.Name)
		}
		if repository.Host.Type != "local" && repository.Host.Type != "s3" {
			return fmt.Errorf("plan repository %q has unsupported host type %q", repository.Name, repository.Host.Type)
		}
		if repository.CanonicalEndpoint == "" {
			return fmt.Errorf("plan repository %q has no canonical endpoint", repository.Name)
		}
		if repository.Host.Type == "s3" && !validSHA256(repository.InstallDocSHA256) {
			return fmt.Errorf("plan repository %q has an invalid install document digest", repository.Name)
		}
		if repository.Host.Type == "s3" && !validSHA256(repository.DesiredManifestSHA256) {
			return fmt.Errorf("plan repository %q has an invalid desired manifest digest", repository.Name)
		}
		for _, digest := range []string{repository.ObservedReleaseSHA256, repository.ObservedManifestSHA256, repository.ObservedRestoreSHA256, repository.ObservedRestoreRootSHA256} {
			if digest != "" && !validSHA256(digest) {
				return fmt.Errorf("plan repository %q has an invalid observed publication digest", repository.Name)
			}
		}
		if repository.Host.Type == "s3" {
			if repository.ObservedTreeSHA256 == "" {
				if repository.ObservedPlanID != "" || repository.ObservedChangeID != "" || repository.ObservedReleaseSHA256 != "" ||
					repository.ObservedManifestSHA256 != "" || repository.ObservedRestoreID != "" || repository.ObservedRestoreSHA256 != "" || repository.ObservedRestoreRootSHA256 != "" {
					return fmt.Errorf("plan repository %q has an incomplete observed publication", repository.Name)
				}
			} else if repository.ObservedRevision == "" || !validSHA256(repository.ObservedPlanID) || repository.ObservedChangeID != repository.Name+":"+repository.ObservedTreeSHA256[:12] ||
				!validSHA256(repository.ObservedReleaseSHA256) || !validSHA256(repository.ObservedManifestSHA256) ||
				!validSHA256(repository.ObservedRestoreID) || !validSHA256(repository.ObservedRestoreSHA256) {
				return fmt.Errorf("plan repository %q has an invalid observed publication", repository.Name)
			}
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

func revisionMatchesPlanObservation(revision host.PublishedRevision, planned state.PlanRepository) bool {
	return revision.NativeRevision == planned.ObservedRevision && revision.TreeSHA256 == planned.ObservedTreeSHA256 &&
		revision.PlanID == planned.ObservedPlanID && revision.ChangeID == planned.ObservedChangeID &&
		revision.ReleaseSHA256 == planned.ObservedReleaseSHA256 && revision.ManifestSHA256 == planned.ObservedManifestSHA256 &&
		revision.RestoreID == planned.ObservedRestoreID && revision.RestoreSHA256 == planned.ObservedRestoreSHA256 &&
		revision.RestoreRootSHA256 == planned.ObservedRestoreRootSHA256
}

func expectedRevisionFromPlan(planned state.PlanRepository) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: planned.ObservedRevision, TreeSHA256: planned.ObservedTreeSHA256,
		PlanID: planned.ObservedPlanID, ChangeID: planned.ObservedChangeID,
		ReleaseSHA256: planned.ObservedReleaseSHA256, ManifestSHA256: planned.ObservedManifestSHA256,
		RestoreID: planned.ObservedRestoreID, RestoreSHA256: planned.ObservedRestoreSHA256,
		RestoreRootSHA256: planned.ObservedRestoreRootSHA256,
	}
}

func expectedRevisionFromPublished(revision host.PublishedRevision) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: revision.NativeRevision, TreeSHA256: revision.TreeSHA256, PlanID: revision.PlanID, ChangeID: revision.ChangeID,
		ReleaseSHA256: revision.ReleaseSHA256, ManifestSHA256: revision.ManifestSHA256, RestoreID: revision.RestoreID,
		RestoreSHA256: revision.RestoreSHA256, RestoreRootSHA256: revision.RestoreRootSHA256,
	}
}

func PlanSummary(plan state.Plan) string {
	var lines []string
	for _, repository := range plan.Payload.Repositories {
		lines = append(lines, fmt.Sprintf("%s %s %s", repository.Action, repository.Format, repository.Name))
	}
	return strings.Join(lines, "\n")
}
