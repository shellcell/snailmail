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
	"reflect"
	"sort"
	"strings"
	"time"

	localhost "github.com/shellcell/snailmail/adapters/host/local"
	"github.com/shellcell/snailmail/blob"
	debformat "github.com/shellcell/snailmail/formats/deb"
	helmformat "github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/gate"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/knowledge"
	"github.com/shellcell/snailmail/internal/state"
	statusrenderer "github.com/shellcell/snailmail/internal/status"
	"github.com/shellcell/snailmail/signer"
)

const phase1EngineVersion = "phase3-v1"

type InitWorkspaceRequest struct {
	Root            string
	Name            string
	ForgeRepository string
}

type SetupRepositoryRequest struct {
	Root              string
	Name              string
	Format            string
	Output            string
	HostType          string
	Gate              string
	ApprovalKeys      []string
	SigningKey        string
	AllowUnsigned     bool
	Visibility        string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	CanonicalEndpoint string
	UsePathStyle      bool
	ReadAuth          string
	CredentialBroker  string
	RemoteRepository  string
	Branch            string
	PreviewRepository string
	PreviewBranch     string
	PreviewEndpoint   string
	Track             string
	Suite             string
	Component         string
	Architectures     []string
}

type AddArtifactsRequest struct {
	Context    context.Context
	Root       string
	Repository string
	Artifacts  []string
	Track      string
	Blobs      blob.Resolver
}

type ConfigureBlobStoreRequest struct {
	Context      context.Context
	Root         string
	Type         string
	Bucket       string
	Prefix       string
	Region       string
	Endpoint     string
	UsePathStyle bool
	Blobs        blob.Resolver
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
	createdAt        time.Time
	ExpiresIn        time.Duration
	VerificationMode string
	Hosts            host.Resolver
	Blobs            blob.Resolver
	Signers          signer.Resolver
}

type PlanWorkspaceResult struct {
	PlanID       string
	Output       string
	Changes      int
	Acquisitions []PlannedAcquisition
}

type PlannedAcquisition struct {
	Repository string
	Package    string
	Version    string
	Filename   string
	SHA256     string
	OriginURL  string
}

type ApprovePlanRequest struct {
	Root       string
	Plan       string
	Output     string
	Repository string
	KeyFile    string
	Now        time.Time
	ExpiresIn  time.Duration
}

type ApprovePlanResult struct {
	PlanID   string
	Output   string
	Approver string
}

type RenderStatusRequest struct {
	Root   string
	Output string
	Plan   string
	Now    time.Time
}

type RenderStatusResult struct {
	Output       string
	Repositories int
}

type ApplyWorkspaceRequest struct {
	Root                   string
	Plan                   string
	now                    time.Time
	clock                  func() time.Time
	StructuralOnly         bool
	Python                 string
	Runner                 string
	DebianImage            string
	HelmImage              string
	MaxWorkspaceBytes      int64
	Hosts                  host.Resolver
	Blobs                  blob.Resolver
	Gates                  gate.Evaluator
	beforeDeploymentCommit func() error
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
	return state.Init(root, state.InitOptions{Name: request.Name, ForgeRepository: request.ForgeRepository})
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
		Gate: request.Gate, ApprovalKeys: append([]string(nil), request.ApprovalKeys...), SigningKeys: optionalSigningKeys(request.SigningKey), AllowUnsigned: request.AllowUnsigned,
		Prefix: request.Prefix, Region: request.Region, Endpoint: request.Endpoint,
		CanonicalEndpoint: request.CanonicalEndpoint, UsePathStyle: request.UsePathStyle,
		ReadAuth: request.ReadAuth, CredentialBroker: request.CredentialBroker,
		Repository: request.RemoteRepository, Branch: request.Branch, PreviewRepository: request.PreviewRepository,
		PreviewBranch: request.PreviewBranch, PreviewEndpoint: request.PreviewEndpoint,
		Track: request.Track, Suite: request.Suite, Component: request.Component, Architectures: request.Architectures,
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
	ctx := request.Context
	if ctx == nil {
		ctx = context.Background()
	}
	blobStore, err := resolveBlobStore(ctx, manifest, request.Blobs)
	if err != nil {
		return AddArtifactsResult{}, err
	}
	result := AddArtifactsResult{Repository: request.Repository}
	packages := make(map[string]bool)
	for _, artifact := range request.Artifacts {
		blob, err := state.PutArtifact(root, repository.Format, artifact)
		if err != nil {
			return AddArtifactsResult{}, err
		}
		if blobStore != nil {
			locked := state.ToLockedBlob(blob)
			_, name, err := state.LoadBlob(root, repository.Format, locked)
			if err != nil {
				return AddArtifactsResult{}, err
			}
			file, err := os.Open(name)
			if err != nil {
				return AddArtifactsResult{}, err
			}
			putErr := blobStore.Put(ctx, blobref(locked), file)
			closeErr := file.Close()
			if putErr != nil {
				return AddArtifactsResult{}, putErr
			}
			if closeErr != nil {
				return AddArtifactsResult{}, closeErr
			}
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

func ConfigureBlobStore(ctx context.Context, request ConfigureBlobStoreRequest) error {
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
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return err
	}
	configuration := state.BlobStoreFromOptions(state.BlobStoreOptions{
		Type: request.Type, Bucket: request.Bucket, Prefix: request.Prefix, Region: request.Region,
		Endpoint: request.Endpoint, UsePathStyle: request.UsePathStyle,
	})
	if err := state.ValidateBlobStore(configuration); err != nil {
		return err
	}
	sourceStore, err := resolveBlobStore(ctx, manifest, request.Blobs)
	if err != nil {
		return err
	}
	candidate := manifest
	candidate.BlobStore = configuration
	if configuration.Type == "s3" && manifest.BlobStore.Type == "local" && state.IsLegacyWorkspaceID(candidate.Workspace.Name, candidate.Workspace.ID) {
		candidate.Workspace.ID, err = state.NewWorkspaceID()
		if err != nil {
			return err
		}
		identityManifest := manifest
		identityManifest.Workspace.ID = candidate.Workspace.ID
		if err := state.WriteManifest(root, identityManifest); err != nil {
			return fmt.Errorf("persist workspace identity before blob migration: %w", err)
		}
		manifest.Workspace.ID = candidate.Workspace.ID
	}
	store, err := resolveBlobStore(ctx, candidate, request.Blobs)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, name := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[name]
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return err
		}
		if err := state.ValidateLock(lock, name, repository.Format); err != nil {
			return err
		}
		for _, packageVersion := range lock.PackageVersion {
			for _, locked := range packageVersion.Blobs {
				if seen[locked.SHA256] {
					continue
				}
				seen[locked.SHA256] = true
				_, blobName, err := state.EnsureBlob(ctx, root, repository.Format, locked, sourceStore)
				if err != nil {
					return err
				}
				if store != nil {
					file, err := os.Open(blobName)
					if err != nil {
						return err
					}
					putErr := store.Put(ctx, blobref(locked), file)
					closeErr := file.Close()
					if putErr != nil {
						return putErr
					}
					if closeErr != nil {
						return closeErr
					}
				}
			}
		}
	}
	return state.WriteManifest(root, candidate)
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
	blobStore, err := resolveBlobStore(ctx, manifest, request.Blobs)
	if err != nil {
		return PlanWorkspaceResult{}, err
	}
	blobStoreIdentity, err := blobStoreIdentity(manifest)
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
	createdAt := request.createdAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	createdAt = createdAt.UTC().Truncate(time.Second)
	generatedAt := request.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = createdAt
	}
	generatedAt = generatedAt.UTC().Truncate(time.Second)
	expiresIn := request.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 2 * time.Hour
	}
	if expiresIn <= 0 {
		return PlanWorkspaceResult{}, errors.New("plan expiry must be positive")
	}
	payload := state.PlanPayload{
		EngineVersion: phase1EngineVersion, GitRevision: gitRevision, ManifestSHA256: manifestDigest,
		WorkspaceID: manifest.Workspace.ID, ForgeRepository: manifest.Workspace.ForgeRepository,
		BlobStore: manifest.BlobStore, BlobStoreIdentitySHA256: blobStoreIdentity, KnowledgeSHA256: knowledge.SigningDigest(),
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
	var plannedAcquisitions []PlannedAcquisition
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
		if err := validateRotationKeyValidity(repository, manifest.Keys, createdAt); err != nil {
			return PlanWorkspaceResult{}, fmt.Errorf("repository %q: %w", name, err)
		}
		deployment, err := state.LoadDeployment(root, name)
		if err != nil {
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
		desired, err := buildLockedRepository(ctx, root, name, repository, lock, generatedAt, createdAt, "", blobStore, manifest.Keys, nil, request.Signers)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		if len(desired.Signing) != 0 {
			activeKey, _, _, _, signingErr := repositorySigningState(repository)
			keyExpiresAt, err := time.Parse(time.RFC3339, manifest.Keys[activeKey].ExpiresAt)
			if signingErr != nil || err != nil || createdAt.Add(expiresIn).After(keyExpiresAt) {
				return PlanWorkspaceResult{}, fmt.Errorf("repository %q plan expires after its signing key", name)
			}
		}
		hostIdentity, err := repositoryHostIdentity(repository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		hostRepository := toHostRepository(root, manifest.Workspace.ID, hostIdentity, name, repository)
		selectedHost, err := hosts.Resolve(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		capabilities, err := selectedHost.Capabilities(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		if !capabilities.FaithfulPreview || !capabilities.ConditionalCommit || (repository.Visibility == "private" && !capabilities.PrivateRead) {
			return PlanWorkspaceResult{}, fmt.Errorf("repository %q host cannot provide verified conditional publication", name)
		}
		observed, err := selectedHost.Observe(ctx, hostRepository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		trustNotBefore := time.Time{}
		if repository.SigningRotation != nil || deployment.SigningRotationPhase != "" {
			trustNotBefore, err = state.AuthoritativeDeploymentTrustSince(root, name, deployment)
			if err != nil {
				return PlanWorkspaceResult{}, err
			}
		}
		if err := validateRepositorySigningTransition(repository, manifest.Keys, deployment, observed, createdAt, trustNotBefore); err != nil {
			return PlanWorkspaceResult{}, fmt.Errorf("repository %q: %w", name, err)
		}
		desiredSigningState, err := repositoryDeploymentSigningState(repository, manifest.Keys)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		missingBindings := missingPublicationBindings(lock, repository, ledger)
		acquisitions := planAcquisitionsForVersions(visiblePackageVersions(lock, repository))
		for _, acquisition := range acquisitions {
			plannedAcquisitions = append(plannedAcquisitions, PlannedAcquisition{
				Repository: name, Package: acquisition.Package, Version: acquisition.Version,
				Filename: acquisition.Filename, SHA256: acquisition.SHA256, OriginURL: acquisition.OriginURL,
			})
		}
		publicationBindings := []state.PlanPublicationBinding(nil)
		if len(missingBindings) != 0 {
			publicationBindings = publicationBindingsForVersions(visiblePackageVersions(lock, repository))
		}
		publicationRecords := len(publicationBindings) != 0
		action := "noop"
		if observed.TreeSHA256 != desired.TreeSHA256 || ((hostRepository.Type == "s3" || hostRepository.Type == "github-pages") && observed.ManifestSHA256 != desired.ManifestSHA256) || publicationRecords || !deploymentMatchesDesired(deployment, observed, desired.TreeSHA256, desired.ManifestSHA256, desiredSigningState) {
			action = "update"
			if observed.NativeRevision == "" {
				action = "create"
			}
			changes++
		}
		installDocDigest, err := repositoryInstallDocDigest(root, name, repository)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		payload.Repositories = append(payload.Repositories, state.PlanRepository{
			Name: name, Gate: repository.Gate, ApprovalKeys: append([]string(nil), repository.ApprovalKeys...), Format: repository.Format, LockSHA256: lockDigest,
			Host: repository.Host, Visibility: repository.Visibility, HostIdentitySHA256: hostIdentity,
			CanonicalEndpoint: hostRepository.CanonicalEndpoint, ObservedRevision: observed.NativeRevision,
			ObservedPlanID: observed.PlanID, ObservedChangeID: observed.ChangeID,
			ObservedReleaseSHA256: observed.ReleaseSHA256, ObservedManifestSHA256: observed.ManifestSHA256,
			ObservedRestoreID: observed.RestoreID, ObservedRestoreSHA256: observed.RestoreSHA256,
			ObservedRestoreRootSHA256: observed.RestoreRootSHA256,
			ObservedDeployment:        deployment,
			Signing:                   desired.Signing,
			PublicationRecords:        publicationRecords,
			PublicationBindings:       publicationBindings,
			Acquisitions:              acquisitions,
			FaithfulPreview:           capabilities.FaithfulPreview, ConditionalCommit: capabilities.ConditionalCommit,
			ConditionalRestore:       capabilities.ConditionalRestore,
			PrivateRead:              capabilities.PrivateRead,
			CredentialBrokerIdentity: capabilities.CredentialBrokerIdentity,
			InstallDocSHA256:         installDocDigest,
			ObservedTreeSHA256:       observed.TreeSHA256, DesiredTreeSHA256: desired.TreeSHA256, DesiredManifestSHA256: desired.ManifestSHA256,
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
	return PlanWorkspaceResult{PlanID: plan.PlanID, Output: output, Changes: changes, Acquisitions: plannedAcquisitions}, nil
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
	now := request.currentTime()
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
	plannedDeploymentRepositories := make([]string, 0, len(plan.Payload.Repositories))
	for _, repository := range plan.Payload.Repositories {
		if repository.PublicationRecords {
			plannedLedgerRepositories = append(plannedLedgerRepositories, repository.Name)
		}
		if repository.Action != "noop" {
			plannedDeploymentRepositories = append(plannedDeploymentRepositories, repository.Name)
		}
	}
	ledgerCommitted, err := state.ValidatePlanGit(root, plan.Payload.GitRevision, plan.PlanID, plannedLedgerRepositories, plannedDeploymentRepositories)
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
	blobIdentity, err := blobStoreIdentity(manifest)
	if err != nil || plan.Payload.WorkspaceID != manifest.Workspace.ID || plan.Payload.ForgeRepository != manifest.Workspace.ForgeRepository || plan.Payload.BlobStore != manifest.BlobStore || plan.Payload.BlobStoreIdentitySHA256 != blobIdentity {
		return ApplyWorkspaceResult{}, errors.New("stale plan: blob store changed")
	}
	blobStore, err := resolveBlobStore(ctx, manifest, request.Blobs)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	generatedAt, err := time.Parse(time.RFC3339, plan.Payload.GeneratedAt)
	if err != nil {
		return ApplyWorkspaceResult{}, err
	}
	signatureTime, err := time.Parse(time.RFC3339, plan.Payload.CreatedAt)
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
		stagedManifest buildgraph.RepositoryManifest
		current        bool
		deployment     state.DeploymentRecord
		signingState   deploymentSigningState
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
		if !exists || repository.Format != planned.Format || repository.Gate != planned.Gate || !reflect.DeepEqual(repository.ApprovalKeys, planned.ApprovalKeys) || len(planned.Signing) > 1 || (len(planned.Signing) == 0) != (len(repository.SigningKeys) == 0) {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q configuration changed", planned.Name)
		}
		activeSigningKey, _, _, _, signingStateErr := repositorySigningState(repository)
		if signingStateErr != nil {
			return ApplyWorkspaceResult{}, signingStateErr
		}
		for index, signing := range planned.Signing {
			if index != 0 || signing.KeyName != activeSigningKey {
				return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q signing key changed", planned.Name)
			}
			key, exists := manifest.Keys[signing.KeyName]
			if !exists {
				return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q signing key is missing", planned.Name)
			}
			keyExpiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
			if err != nil || expiresAt.After(keyExpiresAt) {
				return ApplyWorkspaceResult{}, fmt.Errorf("repository %q plan expires after its signing key", planned.Name)
			}
			if err := validateSigningRecipeMetadata(signing, repository.Suite); err != nil {
				return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q: %w", planned.Name, err)
			}
		}
		hostIdentity, err := repositoryHostIdentity(repository)
		if err != nil || hostIdentity != planned.HostIdentitySHA256 || repository.Host != planned.Host || repository.Visibility != planned.Visibility {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q host changed", planned.Name)
		}
		hostRepository := toHostRepository(root, manifest.Workspace.ID, hostIdentity, planned.Name, repository)
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
		if capabilities.FaithfulPreview != planned.FaithfulPreview || capabilities.ConditionalCommit != planned.ConditionalCommit || capabilities.ConditionalRestore != planned.ConditionalRestore ||
			capabilities.PrivateRead != planned.PrivateRead || capabilities.CredentialBrokerIdentity != planned.CredentialBrokerIdentity {
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
		if err := state.ValidatePublicationHistory(planned.Name, ledger); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		missingBindings := missingPublicationBindings(lock, repository, ledger)
		expectedBindings := []state.PlanPublicationBinding(nil)
		if planned.PublicationRecords {
			expectedBindings = publicationBindingsForVersions(visiblePackageVersions(lock, repository))
		}
		expectedAcquisitions := planAcquisitionsForVersions(visiblePackageVersions(lock, repository))
		if !reflect.DeepEqual(planned.Acquisitions, expectedAcquisitions) {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q has inconsistent adopted acquisitions", planned.Name)
		}
		if planned.PublicationRecords != (len(planned.PublicationBindings) != 0) ||
			!reflect.DeepEqual(planned.PublicationBindings, expectedBindings) ||
			(!ledgerCommitted && planned.PublicationRecords != (len(missingBindings) != 0)) ||
			(ledgerCommitted && !planned.PublicationRecords && len(missingBindings) != 0) {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q has inconsistent publication-record effects", planned.Name)
		}
		deployment, err := state.LoadDeployment(root, planned.Name)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		desiredSigningState, err := repositoryDeploymentSigningState(repository, manifest.Keys)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		observed, err := selectedHost.Observe(ctx, hostRepository)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		plannedObserved := publishedFromPlanObservation(planned)
		trustNotBefore := time.Time{}
		if repository.SigningRotation != nil || deployment.SigningRotationPhase != "" {
			trustNotBefore, err = state.AuthoritativeDeploymentTrustSince(root, planned.Name, deployment)
			if err != nil {
				return ApplyWorkspaceResult{}, err
			}
		}
		if err := validateRepositorySigningTransition(repository, manifest.Keys, deployment, plannedObserved, now, trustNotBefore); err != nil {
			return ApplyWorkspaceResult{}, fmt.Errorf("repository %q: %w", planned.Name, err)
		}
		matchesObserved := revisionMatchesPlanObservation(observed, planned)
		managedRemote := repository.Host.Type == "s3" || repository.Host.Type == "github-pages"
		matchesApplied := planned.Action != "noop" && observed.TreeSHA256 == planned.DesiredTreeSHA256 &&
			(!managedRemote || (observed.PlanID == plan.PlanID && observed.ChangeID == planned.ChangeID && observed.ManifestSHA256 == planned.DesiredManifestSHA256))
		deploymentApplied := deployment.PlanID == plan.PlanID && deployment.ChangeID == planned.ChangeID && deployment.TreeSHA256 == planned.DesiredTreeSHA256 && deployment.ManifestSHA256 == planned.DesiredManifestSHA256 && deployment.NativeRevision == observed.NativeRevision && deploymentSigningMatches(deployment, desiredSigningState)
		deploymentCurrent := deploymentMatchesDesired(deployment, observed, planned.DesiredTreeSHA256, planned.DesiredManifestSHA256, desiredSigningState)
		if !reflect.DeepEqual(deployment, planned.ObservedDeployment) && !deploymentApplied {
			return ApplyWorkspaceResult{}, fmt.Errorf("stale plan: repository %q deployment receipt changed", planned.Name)
		}
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
		if planned.ObservedTreeSHA256 != planned.DesiredTreeSHA256 || (managedRemote && planned.ObservedManifestSHA256 != planned.DesiredManifestSHA256) || !publicationBindingsComplete(lock, repository, ledger) || !deploymentMatchesDesired(planned.ObservedDeployment, plannedObserved, planned.DesiredTreeSHA256, planned.DesiredManifestSHA256, desiredSigningState) {
			expectedAction = "update"
			if planned.ObservedRevision == "" {
				expectedAction = "create"
			}
		}
		if planned.Action != expectedAction || planned.ChangeID != planned.Name+":"+planned.DesiredTreeSHA256[:12] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan repository %q has inconsistent action metadata", planned.Name)
		}
		receiptRecovery := matchesApplied && reflect.DeepEqual(deployment, planned.ObservedDeployment)
		current := observed.TreeSHA256 == planned.DesiredTreeSHA256 && (!managedRemote || observed.ManifestSHA256 == planned.DesiredManifestSHA256) && (deploymentApplied || (planned.Action == "noop" && deploymentCurrent) || receiptRecovery)
		item := applyRepository{
			planned: planned, repository: repository, lock: lock, host: selectedHost,
			hostRepository: hostRepository, observed: observed, current: current, deployment: deployment, signingState: desiredSigningState,
		}
		if item.current && (request.StructuralOnly || planned.Action == "noop") && !(planned.Action != "noop" && len(planned.Signing) != 0) {
			prepared = append(prepared, item)
			continue
		}
		staging, err := stagingRoot(root)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		stage, err := os.MkdirTemp(staging, ".snailmail-apply-*")
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		stageOutput := filepath.Join(stage, "repository")
		staged, buildErr := buildLockedRepository(ctx, root, planned.Name, repository, lock, generatedAt, signatureTime, stageOutput, blobStore, manifest.Keys, planned.Signing, nil)
		if buildErr == nil && (staged.TreeSHA256 != planned.DesiredTreeSHA256 || staged.ManifestSHA256 != planned.DesiredManifestSHA256) {
			buildErr = errors.New("stale plan: rebuilt tree digest changed")
		}
		if buildErr == nil && !signingContentsEqual(staged.Signing, planned.Signing) {
			buildErr = errors.New("stale plan: signing recipe changed")
		}
		var stagedManifest buildgraph.RepositoryManifest
		if buildErr == nil {
			structuralRequest := request
			structuralRequest.StructuralOnly = true
			stagedManifest, buildErr = verifyStaged(ctx, repository.Format, stageOutput, structuralRequest)
		}
		if buildErr != nil {
			_ = os.RemoveAll(stage)
			for _, previous := range prepared {
				_ = os.RemoveAll(previous.stageRoot)
			}
			return ApplyWorkspaceResult{}, buildErr
		}
		item.stageRoot, item.stage, item.stagedManifest = stage, stageOutput, stagedManifest
		prepared = append(prepared, item)
	}
	defer func() {
		for _, item := range prepared {
			_ = os.RemoveAll(item.stageRoot)
		}
	}()
	authorize := func(item applyRepository) error {
		if item.planned.Action == "noop" {
			return nil
		}
		effectNow := request.currentTime()
		if !effectNow.Before(expiresAt) {
			return errors.New("plan expired before publication effect")
		}
		if item.repository.Gate == "auto" {
			return nil
		}
		if request.Gates == nil {
			return fmt.Errorf("repository %q requires %s gate evidence", item.planned.Name, item.repository.Gate)
		}
		if err := request.Gates.Authorize(ctx, gate.Requirement{
			Policy: item.repository.Gate, PlanID: plan.PlanID, Repository: item.planned.Name,
			GitRevision: plan.Payload.GitRevision, Root: root, Now: effectNow,
			ForgeRepository: plan.Payload.ForgeRepository, ApprovalKeys: item.planned.ApprovalKeys,
		}); err != nil {
			return fmt.Errorf("repository %q gate: %w", item.planned.Name, err)
		}
		return nil
	}
	for _, item := range prepared {
		if err := authorize(item); err != nil {
			return ApplyWorkspaceResult{}, err
		}
	}
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
		files, err := stagedHostFiles(item.stage, item.stagedManifest)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		if err := authorize(*item); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		item.hostStage, err = item.host.Stage(ctx, item.hostRepository, host.StageRequest{
			PlanID: plan.PlanID, ChangeID: item.planned.ChangeID, PreviousRevision: item.planned.ObservedRevision, Directory: item.stage,
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
			if _, err := verifyStaged(ctx, item.repository.Format, item.stage, request); err != nil {
				return ApplyWorkspaceResult{}, err
			}
			continue
		}
		if item.repository.Format != "pypi" {
			return ApplyWorkspaceResult{}, fmt.Errorf("host preview verification is not implemented for format %q", item.repository.Format)
		}
		access := item.hostStage.Access
		if access.Endpoint == "" {
			access.Endpoint = item.hostStage.PreviewEndpoint
		}
		if _, _, err := app.VerifyPyPIClientEndpointAccess(ctx, item.stage, access, request.Python); err != nil {
			return ApplyWorkspaceResult{}, err
		}
	}
	if !ledgerCommitted {
		for _, item := range prepared {
			if item.planned.PublicationRecords {
				if err := authorize(item); err != nil {
					return ApplyWorkspaceResult{}, err
				}
			}
		}
	}
	ledgerRepositories := plannedLedgerRepositories
	ledgerRevision := ""
	applyGitRevision := ""
	if ledgerCommitted {
		applyGitRevision, err = state.RequireCleanGit(root)
		if err != nil {
			return ApplyWorkspaceResult{}, errors.New("committed publication ledgers do not match the plan")
		}
		if len(ledgerRepositories) == 0 {
			ledgerRevision = plan.Payload.GitRevision
		} else {
			ledgerRevision, err = state.PlanLedgerRevision(root, plan.PlanID)
			if err != nil {
				return ApplyWorkspaceResult{}, err
			}
			if err := state.ValidatePublicationCommitPaths(root, ledgerRevision, ledgerRepositories); err != nil {
				return ApplyWorkspaceResult{}, err
			}
			for _, item := range prepared {
				if !item.planned.PublicationRecords {
					continue
				}
				if err := state.ValidateCommittedPublicationLedger(
					root, plan.Payload.GitRevision, ledgerRevision, item.planned.Name, plan.PlanID, item.planned.ChangeID,
					item.planned.DesiredTreeSHA256, plan.Payload.CreatedAt, activeRepositoryLock(item.lock, item.repository),
				); err != nil {
					return ApplyWorkspaceResult{}, err
				}
			}
		}
	}
	for _, item := range prepared {
		if !item.planned.PublicationRecords {
			continue
		}
		publishedLock := activeRepositoryLock(item.lock, item.repository)
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
		applyGitRevision = ledgerRevision
		if err := state.ValidatePublicationCommitPaths(root, ledgerRevision, ledgerRepositories); err != nil {
			return ApplyWorkspaceResult{}, err
		}
		for _, item := range prepared {
			if !item.planned.PublicationRecords {
				continue
			}
			if err := state.ValidateCommittedPublicationLedger(
				root, plan.Payload.GitRevision, ledgerRevision, item.planned.Name, plan.PlanID, item.planned.ChangeID,
				item.planned.DesiredTreeSHA256, plan.Payload.CreatedAt, activeRepositoryLock(item.lock, item.repository),
			); err != nil {
				return ApplyWorkspaceResult{}, err
			}
		}
	} else if !ledgerCommitted {
		ledgerRevision = plan.Payload.GitRevision
		applyGitRevision = ledgerRevision
	}
	needsPublication := false
	for _, item := range prepared {
		if !item.current {
			needsPublication = true
			break
		}
	}
	var unlockGit func()
	if needsPublication {
		unlockGit, err = state.AcquireGitRevisionLock(root, applyGitRevision)
		if err != nil {
			return ApplyWorkspaceResult{}, err
		}
		defer func() {
			if unlockGit != nil {
				unlockGit()
			}
		}()
	} else if err := state.AssertGitRevision(root, applyGitRevision); err != nil {
		return ApplyWorkspaceResult{}, err
	}
	result := ApplyWorkspaceResult{PlanID: plan.PlanID}
	deployments := make([]state.DeploymentRecord, 0, len(prepared))
	for _, item := range prepared {
		if item.current {
			result.Current++
			if !request.StructuralOnly && item.planned.Action != "noop" {
				access, accessErr := item.host.ReadAccess(ctx, item.hostRepository, item.observed)
				if accessErr != nil {
					return result, accessErr
				}
				if err := verifyCanonicalClient(ctx, root, item.repository, item.stage, access, request); err != nil {
					if item.observed.RestoreID != "" {
						if gateErr := authorize(item); gateErr != nil {
							return result, gateErr
						}
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
			if item.planned.Action != "noop" {
				deployments = append(deployments, deploymentRecordFor(item.planned, item.deployment, item.observed, item.signingState, item.observed.NativeRevision, plan.PlanID, plan.Payload.CreatedAt, request.currentTime()))
			}
			continue
		}
		if err := state.AssertGitRevision(root, applyGitRevision); err != nil {
			return result, err
		}
		if err := authorize(item); err != nil {
			return result, err
		}
		committed, err := item.host.Commit(ctx, item.hostRepository, item.hostStage, expectedRevisionFromPlan(item.planned))
		if err != nil {
			return result, err
		}
		if committed.Access.Credential != nil {
			// The deferred destroy covers the error paths below, which return
			// immediately. Successful iterations destroy their own credential at
			// the end so that a multi-repository apply does not accumulate live
			// short-lived credentials until the whole apply finishes.
			defer committed.Access.Credential.Destroy()
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
				if gateErr := authorize(item); gateErr != nil {
					return result, fmt.Errorf("canonical probe failed: %v; restore gate failed: %w", probeErr, gateErr)
				}
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
			access := committed.Access
			if access.Endpoint == "" {
				access.Endpoint = committed.CanonicalEndpoint
			}
			if probeErr := verifyCanonicalClient(ctx, root, item.repository, item.stage, access, request); probeErr != nil {
				if committed.RestoreRef != nil {
					if gateErr := authorize(item); gateErr != nil {
						return result, fmt.Errorf("canonical client probe failed: %v; restore gate failed: %w", probeErr, gateErr)
					}
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
		if err := state.AssertGitRevision(root, applyGitRevision); err != nil {
			return result, err
		}
		deployments = append(deployments, deploymentRecordFor(item.planned, item.deployment, item.observed, item.signingState, committed.Revision.NativeRevision, plan.PlanID, plan.Payload.CreatedAt, request.currentTime()))
		if committed.Access.Credential != nil {
			committed.Access.Credential.Destroy()
		}
	}
	if unlockGit != nil {
		unlockGit()
		unlockGit = nil
	}
	if request.beforeDeploymentCommit != nil {
		if err := request.beforeDeploymentCommit(); err != nil {
			return result, fmt.Errorf("before deployment receipt commit: %w", err)
		}
	}
	if _, err := state.CommitDeployments(root, plan.PlanID, applyGitRevision, deployments); err != nil {
		return result, fmt.Errorf("record successful deployments: %w", err)
	}
	return result, nil
}

func (request ApplyWorkspaceRequest) currentTime() time.Time {
	if request.clock != nil {
		return request.clock().UTC()
	}
	if !request.now.IsZero() {
		return request.now.UTC()
	}
	return time.Now().UTC()
}

func ApprovePlan(request ApprovePlanRequest) (ApprovePlanResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return ApprovePlanResult{}, err
	}
	if request.Repository == "" || request.KeyFile == "" {
		return ApprovePlanResult{}, errors.New("repository and approval private key are required")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return ApprovePlanResult{}, err
	}
	defer unlock()
	planName := request.Plan
	if planName == "" {
		planName = "snailmail.snailmail-plan.json"
	}
	if !filepath.IsAbs(planName) {
		planName = filepath.Join(root, planName)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		return ApprovePlanResult{}, err
	}
	if err := validateApplyPlan(plan); err != nil {
		return ApprovePlanResult{}, err
	}
	found := false
	var allowedKeys []string
	for _, repository := range plan.Payload.Repositories {
		if repository.Name == request.Repository && repository.Gate == "approval" && repository.Action != "noop" {
			found = true
			allowedKeys = repository.ApprovalKeys
			break
		}
	}
	if !found {
		return ApprovePlanResult{}, fmt.Errorf("repository %q has no pending approval gate in this plan", request.Repository)
	}
	now := request.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresIn := request.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 30 * time.Minute
	}
	planExpires, err := time.Parse(time.RFC3339, plan.Payload.ExpiresAt)
	if err != nil || !now.Before(planExpires) {
		return ApprovePlanResult{}, errors.New("plan has expired")
	}
	expiresAt := now.Add(expiresIn)
	if expiresAt.After(planExpires) {
		expiresAt = planExpires
	}
	output := request.Output
	if output == "" {
		output = planName + ".approvals.json"
	} else if !filepath.IsAbs(output) {
		output, err = state.WorkspacePath(root, filepath.ToSlash(output))
		if err != nil {
			return ApprovePlanResult{}, err
		}
	}
	evidence := gate.ApprovalFile{SchemaVersion: gate.ApprovalSchema}
	if existing, loadErr := gate.LoadApprovals(output); loadErr == nil {
		evidence = existing
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return ApprovePlanResult{}, loadErr
	}
	filtered := evidence.Approvals[:0]
	for _, approval := range evidence.Approvals {
		if approval.PlanID != plan.PlanID || approval.Repository != request.Repository {
			filtered = append(filtered, approval)
		}
	}
	approval, publicKey, err := gate.SignApproval(request.KeyFile, plan.PlanID, request.Repository, expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return ApprovePlanResult{}, err
	}
	allowed := false
	for _, candidate := range allowedKeys {
		allowed = allowed || candidate == publicKey
	}
	if !allowed {
		return ApprovePlanResult{}, errors.New("approval private key is not authorized by the reviewed plan")
	}
	evidence.Approvals = append(filtered, approval)
	sort.Slice(evidence.Approvals, func(left, right int) bool {
		if evidence.Approvals[left].PlanID != evidence.Approvals[right].PlanID {
			return evidence.Approvals[left].PlanID < evidence.Approvals[right].PlanID
		}
		return evidence.Approvals[left].Repository < evidence.Approvals[right].Repository
	})
	if err := gate.WriteApprovals(output, evidence); err != nil {
		return ApprovePlanResult{}, err
	}
	return ApprovePlanResult{PlanID: plan.PlanID, Output: output, Approver: approval.Approver}, nil
}

func RenderStatus(request RenderStatusRequest) (RenderStatusResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return RenderStatusResult{}, err
	}
	revision, err := state.RequireCleanGit(root)
	if err != nil {
		return RenderStatusResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return RenderStatusResult{}, err
	}
	manifestPath, err := state.WorkspacePath(root, state.ManifestFilename)
	if err != nil {
		return RenderStatusResult{}, err
	}
	manifestDigest, err := state.HashFile(manifestPath)
	if err != nil {
		return RenderStatusResult{}, err
	}
	names := make([]string, 0, len(manifest.Repositories))
	for name := range manifest.Repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	inputs := make([]statusrenderer.InputRepository, 0, len(names))
	pending := make(map[string]bool)
	planName := request.Plan
	if planName == "" {
		planName = "snailmail.snailmail-plan.json"
	}
	if !filepath.IsAbs(planName) {
		planName = filepath.Join(root, planName)
	}
	if planned, planErr := state.LoadPlan(planName); planErr == nil {
		now := request.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		expiresAt, expiryErr := time.Parse(time.RFC3339, planned.Payload.ExpiresAt)
		if validateApplyPlan(planned) == nil && expiryErr == nil && now.Before(expiresAt) && planned.Payload.GitRevision == revision && planned.Payload.ManifestSHA256 == manifestDigest && planned.Payload.WorkspaceID == manifest.Workspace.ID {
			for _, repository := range planned.Payload.Repositories {
				if repository.Action != "noop" && repository.Gate != "auto" {
					pending[repository.Name] = true
				}
			}
		}
	} else if !errors.Is(planErr, os.ErrNotExist) {
		return RenderStatusResult{}, fmt.Errorf("load pending status plan: %w", planErr)
	}
	for _, name := range names {
		repository := manifest.Repositories[name]
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return RenderStatusResult{}, err
		}
		records, err := state.LoadLedger(root, name)
		if err != nil {
			return RenderStatusResult{}, err
		}
		deployment, err := state.LoadDeployment(root, name)
		if err != nil {
			return RenderStatusResult{}, err
		}
		inputs = append(inputs, statusrenderer.InputRepository{Name: name, Config: repository, Lock: lock, Records: records, Deployment: deployment, Pending: pending[name]})
	}
	output, err := statusrenderer.Render(manifest.Workspace.Name, revision, inputs)
	if err != nil {
		return RenderStatusResult{}, err
	}
	destination := request.Output
	if destination == "" {
		destination = "site"
	}
	if !filepath.IsAbs(destination) {
		destination, err = state.WorkspacePath(root, filepath.ToSlash(destination))
		if err != nil {
			return RenderStatusResult{}, err
		}
	}
	if err := publishStatusDirectory(destination, output); err != nil {
		return RenderStatusResult{}, err
	}
	return RenderStatusResult{Output: destination, Repositories: len(inputs)}, nil
}

func publishStatusDirectory(destination string, output statusrenderer.Output) error {
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".snailmail-status-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for name, content := range map[string][]byte{"index.html": output.HTML, "status.json": output.JSON, ".snailmail-status": []byte("v1\n")} {
		if err := os.WriteFile(filepath.Join(staging, name), content, 0o644); err != nil {
			return err
		}
	}
	backup := ""
	if _, err := os.Lstat(destination); err == nil {
		marker := filepath.Join(destination, ".snailmail-status")
		if content, markerErr := os.ReadFile(marker); markerErr != nil || string(content) != "v1\n" {
			return fmt.Errorf("refusing to replace unmanaged status directory %q", destination)
		}
		backup, err = os.MkdirTemp(parent, ".snailmail-status-backup-*")
		if err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(staging, destination); err != nil {
		if _, backupErr := os.Lstat(backup); backupErr == nil {
			_ = os.Rename(backup, destination)
		}
		return err
	}
	if backup != "" {
		return os.RemoveAll(backup)
	}
	return nil
}

func verifyCanonicalClient(ctx context.Context, root string, repository state.Repository, staged string, access host.ClientAccess, request ApplyWorkspaceRequest) error {
	if repository.Host.Type == "local" {
		output, err := state.WorkspacePath(root, repository.Host.Path)
		if err != nil {
			return err
		}
		_, err = verifyStaged(ctx, repository.Format, output, request)
		return err
	}
	if repository.Format != "pypi" {
		return fmt.Errorf("canonical client verification is not implemented for format %q", repository.Format)
	}
	_, _, err := app.VerifyPyPIClientEndpointAccess(ctx, staged, access, request.Python)
	return err
}

func buildLockedRepository(ctx context.Context, root, name string, repository state.Repository, lock state.RepositoryLock, generatedAt, signatureTime time.Time, output string, blobStore blob.Store, keys map[string]state.SigningKey, plannedSigning []state.PlanSigning, signers signer.Resolver) (BuildResult, error) {
	staging, err := stagingRoot(root)
	if err != nil {
		return BuildResult{}, err
	}
	input, err := os.MkdirTemp(staging, ".snailmail-locked-input-*")
	if err != nil {
		return BuildResult{}, err
	}
	defer os.RemoveAll(input)
	active := visiblePackageVersions(lock, repository)
	for _, packageVersion := range active {
		for _, locked := range packageVersion.Blobs {
			blob, source, err := state.EnsureBlob(ctx, root, repository.Format, locked, blobStore)
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
	if output == "" {
		temporary, err := os.MkdirTemp(staging, ".snailmail-plan-build-*")
		if err != nil {
			return BuildResult{}, err
		}
		defer os.RemoveAll(temporary)
		output = filepath.Join(temporary, "repository")
	}
	if len(active) == 0 {
		var artifact domain.RepositoryArtifact
		switch repository.Format {
		case "pypi":
			if len(plannedSigning) != 0 || len(repository.SigningKeys) != 0 {
				return BuildResult{}, errors.New("PyPI repository cannot contain repository signing effects")
			}
			artifact, err = pypi.Build(nil)
		case "deb":
			artifact, err = debformat.Build(nil, debformat.BuildOptions{
				Suite: repository.Suite, Component: repository.Component, Architectures: repository.Architectures, GeneratedAt: generatedAt,
			})
			if err == nil {
				var signing []state.PlanSigning
				artifact, signing, err = applyRepositorySigning(ctx, root, repository, keys, artifact, signatureTime, plannedSigning, signers)
				if err == nil {
					result, materializeErr := materializeLockedArtifact(ctx, output, generatedAt, artifact)
					result.Signing = signing
					return result, materializeErr
				}
			}
		case "helm":
			if len(plannedSigning) != 0 || len(repository.SigningKeys) != 0 {
				return BuildResult{}, errors.New("Helm repository signing is not implemented")
			}
			artifact, err = helmformat.Build(nil, helmformat.BuildOptions{GeneratedAt: generatedAt})
		default:
			return BuildResult{}, fmt.Errorf("unsupported repository format %q", repository.Format)
		}
		if err != nil {
			return BuildResult{}, err
		}
		return materializeLockedArtifact(ctx, output, generatedAt, artifact)
	}
	switch repository.Format {
	case "pypi":
		if len(plannedSigning) != 0 || len(repository.SigningKeys) != 0 {
			return BuildResult{}, errors.New("PyPI repository cannot contain repository signing effects")
		}
		return BuildPyPI(ctx, BuildPyPIRequest{Input: input, Output: output, GeneratedAt: generatedAt})
	case "deb":
		var resolved []state.PlanSigning
		result, err := buildDeb(ctx, BuildDebRequest{Input: input, Output: output, Suite: repository.Suite, Component: repository.Component, Architectures: repository.Architectures, GeneratedAt: generatedAt}, func(artifact domain.RepositoryArtifact) (domain.RepositoryArtifact, error) {
			signed, signing, err := applyRepositorySigning(ctx, root, repository, keys, artifact, signatureTime, plannedSigning, signers)
			resolved = signing
			return signed, err
		})
		result.Signing = resolved
		return result, err
	case "helm":
		if len(plannedSigning) != 0 || len(repository.SigningKeys) != 0 {
			return BuildResult{}, errors.New("Helm repository signing is not implemented")
		}
		return BuildHelm(ctx, BuildHelmRequest{Input: input, Output: output, GeneratedAt: generatedAt})
	default:
		return BuildResult{}, fmt.Errorf("unsupported repository format %q", repository.Format)
	}
}

func materializeLockedArtifact(ctx context.Context, output string, generatedAt time.Time, artifact domain.RepositoryArtifact) (BuildResult, error) {
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, nil); err != nil {
		return BuildResult{}, err
	}
	manifestSHA256, err := state.HashFile(filepath.Join(output, buildgraph.ManifestFilename))
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{Format: manifest.Format, Output: output, TreeSHA256: manifest.TreeSHA256, ManifestSHA256: manifestSHA256}, nil
}

func visiblePackageVersions(lock state.RepositoryLock, repository state.Repository) []state.PackageVersion {
	active := make(map[string]bool)
	for _, placement := range lock.Placement {
		if placement.Track != repository.Track {
			continue
		}
		if repository.Format == "deb" {
			if placement.Distro != repository.Suite {
				continue
			}
		} else if placement.Distro != "" {
			continue
		}
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

func activeRepositoryLock(lock state.RepositoryLock, repository state.Repository) state.RepositoryLock {
	lock.PackageVersion = visiblePackageVersions(lock, repository)
	return lock
}

func publicationBindingsComplete(lock state.RepositoryLock, repository state.Repository, records []state.PublicationRecord) bool {
	return len(missingPublicationBindings(lock, repository, records)) == 0
}

func missingPublicationBindings(lock state.RepositoryLock, repository state.Repository, records []state.PublicationRecord) []state.PlanPublicationBinding {
	published := make(map[string][]string)
	for _, record := range records {
		digests := append([]string(nil), record.BlobSHA256...)
		sort.Strings(digests)
		published[record.Package+"\x00"+record.Version] = digests
	}
	var missing []state.PlanPublicationBinding
	for _, version := range visiblePackageVersions(lock, repository) {
		digests := make([]string, 0, len(version.Blobs))
		for _, artifact := range version.Blobs {
			digests = append(digests, artifact.SHA256)
		}
		sort.Strings(digests)
		if !reflect.DeepEqual(published[version.Package+"\x00"+version.Version], digests) {
			missing = append(missing, state.PlanPublicationBinding{Package: version.Package, Version: version.Version, BlobSHA256: digests})
		}
	}
	return missing
}

func publicationBindingsForVersions(versions []state.PackageVersion) []state.PlanPublicationBinding {
	bindings := make([]state.PlanPublicationBinding, 0, len(versions))
	for _, version := range versions {
		digests := make([]string, 0, len(version.Blobs))
		for _, artifact := range version.Blobs {
			digests = append(digests, artifact.SHA256)
		}
		sort.Strings(digests)
		bindings = append(bindings, state.PlanPublicationBinding{Package: version.Package, Version: version.Version, BlobSHA256: digests})
	}
	return bindings
}

func planAcquisitionsForVersions(versions []state.PackageVersion) []state.PlanAcquisition {
	var acquisitions []state.PlanAcquisition
	for _, version := range versions {
		for _, locked := range version.Blobs {
			if locked.Origin == nil {
				continue
			}
			acquisitions = append(acquisitions, state.PlanAcquisition{
				Package: version.Package, Version: version.Version, Filename: locked.Filename,
				SHA256: locked.SHA256, OriginURL: locked.Origin.URL,
			})
		}
	}
	sort.Slice(acquisitions, func(left, right int) bool {
		if acquisitions[left].Package != acquisitions[right].Package {
			return acquisitions[left].Package < acquisitions[right].Package
		}
		if acquisitions[left].Version != acquisitions[right].Version {
			return acquisitions[left].Version < acquisitions[right].Version
		}
		if acquisitions[left].Filename != acquisitions[right].Filename {
			return acquisitions[left].Filename < acquisitions[right].Filename
		}
		return acquisitions[left].SHA256 < acquisitions[right].SHA256
	})
	return acquisitions
}

func verifyStaged(ctx context.Context, format, repository string, request ApplyWorkspaceRequest) (buildgraph.RepositoryManifest, error) {
	switch format {
	case "pypi":
		result, err := VerifyPyPI(ctx, VerifyPyPIRequest{Repository: repository, Python: request.Python, StructuralOnly: request.StructuralOnly})
		return result.Manifest, err
	case "deb":
		result, err := VerifyDeb(ctx, VerifyDebRequest{Repository: repository, Runner: request.Runner, Image: request.DebianImage, MaxWorkspaceBytes: request.MaxWorkspaceBytes, StructuralOnly: request.StructuralOnly})
		return result.Manifest, err
	case "helm":
		result, err := VerifyHelm(ctx, VerifyHelmRequest{Repository: repository, Runner: request.Runner, Image: request.HelmImage, StructuralOnly: request.StructuralOnly})
		return result.Manifest, err
	default:
		return buildgraph.RepositoryManifest{}, fmt.Errorf("unsupported repository format %q", format)
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

// StageDirectoryEnvironment overrides where build and stage trees are created.
const StageDirectoryEnvironment = "SNAILMAIL_STAGE_DIR"

// stagingRoot returns the directory that holds temporary build and stage trees.
//
// These default to the workspace rather than TMPDIR for two reasons. TMPDIR is
// commonly a tmpfs, so a multi-gigabyte repository tree would be held in RAM,
// and it is a different filesystem from the local CAS, so linking artifacts
// into a build input falls back to copying every byte. Staging beside the CAS
// keeps the links and the bytes on disk.
func stagingRoot(root string) (string, error) {
	directory := filepath.Join(root, ".snailmail", "stage")
	if override := strings.TrimSpace(os.Getenv(StageDirectoryEnvironment)); override != "" {
		if !filepath.IsAbs(override) {
			return "", fmt.Errorf("%s must be an absolute path", StageDirectoryEnvironment)
		}
		directory = override
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	return directory, nil
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

func optionalSigningKeys(name string) []string {
	if name == "" {
		return nil
	}
	return []string{name}
}

type localHostResolver struct{}

func (localHostResolver) Resolve(_ context.Context, repository host.Repository) (host.Host, error) {
	if repository.Type != "local" {
		return nil, fmt.Errorf("host type %q requires a configured host resolver", repository.Type)
	}
	return localhost.New(), nil
}

func toHostRepository(root, workspaceID, hostIdentity, name string, repository state.Repository) host.Repository {
	canonicalEndpoint := repository.Host.CanonicalEndpoint
	if repository.Host.Type == "local" {
		canonicalEndpoint = repository.Host.Path
	}
	return host.Repository{
		Name: name, WorkspaceID: workspaceID, HostIdentity: hostIdentity, Format: repository.Format, Type: repository.Host.Type,
		Visibility: repository.Visibility, WorkspaceRoot: root, Path: repository.Host.Path,
		Bucket: repository.Host.Bucket, Prefix: repository.Host.Prefix, Region: repository.Host.Region,
		Endpoint: repository.Host.Endpoint, CanonicalEndpoint: canonicalEndpoint,
		UsePathStyle: repository.Host.UsePathStyle,
		ReadAuth:     repository.Host.ReadAuth, CredentialBroker: repository.Host.CredentialBroker,
		RemoteRepository: repository.Host.Repository, Branch: repository.Host.Branch,
		PreviewRepository: repository.Host.PreviewRepository, PreviewBranch: repository.Host.PreviewBranch,
		PreviewEndpoint: repository.Host.PreviewEndpoint,
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
	if (repository.Host.Type != "s3" && repository.Host.Type != "github-pages") || repository.Format != "pypi" {
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

// stagedHostFiles enumerates a stage that this apply has already verified in
// full. The host verifies the directory again when it stages it, so the file
// list is a convenience here rather than the integrity boundary.
func stagedHostFiles(directory string, manifest buildgraph.RepositoryManifest) ([]host.File, error) {
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
		if len(repository.SigningKeys) != 0 {
			return []string{
				filepath.ToSlash(filepath.Join("dists", repository.Suite, "InRelease")),
				filepath.ToSlash(filepath.Join("dists", repository.Suite, "Release")),
				filepath.ToSlash(filepath.Join("dists", repository.Suite, "Release.gpg")),
			}
		}
		return []string{filepath.ToSlash(filepath.Join("dists", repository.Suite, "Release"))}
	default:
		return nil
	}
}

func validateApplyPlan(plan state.Plan) error {
	if !validSHA256(plan.Payload.ManifestSHA256) {
		return errors.New("plan has an invalid manifest digest")
	}
	if plan.Payload.KnowledgeSHA256 != knowledge.SigningDigest() {
		return errors.New("plan signing compatibility knowledge is incompatible")
	}
	if !validSHA256(plan.Payload.WorkspaceID) || !validSHA256(plan.Payload.BlobStoreIdentitySHA256) || state.ValidateBlobStore(plan.Payload.BlobStore) != nil {
		return errors.New("plan has an invalid blob store binding")
	}
	plannedBlobIdentity, err := blobIdentity(plan.Payload.WorkspaceID, plan.Payload.BlobStore)
	if err != nil || plannedBlobIdentity != plan.Payload.BlobStoreIdentitySHA256 {
		return errors.New("plan blob store identity does not match its configuration")
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
		if repository.PublicationRecords && repository.Action == "noop" {
			return fmt.Errorf("plan repository %q cannot record publications for a noop", repository.Name)
		}
		if repository.PublicationRecords != (len(repository.PublicationBindings) != 0) {
			return fmt.Errorf("plan repository %q has inconsistent publication bindings", repository.Name)
		}
		previousBinding := ""
		for _, binding := range repository.PublicationBindings {
			if binding.Package == "" || binding.Version == "" || len(binding.BlobSHA256) == 0 {
				return fmt.Errorf("plan repository %q has invalid publication binding", repository.Name)
			}
			identity := binding.Package + "\x00" + binding.Version
			if identity <= previousBinding {
				return fmt.Errorf("plan repository %q has unsorted publication bindings", repository.Name)
			}
			previousBinding = identity
			previous := ""
			for _, digest := range binding.BlobSHA256 {
				if !validSHA256(digest) || digest <= previous {
					return fmt.Errorf("plan repository %q has invalid publication binding digests", repository.Name)
				}
				previous = digest
			}
		}
		previousAcquisition := ""
		for _, acquisition := range repository.Acquisitions {
			identity := acquisition.Package + "\x00" + acquisition.Version + "\x00" + acquisition.Filename + "\x00" + acquisition.SHA256
			if acquisition.Package == "" || acquisition.Version == "" || acquisition.Filename == "" || !validSHA256(acquisition.SHA256) || identity <= previousAcquisition ||
				state.ValidateArtifactOrigin(state.ArtifactOrigin{Kind: "https", URL: acquisition.OriginURL}) != nil {
				return fmt.Errorf("plan repository %q has invalid adopted acquisition", repository.Name)
			}
			previousAcquisition = identity
		}
		if err := state.ValidateGateConfiguration(repository.Gate, repository.ApprovalKeys, plan.Payload.ForgeRepository); err != nil {
			return fmt.Errorf("plan repository %q gate: %w", repository.Name, err)
		}
		if err := state.ValidateDeploymentRecord(repository.ObservedDeployment, repository.Name); err != nil {
			return fmt.Errorf("plan repository %q has invalid deployment observation", repository.Name)
		}
		if !validSHA256(repository.LockSHA256) || !validSHA256(repository.DesiredTreeSHA256) ||
			!validSHA256(repository.HostIdentitySHA256) ||
			(repository.ObservedTreeSHA256 != "" && !validSHA256(repository.ObservedTreeSHA256)) {
			return fmt.Errorf("plan repository %q has an invalid digest", repository.Name)
		}
		if len(repository.Signing) > 1 {
			return fmt.Errorf("plan repository %q has unsupported dual signing", repository.Name)
		}
		for _, signing := range repository.Signing {
			if repository.Format != "deb" || signing.KeyName == "" || signing.Algorithm != signer.AlgorithmOpenPGPRSA4096 || !validFingerprint(signing.Fingerprint) ||
				!validSHA256(signing.PublicKeySHA256) || !validSHA256(signing.PublicArmorSHA256) || !validSHA256(signing.RecipeSHA256) || signing.PublicKeyPath == "" || signing.PublicArmorPath == "" || len(signing.Nodes) != 2 {
				return fmt.Errorf("plan repository %q has invalid signing metadata", repository.Name)
			}
			if _, err := time.Parse(time.RFC3339, signing.SignatureTime); err != nil {
				return fmt.Errorf("plan repository %q has invalid signature time", repository.Name)
			}
			if err := validateSigningRecipeMetadata(signing, ""); err != nil {
				return fmt.Errorf("plan repository %q: %w", repository.Name, err)
			}
			ids := []string{"deb-inrelease", "deb-release-gpg"}
			for index, scheme := range []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached} {
				node := signing.Nodes[index]
				if node.ID != ids[index] || node.Kind != "sign" || len(node.DependsOn) == 0 || node.Scheme != scheme || !validSHA256(node.PayloadSHA256) || !validSHA256(node.ContentSHA256) || node.OutputPath == "" || len(node.Content) == 0 || len(node.Content) > 8<<20 {
					return fmt.Errorf("plan repository %q has invalid signing response", repository.Name)
				}
			}
		}
		if repository.Host.Type != "local" && repository.Host.Type != "s3" && repository.Host.Type != "github-pages" {
			return fmt.Errorf("plan repository %q has unsupported host type %q", repository.Name, repository.Host.Type)
		}
		if repository.CanonicalEndpoint == "" {
			return fmt.Errorf("plan repository %q has no canonical endpoint", repository.Name)
		}
		if (repository.Host.Type == "s3" || repository.Host.Type == "github-pages") && !validSHA256(repository.InstallDocSHA256) {
			return fmt.Errorf("plan repository %q has an invalid install document digest", repository.Name)
		}
		if (repository.Host.Type == "s3" || repository.Host.Type == "github-pages") && !validSHA256(repository.DesiredManifestSHA256) {
			return fmt.Errorf("plan repository %q has an invalid desired manifest digest", repository.Name)
		}
		if repository.Visibility == "private" && !repository.PrivateRead {
			return fmt.Errorf("plan repository %q lacks private read capability", repository.Name)
		}
		if repository.Visibility == "private" && !validSHA256(repository.CredentialBrokerIdentity) {
			return fmt.Errorf("plan repository %q has an invalid credential broker identity", repository.Name)
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

func validFingerprint(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20 && value == strings.ToLower(value)
}

func resolveBlobStore(ctx context.Context, manifest state.Manifest, resolver blob.Resolver) (blob.Store, error) {
	configuration := state.BlobConfiguration(manifest)
	if configuration.Type == "local" {
		return nil, nil
	}
	if resolver == nil {
		return nil, errors.New("remote blob store resolver is required")
	}
	store, err := resolver.Resolve(ctx, configuration)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("remote blob store resolver returned no store")
	}
	return store, nil
}

func blobStoreIdentity(manifest state.Manifest) (string, error) {
	return blobIdentity(manifest.Workspace.ID, manifest.BlobStore)
}

func blobIdentity(workspaceID string, configuration state.BlobStoreConfig) (string, error) {
	encoded, err := json.Marshal(struct {
		WorkspaceID string                `json:"workspace_id"`
		BlobStore   state.BlobStoreConfig `json:"blob_store"`
	}{WorkspaceID: workspaceID, BlobStore: configuration})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func blobref(locked state.LockedBlob) blob.Ref {
	return blob.Ref{SHA256: locked.SHA256, Size: locked.Size}
}

func deploymentMatchesDesired(deployment state.DeploymentRecord, observed host.PublishedRevision, treeSHA256, manifestSHA256 string, signing deploymentSigningState) bool {
	if !validSHA256(treeSHA256) || deployment.TreeSHA256 != treeSHA256 || deployment.ManifestSHA256 != manifestSHA256 ||
		deployment.NativeRevision == "" || deployment.NativeRevision != observed.NativeRevision ||
		deployment.ChangeID != deployment.Repository+":"+treeSHA256[:12] || !deploymentSigningMatches(deployment, signing) {
		return false
	}
	return true
}

func deploymentSigningMatches(deployment state.DeploymentRecord, signing deploymentSigningState) bool {
	return deployment.ActiveSigningFingerprint == signing.active && reflect.DeepEqual(deployment.TrustedSigningFingerprints, signing.trusted) && deployment.SigningRotationPhase == signing.phase &&
		deployment.SigningKeyringPath == signing.keyring && deployment.SigningMinimumRefreshSeconds == signing.minimumRefresh && (signing.active == "" || deployment.TrustSince != "")
}

func publishedFromPlanObservation(planned state.PlanRepository) host.PublishedRevision {
	return host.PublishedRevision{
		NativeRevision: planned.ObservedRevision, TreeSHA256: planned.ObservedTreeSHA256,
		PlanID: planned.ObservedPlanID, ChangeID: planned.ObservedChangeID,
		ReleaseSHA256: planned.ObservedReleaseSHA256, ManifestSHA256: planned.ObservedManifestSHA256,
		RestoreID: planned.ObservedRestoreID, RestoreSHA256: planned.ObservedRestoreSHA256,
		RestoreRootSHA256: planned.ObservedRestoreRootSHA256,
	}
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
