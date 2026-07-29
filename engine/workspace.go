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
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/gate"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/knowledge"
	"github.com/shellcell/snailmail/internal/state"
	statusrenderer "github.com/shellcell/snailmail/internal/status"
	"github.com/shellcell/snailmail/signer"
	"github.com/shellcell/snailmail/source"
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
	// Name and Version supply identity for a format whose artifacts carry none,
	// such as a release tarball. Formats that name themselves reject them.
	Name    string
	Version string
	Blobs   blob.Resolver
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
	Repository string   `json:"repository"`
	Added      int      `json:"added"`
	Skipped    int      `json:"skipped"`
	Packages   []string `json:"packages"`
}

type PlanWorkspaceRequest struct {
	Root string
	// Sources fetches an artifact back from the origin its lock records, for a
	// workspace whose blobs are not in the clone and not in a blob store.
	Sources          source.Fetcher
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
	PlanID       string               `json:"plan_id"`
	Output       string               `json:"output"`
	Changes      int                  `json:"changes"`
	Acquisitions []PlannedAcquisition `json:"acquisitions"`
}

type PlannedAcquisition struct {
	Repository string `json:"repository"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	Filename   string `json:"filename"`
	SHA256     string `json:"sha256"`
	OriginURL  string `json:"origin_url"`
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
	PlanID   string `json:"plan_id"`
	Output   string `json:"output"`
	Approver string `json:"approver"`
}

type RenderStatusRequest struct {
	Root   string
	Output string
	Plan   string
	Now    time.Time
}

type RenderStatusResult struct {
	Output       string `json:"output"`
	Repositories int    `json:"repositories"`
}

type ApplyWorkspaceRequest struct {
	Root           string
	Sources        source.Fetcher
	Plan           string
	now            time.Time
	clock          func() time.Time
	StructuralOnly bool
	Python         string
	Runner         string
	DebianImage    string
	HelmImage      string
	RPMImage       string
	APKImage       string
	// VerifyAllVersions installs every retained version with a real client
	// rather than the newest and oldest of each package on each architecture.
	VerifyAllVersions      bool
	MaxWorkspaceBytes      int64
	Hosts                  host.Resolver
	Blobs                  blob.Resolver
	Gates                  gate.Evaluator
	beforeDeploymentCommit func() error
}

type ApplyWorkspaceResult struct {
	PlanID  string `json:"plan_id"`
	Applied int    `json:"applied"`
	Current int    `json:"current"`
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
	selectedFormat, err := formats.For(repository.Format)
	if err != nil {
		return AddArtifactsResult{}, err
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
		// What the operator typed goes to the format unfiltered. IdentityFor is
		// for replaying an identity a lock already records; using it here would
		// drop --name and --version for formats that read identity from bytes,
		// turning a rejection an operator needs to see into a silent no-op.
		blob, err := state.PutArtifact(root, repository.Format, artifact,
			formats.Identity{Name: request.Name, Version: request.Version})
		if err != nil {
			return AddArtifactsResult{}, err
		}
		if blobStore != nil {
			locked := state.ToLockedBlob(blob)
			_, name, err := state.LoadBlob(root, repository.Format, locked,
				formats.IdentityFor(selectedFormat, blob.Facts.Name, blob.Facts.Version))
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
		distro := defaultPlacementDistro(repository, "")
		packageName := nativePackageName(repository.Format, blob.Facts.Name)
		toLock := state.ToLockedBlob(blob)
		toLock.Added = state.LockTime(time.Now())
		added, err := state.AddBlob(&lock, repository.Format, request.Track, distro, toLock, packageName, blob.Facts.Version)
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
		migratingFormat, err := formats.For(repository.Format)
		if err != nil {
			return err
		}
		for _, packageVersion := range lock.PackageVersion {
			for _, locked := range packageVersion.Blobs {
				if seen[locked.SHA256] {
					continue
				}
				seen[locked.SHA256] = true
				_, blobName, err := state.EnsureBlob(ctx, root, repository.Format, locked, sourceStore,
					formats.IdentityFor(migratingFormat, packageVersion.Package, packageVersion.Version))
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
		// Not the wall clock: generated content is dated by when the desired
		// state last changed, so replanning unchanged inputs renders the same
		// bytes and a publication with nothing to do does nothing.
		committedAt, err := state.DesiredStateTime(ctx, root)
		if err != nil {
			return PlanWorkspaceResult{}, err
		}
		generatedAt = committedAt
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
		desired, err := buildLockedRepository(ctx, root, name, repository, lock, generatedAt, createdAt, "", blobStore, manifest.Keys, nil, request.Signers, request.Sources)
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

// applyRepository is one repository's state as apply carries it from plan
// revalidation through staging to publication.
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

// restoreFailedPublication compensates a failed verification by asking the host
// to put back the revision this change displaced. Restoring is itself a
// publication effect, so it is gated exactly like the change that failed.
func restoreFailedPublication(ctx context.Context, item applyRepository, reference host.RestoreRef, expected host.ExpectedRevision, authorize func(applyRepository) error) error {
	if err := authorize(item); err != nil {
		return fmt.Errorf("restore gate failed: %w", err)
	}
	// The restore must still run when the caller's context is already done,
	// otherwise an interrupt would leave the failed tree published.
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if _, err := item.host.Restore(restoreCtx, item.hostRepository, reference, expected); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	return nil
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
	var prepared []applyRepository
	hosts := request.Hosts
	if hosts == nil {
		hosts = localHostResolver{}
	}
	seenRepositories := make(map[string]bool)
	preparation := &applyPreparation{
		ctx: ctx, root: root, request: request, plan: plan, manifest: manifest, hosts: hosts,
		blobStore: blobStore, now: now, expiresAt: expiresAt, generatedAt: generatedAt,
		signatureTime: signatureTime, ledgerCommitted: ledgerCommitted,
	}
	for _, planned := range plan.Payload.Repositories {
		if seenRepositories[planned.Name] {
			return ApplyWorkspaceResult{}, fmt.Errorf("plan contains duplicate repository %q", planned.Name)
		}
		seenRepositories[planned.Name] = true
		item, err := preparation.prepareRepository(planned)
		if err != nil {
			for _, previous := range prepared {
				_ = os.RemoveAll(previous.stageRoot)
			}
			return ApplyWorkspaceResult{}, err
		}
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
		if !host.Supports(item.hostRepository.Type, item.repository.Format).RemoteClientVerification {
			return ApplyWorkspaceResult{}, fmt.Errorf("host preview verification is not implemented for format %q on host %q",
				item.repository.Format, item.hostRepository.Type)
		}
		access := item.hostStage.Access
		if access.Endpoint == "" {
			access.Endpoint = item.hostStage.PreviewEndpoint
		}
		if access.Endpoint == "" {
			// No preview site was configured, so there is no endpoint to install
			// from before production changes. The staged tree is still checked by
			// a real client, exactly as a local host is; what is not checked is
			// that the host serves it correctly, which is what a preview buys.
			if _, err := verifyStaged(ctx, item.repository.Format, item.stage, request); err != nil {
				return ApplyWorkspaceResult{}, err
			}
			continue
		}
		if err := verifyEndpointClient(ctx, item.repository, item.stage, access, request); err != nil {
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
	execution := &applyExecution{
		ctx: ctx, root: root, request: request, plan: plan,
		applyGitRevision: applyGitRevision, authorize: authorize, result: result,
	}
	for _, item := range prepared {
		var err error
		if item.current {
			err = execution.verifyCurrent(item)
		} else {
			err = execution.publish(item)
		}
		if err != nil {
			return execution.result, err
		}
	}
	result, deployments = execution.result, execution.deployments
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
	return verifyEndpointClient(ctx, repository, staged, access, request)
}

// verifyEndpointClient runs the ecosystem's official client against the tree a
// host is serving. Each format needs its own client, so the pair must be
// declared before the attempt rather than discovered by a nil dispatch.
func verifyEndpointClient(ctx context.Context, repository state.Repository, staged string, access host.ClientAccess, request ApplyWorkspaceRequest) error {
	if !host.Supports(repository.Host.Type, repository.Format).RemoteClientVerification {
		return fmt.Errorf("client verification is not implemented for format %q on host %q",
			repository.Format, repository.Host.Type)
	}
	switch repository.Format {
	case "pypi":
		_, _, err := app.VerifyPyPIClientEndpointAccess(ctx, staged, access, request.Python)
		return err
	case "deb":
		image := request.DebianImage
		if image == "" {
			image = DefaultDebianVerificationImage
		}
		maximum := request.MaxWorkspaceBytes
		if maximum == 0 {
			maximum = 4 << 30
		}
		_, _, err := app.VerifyDebClientEndpointAccess(ctx, staged, access, request.Runner, image, maximum, versionScope(request.VerifyAllVersions))
		return err
	case "raw":
		_, _, err := app.VerifyRawClientEndpointAccess(ctx, staged, access)
		return err
	default:
		return fmt.Errorf("client verification is not implemented for format %q", repository.Format)
	}
}

func buildLockedRepository(ctx context.Context, root, name string, repository state.Repository, lock state.RepositoryLock, generatedAt, signatureTime time.Time, output string, blobStore blob.Store, keys map[string]state.SigningKey, plannedSigning []state.PlanSigning, signers signer.Resolver, fetcher source.Fetcher) (BuildResult, error) {
	staging, err := stagingRoot(root)
	if err != nil {
		return BuildResult{}, err
	}
	input, err := os.MkdirTemp(staging, ".snailmail-locked-input-*")
	if err != nil {
		return BuildResult{}, err
	}
	selected, err := formats.For(repository.Format)
	if err != nil {
		return BuildResult{}, err
	}
	defer os.RemoveAll(input)
	active := visiblePackageVersions(lock, repository)
	// Formats that read identity out of the bytes are rebuilt from the input
	// directory. Raw cannot be: its identity was supplied by an operator and
	// lives in the lock, so the blobs are carried through directly.
	var lockedBlobs []domain.Blob
	lockedSources := make(map[string]string)
	for _, packageVersion := range active {
		for _, locked := range packageVersion.Blobs {
			blob, source, err := ensureBlob(ctx, root, repository.Format, locked, blobStore,
				formats.IdentityFor(selected, packageVersion.Package, packageVersion.Version), fetcher)
			if err != nil {
				return BuildResult{}, err
			}
			lockedBlobs = append(lockedBlobs, blob)
			lockedSources[blob.SHA256] = source
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
	if err := requireSigningSupport(selected, repository, plannedSigning); err != nil {
		return BuildResult{}, err
	}
	renderFromBlobs := func(blobs []domain.Blob, sources map[string]string) (BuildResult, error) {
		artifact, err := selected.Build(blobs, formats.BuildOptions{
			Repository: formatRepositoryWithKeys(repository, name, keys), GeneratedAt: generatedAt,
		})
		if err != nil {
			return BuildResult{}, err
		}
		if !selected.ImplementsSigning() {
			return materializeLockedArtifact(ctx, output, generatedAt, artifact, sources)
		}
		artifact, signing, err := applyRepositorySigning(ctx, root, repository, keys, artifact, signatureTime, plannedSigning, signers, sources)
		if err != nil {
			return BuildResult{}, err
		}
		result, materializeErr := materializeLockedArtifact(ctx, output, generatedAt, artifact, sources)
		result.Signing = signing
		return result, materializeErr
	}
	if len(active) == 0 {
		return renderFromBlobs(nil, nil)
	}
	// Three formats are built by the engine rather than through the format
	// interface, so the listing inputs are handed to them explicitly.
	listingView := formatRepositoryWithKeys(repository, name, keys)
	// These paths rebuild by scanning materialized files, which cannot say when
	// anything was published; the lock can, so it is carried alongside.
	published := make(map[string]time.Time, len(lockedBlobs))
	for _, locked := range lockedBlobs {
		if !locked.Added.IsZero() {
			published[locked.SHA256] = locked.Added
		}
	}
	switch repository.Format {
	case "pypi":
		return BuildPyPI(ctx, BuildPyPIRequest{Input: input, Output: output, GeneratedAt: generatedAt, Listing: listingView, Published: published})
	case "deb":
		var resolved []state.PlanSigning
		result, err := buildDeb(ctx, BuildDebRequest{Input: input, Output: output, Suite: repository.Suite, Component: repository.Component, Architectures: repository.Architectures, GeneratedAt: generatedAt, Listing: listingView, Published: published}, func(artifact domain.RepositoryArtifact) (domain.RepositoryArtifact, error) {
			signed, signing, err := applyRepositorySigning(ctx, root, repository, keys, artifact, signatureTime, plannedSigning, signers, lockedSources)
			resolved = signing
			return signed, err
		})
		result.Signing = resolved
		return result, err
	case "helm":
		var resolvedHelm []state.PlanSigning
		helmResult, err := buildHelm(ctx, BuildHelmRequest{Input: input, Output: output, GeneratedAt: generatedAt, Listing: listingView, Published: published},
			func(artifact domain.RepositoryArtifact) (domain.RepositoryArtifact, error) {
				if len(repository.SigningKeys) == 0 {
					return artifact, nil
				}
				signed, signing, err := applyRepositorySigning(ctx, root, repository, keys, artifact, signatureTime, plannedSigning, signers, lockedSources)
				resolvedHelm = signing
				return signed, err
			})
		helmResult.Signing = resolvedHelm
		return helmResult, err
	case "raw", "rpm", "apk":
		return renderFromBlobs(lockedBlobs, lockedSources)
	default:
		return BuildResult{}, fmt.Errorf("unsupported repository format %q", repository.Format)
	}
}

// requireSigningSupport rejects signing state a format cannot express, keeping
// the reason specific to the format rather than a generic capability message.
// defaultPlacementDistro resolves the distribution coordinate a placement
// takes when none was requested: the repository's own suite where the format
// has the notion, and nothing where it does not.
func defaultPlacementDistro(repository state.Repository, requested string) string {
	if requested != "" {
		return requested
	}
	selected, err := formats.For(repository.Format)
	if err != nil || !selected.SupportsDistros() {
		return ""
	}
	return repository.Suite
}

// formatSupportsSigning reports whether a format name can carry repository
// signatures, treating an unknown format as unable to.
func formatSupportsSigning(name string) bool {
	selected, err := formats.For(name)
	return err == nil && selected.ImplementsSigning()
}

func requireSigningSupport(selected formats.Format, repository state.Repository, plannedSigning []state.PlanSigning) error {
	if selected.ImplementsSigning() || (len(plannedSigning) == 0 && len(repository.SigningKeys) == 0) {
		return nil
	}
	switch selected.Name() {
	case "pypi":
		return errors.New("PyPI repository cannot contain repository signing effects")
	case "raw":
		return errors.New("raw repositories have no signing scheme a client would check")
	}
	return fmt.Errorf("format %q cannot contain repository signing effects", selected.Name())
}

func materializeLockedArtifact(ctx context.Context, output string, generatedAt time.Time, artifact domain.RepositoryArtifact, sources map[string]string) (BuildResult, error) {
	artifact, manifest, err := buildgraph.Finalize(artifact, generatedAt)
	if err != nil {
		return BuildResult{}, err
	}
	if err := app.Materialize(ctx, output, artifact, sources); err != nil {
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
		result, err := VerifyDeb(ctx, VerifyDebRequest{Repository: repository, Runner: request.Runner, Image: request.DebianImage, MaxWorkspaceBytes: request.MaxWorkspaceBytes, StructuralOnly: request.StructuralOnly, VerifyAllVersions: request.VerifyAllVersions})
		return result.Manifest, err
	case "helm":
		result, err := VerifyHelm(ctx, VerifyHelmRequest{Repository: repository, Runner: request.Runner, Image: request.HelmImage, StructuralOnly: request.StructuralOnly})
		return result.Manifest, err
	case "raw":
		result, err := VerifyRaw(VerifyRawRequest{Repository: repository})
		return result.Manifest, err
	case "rpm":
		result, err := VerifyRPM(ctx, VerifyRPMRequest{
			Repository: repository, Runner: request.Runner, Image: request.RPMImage,
			StructuralOnly: request.StructuralOnly, VerifyAllVersions: request.VerifyAllVersions,
		})
		return result.Manifest, err
	case "apk":
		result, err := VerifyAPK(ctx, VerifyAPKRequest{
			Repository: repository, Runner: request.Runner, Image: request.APKImage,
			StructuralOnly: request.StructuralOnly, VerifyAllVersions: request.VerifyAllVersions,
		})
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
	selected, err := formats.For(format)
	if err != nil {
		return name
	}
	return selected.NormalizeName(name)
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
	if !host.Supports(repository.Host.Type, repository.Format).InstallDocument {
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
	selected, err := formats.For(repository.Format)
	if err != nil {
		return nil
	}
	return selected.CommitPaths(formatRepository(repository))
}

// formatRepository projects a configured repository onto the fields a format
// reasons about.
func formatRepository(repository state.Repository) formats.Repository {
	return formatRepositoryWithKeys(repository, "", nil)
}

// formatRepositoryWithKeys adds what only the manifest knows: the repository's
// own name, where it is served, and which key verifies it. A listing states all
// three, and none of them can be recovered from the artifacts alone.
func formatRepositoryWithKeys(repository state.Repository, name string, keys map[string]state.SigningKey) formats.Repository {
	view := formats.Repository{
		Name: name, Suite: repository.Suite, Component: repository.Component,
		Architectures: repository.Architectures, Signed: len(repository.SigningKeys) != 0,
		Endpoint: repository.Host.CanonicalEndpoint,
	}
	if len(repository.SigningKeys) == 1 && keys != nil {
		if key, exists := keys[repository.SigningKeys[0]]; exists {
			view.Signing = &formats.RepositorySigning{
				Fingerprint: key.Fingerprint, Algorithm: key.Algorithm,
				KeyPath: clientKeyPath(repository, key),
			}
		}
	}
	return view
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
			if !formatSupportsSigning(repository.Format) || signing.KeyName == "" || (signing.Algorithm != signer.AlgorithmOpenPGPRSA4096 && signing.Algorithm != signer.AlgorithmAPKRSA4096) || !validFingerprint(signing.Fingerprint) ||
				!validSHA256(signing.PublicKeySHA256) || !validSHA256(signing.PublicArmorSHA256) || !validSHA256(signing.RecipeSHA256) || signing.PublicKeyPath == "" || signing.PublicArmorPath == "" ||
				// A format decides how many signatures it makes, and the count
				// follows from the repository rather than from the format alone,
				// so without the repository only the bound is checkable here.
				len(signing.Nodes) == 0 || len(signing.Nodes) > maxSigningNodes {
				return fmt.Errorf("plan repository %q has invalid signing metadata", repository.Name)
			}
			if _, err := time.Parse(time.RFC3339, signing.SignatureTime); err != nil {
				return fmt.Errorf("plan repository %q has invalid signature time", repository.Name)
			}
			// The repository has not been rebuilt here, so there is no artifact
			// to derive a recipe from; what a plan can be checked against alone
			// is that every response is a well-formed signature.
			if err := validateSigningRecipeMetadata(signing, nil); err != nil {
				return fmt.Errorf("plan repository %q: %w", repository.Name, err)
			}
			for _, node := range signing.Nodes {
				if !validSHA256(node.PayloadSHA256) || !validSHA256(node.ContentSHA256) || len(node.Content) == 0 || len(node.Content) > 8<<20 {
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

// applyExecution carries the mutable outcome of a publication pass so that each
// repository can be handled by its own function rather than by another few
// hundred lines inside ApplyWorkspace.
type applyExecution struct {
	ctx              context.Context
	root             string
	request          ApplyWorkspaceRequest
	plan             state.Plan
	applyGitRevision string
	authorize        func(applyRepository) error

	result      ApplyWorkspaceResult
	deployments []state.DeploymentRecord
}

// verifyCurrent handles a repository the host already serves at the desired
// tree. Nothing is published, but a client probe still has to pass before the
// deployment receipt can claim the tree is being served.
func (execution *applyExecution) verifyCurrent(item applyRepository) error {
	ctx, request := execution.ctx, execution.request
	execution.result.Current++
	if !request.StructuralOnly && item.planned.Action != "noop" {
		access, accessErr := item.host.ReadAccess(ctx, item.hostRepository, item.observed)
		if accessErr != nil {
			return accessErr
		}
		if err := verifyCanonicalClient(ctx, execution.root, item.repository, item.stage, access, request); err != nil {
			if item.observed.RestoreID != "" {
				reference := host.RestoreRef{
					ID: item.observed.RestoreID, PlanID: item.observed.PlanID,
					ChangeID: item.observed.ChangeID, FailedTree: item.observed.TreeSHA256,
					DescriptorSHA256: item.observed.RestoreSHA256, RootSHA256: item.observed.RestoreRootSHA256,
				}
				if restoreErr := restoreFailedPublication(ctx, item, reference, expectedRevisionFromPublished(item.observed), execution.authorize); restoreErr != nil {
					return fmt.Errorf("canonical retry probe failed: %v; %w", err, restoreErr)
				}
				execution.result.Current--
			}
			return err
		}
	}
	if item.planned.Action != "noop" {
		execution.recordDeployment(item, item.observed.NativeRevision)
	}
	return nil
}

// publish switches one repository to its staged tree, proves the host serves
// exactly that tree, and restores the displaced revision if it does not.
func (execution *applyExecution) publish(item applyRepository) error {
	ctx, request := execution.ctx, execution.request
	// The publication locks are held across the whole pass, so Git cannot move
	// the branch under it; confirming HEAD is enough and keeps the cost of a
	// publication independent of how many repositories it covers.
	if err := state.AssertGitHeadRevision(execution.root, execution.applyGitRevision); err != nil {
		return err
	}
	if err := execution.authorize(item); err != nil {
		return err
	}
	committed, err := item.host.Commit(ctx, item.hostRepository, item.hostStage, expectedRevisionFromPlan(item.planned))
	if err != nil {
		return err
	}
	// Scoped to this repository, so a multi-repository apply does not keep every
	// short-lived credential alive until the whole apply finishes.
	if committed.Access.Credential != nil {
		defer committed.Access.Credential.Destroy()
	}
	execution.result.Applied++
	canonical, observeErr := item.host.Observe(ctx, item.hostRepository)
	if observeErr != nil || canonical.TreeSHA256 != item.planned.DesiredTreeSHA256 || canonical.NativeRevision != committed.Revision.NativeRevision ||
		(item.hostRepository.Type == "s3" && canonical != committed.Revision) {
		probeErr := observeErr
		if probeErr == nil {
			probeErr = errors.New("canonical host observation does not match committed tree")
		}
		return execution.restore(item, committed, probeErr, "canonical probe failed")
	}
	if !request.StructuralOnly {
		access := committed.Access
		if access.Endpoint == "" {
			access.Endpoint = committed.CanonicalEndpoint
		}
		if probeErr := verifyCanonicalClient(ctx, execution.root, item.repository, item.stage, access, request); probeErr != nil {
			return execution.restore(item, committed, probeErr, "canonical client probe failed")
		}
	}
	if err := state.AssertGitHeadRevision(execution.root, execution.applyGitRevision); err != nil {
		return err
	}
	execution.recordDeployment(item, committed.Revision.NativeRevision)
	return nil
}

// restore compensates a failed probe and always reports the original failure,
// with the restore outcome attached.
func (execution *applyExecution) restore(item applyRepository, committed host.CommitResult, probeErr error, label string) error {
	if committed.RestoreRef == nil {
		return fmt.Errorf("%s: %w", label, probeErr)
	}
	if restoreErr := restoreFailedPublication(execution.ctx, item, *committed.RestoreRef, expectedRevisionFromPublished(committed.Revision), execution.authorize); restoreErr != nil {
		return fmt.Errorf("%s: %v; %w", label, probeErr, restoreErr)
	}
	execution.result.Applied--
	return fmt.Errorf("%s: %w", label, probeErr)
}

func (execution *applyExecution) recordDeployment(item applyRepository, nativeRevision string) {
	execution.deployments = append(execution.deployments, deploymentRecordFor(
		item.planned, item.deployment, item.observed, item.signingState, nativeRevision,
		execution.plan.PlanID, execution.plan.Payload.CreatedAt, execution.request.currentTime(),
	))
}

// applyPreparation revalidates the reviewed plan against the current workspace
// and builds each repository's stage. Nothing here has a publication effect:
// every failure leaves the hosts untouched.
type applyPreparation struct {
	ctx             context.Context
	root            string
	request         ApplyWorkspaceRequest
	plan            state.Plan
	manifest        state.Manifest
	hosts           host.Resolver
	blobStore       blob.Store
	now             time.Time
	expiresAt       time.Time
	generatedAt     time.Time
	signatureTime   time.Time
	ledgerCommitted bool
}

// prepareRepository checks one planned repository against the workspace it was
// planned from and, unless the host already serves the desired tree, rebuilds
// and verifies its stage. The caller owns cleanup of stages already built.
func (preparation *applyPreparation) prepareRepository(planned state.PlanRepository) (applyRepository, error) {
	repository, exists := preparation.manifest.Repositories[planned.Name]
	if !exists || repository.Format != planned.Format || repository.Gate != planned.Gate || !reflect.DeepEqual(repository.ApprovalKeys, planned.ApprovalKeys) || len(planned.Signing) > 1 || (len(planned.Signing) == 0) != (len(repository.SigningKeys) == 0) {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q configuration changed", planned.Name)
	}
	// The lock is read before the signing shape is checked, because one format's
	// shape depends on it: Helm signs a provenance file per chart, and which
	// charts a repository publishes is desired state rather than configuration.
	// The lock is reviewed and committed like the rest of it, so deriving the
	// shape from it needs no rebuilt tree — only this ordering.
	lockPath, err := state.WorkspacePath(preparation.root, repository.Lock)
	if err != nil {
		return applyRepository{}, err
	}
	lockDigest, err := state.HashFile(lockPath)
	if err != nil || lockDigest != planned.LockSHA256 {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q lock changed", planned.Name)
	}
	lock, err := state.LoadLock(preparation.root, repository)
	if err != nil {
		return applyRepository{}, err
	}
	if err := state.ValidateLock(lock, planned.Name, repository.Format); err != nil {
		return applyRepository{}, err
	}
	activeSigningKey, _, _, _, signingStateErr := repositorySigningState(repository)
	if signingStateErr != nil {
		return applyRepository{}, signingStateErr
	}
	for index, signing := range planned.Signing {
		if index != 0 || signing.KeyName != activeSigningKey {
			return applyRepository{}, fmt.Errorf("stale plan: repository %q signing key changed", planned.Name)
		}
		key, exists := preparation.manifest.Keys[signing.KeyName]
		if !exists {
			return applyRepository{}, fmt.Errorf("stale plan: repository %q signing key is missing", planned.Name)
		}
		keyExpiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if err != nil || preparation.expiresAt.After(keyExpiresAt) {
			return applyRepository{}, fmt.Errorf("repository %q plan expires after its signing key", planned.Name)
		}
		// The tree has not been built here. The shape is still knowable: it
		// follows from the repository's configuration and, for Helm, from the
		// charts its lock says are published.
		shape, err := signingShapeFor(repository, helmChartPathsFromLock(repository, lock))
		if err != nil {
			return applyRepository{}, fmt.Errorf("plan repository %q: %w", planned.Name, err)
		}
		if err := validateSigningRecipeMetadata(signing, &shape); err != nil {
			return applyRepository{}, fmt.Errorf("plan repository %q: %w", planned.Name, err)
		}
	}
	hostIdentity, err := repositoryHostIdentity(repository)
	if err != nil || hostIdentity != planned.HostIdentitySHA256 || repository.Host != planned.Host || repository.Visibility != planned.Visibility {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q host changed", planned.Name)
	}
	hostRepository := toHostRepository(preparation.root, preparation.manifest.Workspace.ID, hostIdentity, planned.Name, repository)
	if hostRepository.CanonicalEndpoint != planned.CanonicalEndpoint {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q canonical endpoint changed", planned.Name)
	}
	installDocDigest, err := repositoryInstallDocDigest(preparation.root, planned.Name, repository)
	if err != nil || installDocDigest != planned.InstallDocSHA256 {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q install document changed", planned.Name)
	}
	selectedHost, err := preparation.hosts.Resolve(preparation.ctx, hostRepository)
	if err != nil {
		return applyRepository{}, err
	}
	capabilities, err := selectedHost.Capabilities(preparation.ctx, hostRepository)
	if err != nil {
		return applyRepository{}, err
	}
	if capabilities.FaithfulPreview != planned.FaithfulPreview || capabilities.ConditionalCommit != planned.ConditionalCommit || capabilities.ConditionalRestore != planned.ConditionalRestore ||
		capabilities.PrivateRead != planned.PrivateRead || capabilities.CredentialBrokerIdentity != planned.CredentialBrokerIdentity {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q host capabilities changed", planned.Name)
	}
	ledger, err := state.LoadLedgerHistory(preparation.root, planned.Name)
	if err != nil {
		return applyRepository{}, err
	}
	if err := state.ValidatePublicationHistory(planned.Name, ledger); err != nil {
		return applyRepository{}, err
	}
	if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
		return applyRepository{}, err
	}
	missingBindings := missingPublicationBindings(lock, repository, ledger)
	expectedBindings := []state.PlanPublicationBinding(nil)
	if planned.PublicationRecords {
		expectedBindings = publicationBindingsForVersions(visiblePackageVersions(lock, repository))
	}
	expectedAcquisitions := planAcquisitionsForVersions(visiblePackageVersions(lock, repository))
	if !reflect.DeepEqual(planned.Acquisitions, expectedAcquisitions) {
		return applyRepository{}, fmt.Errorf("plan repository %q has inconsistent adopted acquisitions", planned.Name)
	}
	if planned.PublicationRecords != (len(planned.PublicationBindings) != 0) ||
		!reflect.DeepEqual(planned.PublicationBindings, expectedBindings) ||
		(!preparation.ledgerCommitted && planned.PublicationRecords != (len(missingBindings) != 0)) ||
		(preparation.ledgerCommitted && !planned.PublicationRecords && len(missingBindings) != 0) {
		return applyRepository{}, fmt.Errorf("plan repository %q has inconsistent publication-record effects", planned.Name)
	}
	deployment, err := state.LoadDeployment(preparation.root, planned.Name)
	if err != nil {
		return applyRepository{}, err
	}
	desiredSigningState, err := repositoryDeploymentSigningState(repository, preparation.manifest.Keys)
	if err != nil {
		return applyRepository{}, err
	}
	observed, err := selectedHost.Observe(preparation.ctx, hostRepository)
	if err != nil {
		return applyRepository{}, err
	}
	plannedObserved := publishedFromPlanObservation(planned)
	trustNotBefore := time.Time{}
	if repository.SigningRotation != nil || deployment.SigningRotationPhase != "" {
		trustNotBefore, err = state.AuthoritativeDeploymentTrustSince(preparation.root, planned.Name, deployment)
		if err != nil {
			return applyRepository{}, err
		}
	}
	if err := validateRepositorySigningTransition(repository, preparation.manifest.Keys, deployment, plannedObserved, preparation.now, trustNotBefore); err != nil {
		return applyRepository{}, fmt.Errorf("repository %q: %w", planned.Name, err)
	}
	matchesObserved := revisionMatchesPlanObservation(observed, planned)
	managedRemote := repository.Host.Type == "s3" || repository.Host.Type == "github-pages"
	matchesApplied := planned.Action != "noop" && observed.TreeSHA256 == planned.DesiredTreeSHA256 &&
		(!managedRemote || (observed.PlanID == preparation.plan.PlanID && observed.ChangeID == planned.ChangeID && observed.ManifestSHA256 == planned.DesiredManifestSHA256))
	deploymentApplied := deployment.PlanID == preparation.plan.PlanID && deployment.ChangeID == planned.ChangeID && deployment.TreeSHA256 == planned.DesiredTreeSHA256 && deployment.ManifestSHA256 == planned.DesiredManifestSHA256 && deployment.NativeRevision == observed.NativeRevision && deploymentSigningMatches(deployment, desiredSigningState)
	deploymentCurrent := deploymentMatchesDesired(deployment, observed, planned.DesiredTreeSHA256, planned.DesiredManifestSHA256, desiredSigningState)
	if !reflect.DeepEqual(deployment, planned.ObservedDeployment) && !deploymentApplied {
		return applyRepository{}, fmt.Errorf("stale plan: repository %q deployment receipt changed", planned.Name)
	}
	if !matchesObserved && !matchesApplied {
		if observed.TreeSHA256 == planned.ObservedTreeSHA256 {
			return applyRepository{}, fmt.Errorf("stale plan: repository %q native revision changed", planned.Name)
		}
		if observed.TreeSHA256 == planned.DesiredTreeSHA256 {
			return applyRepository{}, fmt.Errorf("stale plan: repository %q desired tree was published by another change", planned.Name)
		}
		return applyRepository{}, fmt.Errorf("stale plan: repository %q target changed", planned.Name)
	}
	expectedAction := "noop"
	if planned.ObservedTreeSHA256 != planned.DesiredTreeSHA256 || (managedRemote && planned.ObservedManifestSHA256 != planned.DesiredManifestSHA256) || !publicationBindingsComplete(lock, repository, ledger) || !deploymentMatchesDesired(planned.ObservedDeployment, plannedObserved, planned.DesiredTreeSHA256, planned.DesiredManifestSHA256, desiredSigningState) {
		expectedAction = "update"
		if planned.ObservedRevision == "" {
			expectedAction = "create"
		}
	}
	if planned.Action != expectedAction || planned.ChangeID != planned.Name+":"+planned.DesiredTreeSHA256[:12] {
		return applyRepository{}, fmt.Errorf("plan repository %q has inconsistent action metadata", planned.Name)
	}
	receiptRecovery := matchesApplied && reflect.DeepEqual(deployment, planned.ObservedDeployment)
	current := observed.TreeSHA256 == planned.DesiredTreeSHA256 && (!managedRemote || observed.ManifestSHA256 == planned.DesiredManifestSHA256) && (deploymentApplied || (planned.Action == "noop" && deploymentCurrent) || receiptRecovery)
	item := applyRepository{
		planned: planned, repository: repository, lock: lock, host: selectedHost,
		hostRepository: hostRepository, observed: observed, current: current, deployment: deployment, signingState: desiredSigningState,
	}
	// Nothing to build: the host already serves this tree and no signing effect
	// has to be replayed, so there is no stage for this repository.
	if item.current && (preparation.request.StructuralOnly || planned.Action == "noop") && !(planned.Action != "noop" && len(planned.Signing) != 0) {
		return item, nil
	}
	staging, err := stagingRoot(preparation.root)
	if err != nil {
		return applyRepository{}, err
	}
	stage, err := os.MkdirTemp(staging, ".snailmail-apply-*")
	if err != nil {
		return applyRepository{}, err
	}
	stageOutput := filepath.Join(stage, "repository")
	staged, buildErr := buildLockedRepository(preparation.ctx, preparation.root, planned.Name, repository, lock, preparation.generatedAt, preparation.signatureTime, stageOutput, preparation.blobStore, preparation.manifest.Keys, planned.Signing, nil, preparation.request.Sources)
	if buildErr == nil && (staged.TreeSHA256 != planned.DesiredTreeSHA256 || staged.ManifestSHA256 != planned.DesiredManifestSHA256) {
		buildErr = errors.New("stale plan: rebuilt tree digest changed")
	}
	if buildErr == nil && !signingContentsEqual(staged.Signing, planned.Signing) {
		buildErr = errors.New("stale plan: signing recipe changed")
	}
	var stagedManifest buildgraph.RepositoryManifest
	if buildErr == nil {
		structuralRequest := preparation.request
		structuralRequest.StructuralOnly = true
		stagedManifest, buildErr = verifyStaged(preparation.ctx, repository.Format, stageOutput, structuralRequest)
	}
	if buildErr != nil {
		_ = os.RemoveAll(stage)
		return applyRepository{}, buildErr
	}
	item.stageRoot, item.stage, item.stagedManifest = stage, stageOutput, stagedManifest
	return item, nil
}
