package githubpages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"

	"github.com/shellcell/snailmail/internal/hexdigest"
)

const publicationHeader = "snailmail-pages/v1"

type RemoteResolver func(string) string

type Adapter struct {
	remote         RemoteResolver
	verifyProvider bool
}

func New() *Adapter {
	return &Adapter{remote: func(repository string) string {
		return "https://github.com/" + repository + ".git"
	}, verifyProvider: true}
}

func NewWithRemoteResolver(resolver RemoteResolver) *Adapter {
	return &Adapter{remote: resolver}
}

func (adapter *Adapter) Capabilities(ctx context.Context, repository host.Repository) (host.Capabilities, error) {
	if adapter == nil || adapter.remote == nil {
		return host.Capabilities{}, invalid("configure GitHub Pages host", "Git remote resolver is unavailable")
	}
	if err := validateRepository(repository); err != nil {
		return host.Capabilities{}, err
	}
	if adapter.verifyProvider {
		if err := verifyPagesSite(ctx, repository.RemoteRepository, repository.Branch, repository.CanonicalEndpoint); err != nil {
			return host.Capabilities{}, err
		}
		if err := verifyPagesSite(ctx, repository.PreviewRepository, repository.PreviewBranch, repository.PreviewEndpoint); err != nil {
			return host.Capabilities{}, err
		}
	}
	return host.Capabilities{FaithfulPreview: true, ConditionalCommit: true, ConditionalRestore: true}, nil
}

func (adapter *Adapter) Observe(ctx context.Context, repository host.Repository) (host.PublishedRevision, error) {
	if err := validateRepository(repository); err != nil {
		return host.PublishedRevision{}, err
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	defer workspace.Close()
	commit, err := workspace.fetch(ctx, adapter.remote(repository.RemoteRepository), branchRef(repository.Branch))
	if errors.Is(err, errRefNotFound) {
		return host.PublishedRevision{}, nil
	}
	if err != nil {
		return host.PublishedRevision{}, infrastructure("observe GitHub Pages ref", err)
	}
	revision, _, metadata, err := workspace.inspectPublication(ctx, commit)
	if err != nil {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe GitHub Pages publication", Err: err}
	}
	if revision.TreeSHA256 != "" {
		identifier := effectIdentifier(revision.PlanID, revision.ChangeID)
		descriptorCommit, descriptorErr := workspace.fetch(ctx, adapter.remote(repository.RemoteRepository), restoreRef(identifier))
		if descriptorErr != nil {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe GitHub Pages restore state", Err: descriptorErr}
		}
		descriptor, parent, descriptorErr := workspace.inspectRestoreDescriptor(ctx, descriptorCommit)
		if descriptorErr != nil || descriptor != metadata || parent != metadata.PreviousRevision {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe GitHub Pages restore state", Err: errors.New("restore descriptor does not match canonical publication")}
		}
		revision.RestoreID = identifier
		revision.RestoreSHA256 = digestString(descriptorCommit)
	}
	return revision, nil
}

func (adapter *Adapter) ReadAccess(ctx context.Context, repository host.Repository, revision host.PublishedRevision) (host.ClientAccess, error) {
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.ClientAccess{}, err
	}
	if observed != revision || revision.TreeSHA256 == "" {
		return host.ClientAccess{}, &host.Error{Kind: host.ErrorStale, Operation: "issue GitHub Pages read access", Err: errors.New("requested revision is no longer canonical")}
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return host.ClientAccess{}, err
	}
	defer workspace.Close()
	commit, err := workspace.fetch(ctx, adapter.remote(repository.RemoteRepository), branchRef(repository.Branch))
	if err != nil {
		return host.ClientAccess{}, infrastructure("read GitHub Pages publication", err)
	}
	_, files, _, err := workspace.inspectPublication(ctx, commit)
	if err != nil {
		return host.ClientAccess{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "read GitHub Pages publication", Err: err}
	}
	routes, err := clientRoutes(repository.CanonicalEndpoint, files)
	if err != nil {
		return host.ClientAccess{}, err
	}
	return host.ClientAccess{Endpoint: repository.CanonicalEndpoint, Routes: routes, PropagationTimeout: 2 * time.Minute}, nil
}

func (adapter *Adapter) Stage(ctx context.Context, repository host.Repository, request host.StageRequest) (host.StagedPublication, error) {
	if err := validateRepository(repository); err != nil {
		return host.StagedPublication{}, err
	}
	if err := validateStageRequest(request); err != nil {
		return host.StagedPublication{}, err
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return host.StagedPublication{}, err
	}
	defer workspace.Close()
	commit, err := workspace.createPublication(ctx, request)
	if err != nil {
		return host.StagedPublication{}, err
	}
	identifier := effectIdentifier(request.PlanID, request.ChangeID)
	production := adapter.remote(repository.RemoteRepository)
	stageRef := stageRef(identifier)
	if err := workspace.ensureRef(ctx, production, stageRef, commit); err != nil {
		return host.StagedPublication{}, err
	}
	var routes []host.ClientRoute
	if previewConfigured(repository) {
		preview := adapter.remote(repository.PreviewRepository)
		if err := workspace.replaceRef(ctx, preview, branchRef(repository.PreviewBranch), commit); err != nil {
			return host.StagedPublication{}, err
		}
		routes, err = clientRoutes(repository.PreviewEndpoint, request.Files)
		if err != nil {
			return host.StagedPublication{}, err
		}
	}
	return host.StagedPublication{
		ID: identifier, PlanID: request.PlanID, ChangeID: request.ChangeID, PreviousRevision: request.PreviousRevision, PreviewEndpoint: repository.PreviewEndpoint,
		TreeSHA256: request.TreeSHA256, Files: append([]host.File(nil), request.Files...),
		CommitPaths: append([]string(nil), request.CommitPaths...), Access: host.ClientAccess{Endpoint: repository.PreviewEndpoint, Routes: routes, PropagationTimeout: 2 * time.Minute},
	}, nil
}

func (adapter *Adapter) Commit(ctx context.Context, repository host.Repository, staged host.StagedPublication, expected host.ExpectedRevision) (host.CommitResult, error) {
	if err := validateRepository(repository); err != nil {
		return host.CommitResult{}, err
	}
	if !validIdentifier(staged.ID) || !hexdigest.ValidSHA256(staged.PlanID) || staged.ChangeID == "" || !hexdigest.ValidSHA256(staged.TreeSHA256) {
		return host.CommitResult{}, invalid("commit GitHub Pages publication", "invalid stage handle")
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return host.CommitResult{}, err
	}
	defer workspace.Close()
	remote := adapter.remote(repository.RemoteRepository)
	stageCommit, err := workspace.fetch(ctx, remote, stageRef(staged.ID))
	if err != nil {
		return host.CommitResult{}, infrastructure("read GitHub Pages stage", err)
	}
	stageRevision, files, stageMetadata, err := workspace.inspectPublication(ctx, stageCommit)
	if err != nil || stageRevision.TreeSHA256 != staged.TreeSHA256 || stageRevision.PlanID != staged.PlanID || stageRevision.ChangeID != staged.ChangeID || stageRevision.ManifestSHA256 != fileSHA256(staged.Files, "snailmail.repository.json") || stageMetadata.PreviousRevision != staged.PreviousRevision || !equalFiles(files, staged.Files) {
		return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate GitHub Pages stage", Err: errors.New("remote stage does not match reviewed publication")}
	}
	if staged.PreviousRevision != expected.NativeRevision {
		return host.CommitResult{}, &host.Error{Kind: host.ErrorStale, Operation: "commit GitHub Pages publication", Err: errors.New("stage was built for a different prior revision")}
	}
	current, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	stagedManifest := fileSHA256(staged.Files, "snailmail.repository.json")
	if current.TreeSHA256 == staged.TreeSHA256 && current.PlanID == staged.PlanID && current.ChangeID == staged.ChangeID && current.ManifestSHA256 == stagedManifest {
		access, accessErr := adapter.ReadAccess(ctx, repository, current)
		if accessErr != nil {
			return host.CommitResult{}, accessErr
		}
		return commitResult(repository, current, staged.ID, access), nil
	}
	if !matchesExpected(current, expected) {
		return host.CommitResult{}, stale("commit GitHub Pages publication", expected, current)
	}
	if current.NativeRevision != "" {
		fetchedCurrent, fetchErr := workspace.fetch(ctx, remote, branchRef(repository.Branch))
		if fetchErr != nil || fetchedCurrent != current.NativeRevision {
			return host.CommitResult{}, stale("commit GitHub Pages publication", expected, current)
		}
	}
	descriptorCommit, err := workspace.createRestoreDescriptor(ctx, staged)
	if err != nil {
		return host.CommitResult{}, err
	}
	if err := workspace.ensureRef(ctx, remote, restoreRef(staged.ID), descriptorCommit); err != nil {
		return host.CommitResult{}, err
	}
	if err := workspace.compareAndSwapRef(ctx, remote, branchRef(repository.Branch), current.NativeRevision, stageCommit); err != nil {
		published, observeErr := adapter.Observe(ctx, repository)
		if observeErr == nil && published.NativeRevision == stageCommit && published.TreeSHA256 == staged.TreeSHA256 && published.PlanID == staged.PlanID && published.ChangeID == staged.ChangeID && published.ManifestSHA256 == stagedManifest {
			access, accessErr := adapter.ReadAccess(ctx, repository, published)
			if accessErr != nil {
				return host.CommitResult{}, accessErr
			}
			return commitResult(repository, published, staged.ID, access), nil
		}
		return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "commit GitHub Pages publication", EffectMayHaveOccurred: true, Err: err}
	}
	published, err := adapter.Observe(ctx, repository)
	if err != nil || published.NativeRevision != stageCommit || published.TreeSHA256 != staged.TreeSHA256 || published.PlanID != staged.PlanID || published.ChangeID != staged.ChangeID || published.ManifestSHA256 != stagedManifest {
		if err == nil {
			err = errors.New("published GitHub Pages ref does not match staged commit")
		}
		return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "verify GitHub Pages publication", EffectMayHaveOccurred: true, Err: err}
	}
	access, err := adapter.ReadAccess(ctx, repository, published)
	if err != nil {
		return host.CommitResult{}, err
	}
	return commitResult(repository, published, staged.ID, access), nil
}

func (adapter *Adapter) Restore(ctx context.Context, repository host.Repository, restore host.RestoreRef, expected host.ExpectedRevision) (host.PublishedRevision, error) {
	if err := validateRepository(repository); err != nil {
		return host.PublishedRevision{}, err
	}
	if !validIdentifier(restore.ID) || restore.PlanID == "" || restore.ChangeID == "" || restore.FailedTree == "" {
		return host.PublishedRevision{}, invalid("restore GitHub Pages publication", "invalid restore reference")
	}
	current, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if !matchesExpected(current, expected) || current.PlanID != restore.PlanID || current.ChangeID != restore.ChangeID || current.TreeSHA256 != restore.FailedTree {
		return host.PublishedRevision{}, stale("restore GitHub Pages publication", expected, current)
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	defer workspace.Close()
	remote := adapter.remote(repository.RemoteRepository)
	descriptorCommit, err := workspace.fetch(ctx, remote, restoreRef(restore.ID))
	if err != nil {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "read GitHub Pages restore descriptor", Err: err}
	}
	descriptor, parent, err := workspace.inspectRestoreDescriptor(ctx, descriptorCommit)
	if err != nil || digestString(descriptorCommit) != restore.DescriptorSHA256 || descriptor.PlanID != restore.PlanID || descriptor.ChangeID != restore.ChangeID || descriptor.TreeSHA256 != restore.FailedTree || descriptor.ManifestSHA256 != current.ManifestSHA256 || descriptor.PreviousRevision != parent {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate GitHub Pages restore descriptor", Err: errors.New("restore descriptor does not match failed publication")}
	}
	if err := workspace.compareAndSwapRef(ctx, remote, branchRef(repository.Branch), current.NativeRevision, parent); err != nil {
		observed, observeErr := adapter.Observe(ctx, repository)
		if observeErr == nil && observed.NativeRevision == parent {
			return observed, nil
		}
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore GitHub Pages publication", EffectMayHaveOccurred: true, Err: err}
	}
	return adapter.Observe(ctx, repository)
}

func (adapter *Adapter) Abort(ctx context.Context, repository host.Repository, staged host.StagedPublication) error {
	if err := validateRepository(repository); err != nil {
		return err
	}
	if !validIdentifier(staged.ID) {
		return invalid("abort GitHub Pages stage", "invalid stage identifier")
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		return err
	}
	defer workspace.Close()
	remote := adapter.remote(repository.RemoteRepository)
	commit, err := workspace.lsRemote(ctx, remote, stageRef(staged.ID))
	if errors.Is(err, errRefNotFound) {
		return nil
	}
	if err != nil {
		return infrastructure("inspect GitHub Pages stage", err)
	}
	if err := workspace.compareAndSwapRef(ctx, remote, stageRef(staged.ID), commit, ""); err != nil {
		return infrastructure("abort GitHub Pages stage", err)
	}
	return nil
}

type publicationMetadata struct {
	PlanID           string
	ChangeID         string
	TreeSHA256       string
	ManifestSHA256   string
	PreviousRevision string
}

func commitResult(repository host.Repository, revision host.PublishedRevision, identifier string, access host.ClientAccess) host.CommitResult {
	return host.CommitResult{
		Revision: revision, CanonicalEndpoint: repository.CanonicalEndpoint, Access: access,
		RestoreRef: &host.RestoreRef{
			ID: identifier, PlanID: revision.PlanID, ChangeID: revision.ChangeID, FailedTree: revision.TreeSHA256,
			DescriptorSHA256: revision.RestoreSHA256,
		},
	}
}

// previewConfigured reports whether a companion preview site was asked for.
// Any one of the three fields means yes, so a half-filled preview is caught by
// validation rather than silently ignored.
func previewConfigured(repository host.Repository) bool {
	return repository.PreviewRepository != "" || repository.PreviewBranch != "" || repository.PreviewEndpoint != ""
}

func validateRepository(repository host.Repository) error {
	// Configuration validation rejects an unsupported pair earlier; this is the
	// adapter refusing to act on one that reached it anyway.
	if repository.Type != "github-pages" || !host.Supports(repository.Type, repository.Format).Publish {
		return invalid("configure GitHub Pages host", "GitHub Pages does not serve format "+repository.Format)
	}
	if repository.Visibility != "public" {
		return invalid("configure GitHub Pages host", "GitHub Pages currently supports public repositories only")
	}
	if !validRepositoryName(repository.RemoteRepository) || !validBranch(repository.Branch) ||
		repository.Path != "" || repository.Bucket != "" || repository.Prefix != "" || repository.Region != "" || repository.Endpoint != "" || repository.UsePathStyle || repository.ReadAuth != "" || repository.CredentialBroker != "" {
		return invalid("configure GitHub Pages host", "invalid production repository configuration")
	}
	endpoints := []string{repository.CanonicalEndpoint}
	// A preview is optional. Without one there is no second site to stage to,
	// and the caller verifies the staged tree it already holds instead.
	if previewConfigured(repository) {
		if !validRepositoryName(repository.PreviewRepository) || strings.EqualFold(repository.RemoteRepository, repository.PreviewRepository) || !validBranch(repository.PreviewBranch) {
			return invalid("configure GitHub Pages host", "invalid preview repository configuration")
		}
		endpoints = append(endpoints, repository.PreviewEndpoint)
	}
	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		loopback := err == nil && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback)) {
			return invalid("configure GitHub Pages host", "Pages endpoints must use HTTPS without credentials, query, or fragment")
		}
	}
	if strings.TrimSuffix(repository.CanonicalEndpoint, "/") == strings.TrimSuffix(repository.PreviewEndpoint, "/") {
		return invalid("configure GitHub Pages host", "production and preview endpoints must be distinct")
	}
	return nil
}

func verifyPagesSite(ctx context.Context, repository, branch, endpoint string) error {
	command := exec.CommandContext(ctx, "gh", "api", "repos/"+repository+"/pages")
	output, err := command.Output()
	if err != nil {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "verify GitHub Pages site", Err: errors.New("GitHub Pages is unavailable; authenticate gh and provision the configured site")}
	}
	var configuration struct {
		BuildType     string `json:"build_type"`
		HTMLURL       string `json:"html_url"`
		Public        bool   `json:"public"`
		HTTPSEnforced bool   `json:"https_enforced"`
		Source        struct {
			Branch string `json:"branch"`
			Path   string `json:"path"`
		} `json:"source"`
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(output), 1<<20))
	if err := decoder.Decode(&configuration); err != nil || configuration.BuildType != "legacy" || configuration.Source.Branch != branch || (configuration.Source.Path != "/" && configuration.Source.Path != "") ||
		!configuration.Public || !configuration.HTTPSEnforced || !sameEndpoint(configuration.HTMLURL, endpoint) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "verify GitHub Pages site", Err: errors.New("Pages must deploy the configured branch root")}
	}
	return nil
}

func sameEndpoint(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) && strings.EqualFold(leftURL.Host, rightURL.Host) &&
		strings.EqualFold(strings.TrimSuffix(leftURL.EscapedPath(), "/"), strings.TrimSuffix(rightURL.EscapedPath(), "/"))
}

func validateStageRequest(request host.StageRequest) error {
	if !hexdigest.ValidSHA256(request.PlanID) || request.ChangeID == "" || !hexdigest.ValidSHA256(request.TreeSHA256) || (request.PreviousRevision != "" && !validGitObject(request.PreviousRevision)) || request.Directory == "" || len(request.Files) == 0 {
		return invalid("stage GitHub Pages publication", "invalid stage request")
	}
	manifest, err := app.VerifyRepository(request.Directory)
	if err != nil || manifest.TreeSHA256 != request.TreeSHA256 {
		return invalid("stage GitHub Pages publication", "staged directory does not match reviewed tree")
	}
	for index, file := range request.Files {
		if file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path || strings.HasPrefix(file.Path, "../") || strings.ContainsRune(file.Path, '\\') || file.Size < 0 || !hexdigest.ValidSHA256(file.SHA256) || (index > 0 && request.Files[index-1].Path >= file.Path) {
			return invalid("stage GitHub Pages publication", "invalid staged file descriptor")
		}
	}
	files, err := stagedFiles(request.Directory)
	if err != nil || !equalFiles(files, request.Files) {
		return invalid("stage GitHub Pages publication", "staged file descriptors do not match reviewed tree")
	}
	return nil
}

func clientRoutes(endpoint string, files []host.File) ([]host.ClientRoute, error) {
	routes := make([]host.ClientRoute, 0, len(files))
	for _, file := range files {
		routePath := file.Path
		if strings.HasSuffix(routePath, "/index.html") {
			routePath = strings.TrimSuffix(routePath, "index.html")
		}
		address, err := url.JoinPath(strings.TrimSuffix(endpoint, "/")+"/", routePath)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(routePath, "/") && !strings.HasSuffix(address, "/") {
			address += "/"
		}
		routes = append(routes, host.ClientRoute{URL: address, Size: file.Size, SHA256: file.SHA256})
	}
	return routes, nil
}

func equalFiles(left, right []host.File) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func matchesExpected(revision host.PublishedRevision, expected host.ExpectedRevision) bool {
	return revision.NativeRevision == expected.NativeRevision && revision.TreeSHA256 == expected.TreeSHA256 && revision.PlanID == expected.PlanID && revision.ChangeID == expected.ChangeID && revision.ManifestSHA256 == expected.ManifestSHA256
}

func stale(operation string, expected host.ExpectedRevision, actual host.PublishedRevision) error {
	return &host.Error{Kind: host.ErrorStale, Operation: operation, Err: fmt.Errorf("expected revision %q tree %q, found revision %q tree %q", expected.NativeRevision, expected.TreeSHA256, actual.NativeRevision, actual.TreeSHA256)}
}

func invalid(operation, message string) error {
	return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: operation, Err: errors.New(message)}
}

func infrastructure(operation string, err error) error {
	return &host.Error{Kind: host.ErrorInfrastructure, Operation: operation, Retryable: true, Err: err}
}

func validRepositoryName(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && validName(parts[0]) && validName(parts[1]) && !strings.HasSuffix(strings.ToLower(parts[1]), ".git")
}

func validName(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validBranch(value string) bool {
	if value == "" || value == "@" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, ".lock") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") {
			return false
		}
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune("~^:?*[\\", character) {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool { return hexdigest.ValidSHA256(value) }

func effectIdentifier(planID, changeID string) string {
	digest := sha256.Sum256([]byte(planID + "\x00" + changeID))
	return hex.EncodeToString(digest[:])
}

func branchRef(branch string) string      { return "refs/heads/" + branch }
func stageRef(identifier string) string   { return "refs/heads/snailmail-stage-" + identifier }
func restoreRef(identifier string) string { return "refs/heads/snailmail-restore-" + identifier }

var errRefNotFound = errors.New("Git ref not found")

type gitWorkspace struct {
	root   string
	gitDir string
}

func newGitWorkspace(ctx context.Context) (*gitWorkspace, error) {
	root, err := os.MkdirTemp("", ".snailmail-pages-git-*")
	if err != nil {
		return nil, err
	}
	workspace := &gitWorkspace{root: root, gitDir: filepath.Join(root, "repository.git")}
	if _, err := workspace.git(ctx, nil, nil, "-c", "init.defaultObjectFormat=sha1", "init", "--bare", workspace.gitDir); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("initialize Pages Git workspace: %w", err)
	}
	return workspace, nil
}

func (workspace *gitWorkspace) Close() { _ = os.RemoveAll(workspace.root) }

func (workspace *gitWorkspace) createPublication(ctx context.Context, request host.StageRequest) (string, error) {
	index := filepath.Join(workspace.root, "publication.index")
	environment := []string{"GIT_INDEX_FILE=" + index}
	for _, file := range request.Files {
		filename := filepath.Join(request.Directory, filepath.FromSlash(file.Path))
		output, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "hash-object", "-w", "--no-filters", "--", filename)
		if err != nil {
			return "", fmt.Errorf("hash Pages file %q: %w", file.Path, err)
		}
		object := strings.TrimSpace(string(output))
		if !validGitObject(object) {
			return "", errors.New("Git returned an invalid object identity")
		}
		if _, err := workspace.git(ctx, environment, nil, "--git-dir", workspace.gitDir, "update-index", "--add", "--cacheinfo", "100644", object, file.Path); err != nil {
			return "", fmt.Errorf("index Pages file %q: %w", file.Path, err)
		}
	}
	treeOutput, err := workspace.git(ctx, environment, nil, "--git-dir", workspace.gitDir, "write-tree")
	if err != nil {
		return "", err
	}
	message := publicationMessage(publicationMetadata{
		PlanID: request.PlanID, ChangeID: request.ChangeID, TreeSHA256: request.TreeSHA256,
		ManifestSHA256: fileSHA256(request.Files, "snailmail.repository.json"), PreviousRevision: request.PreviousRevision,
	})
	return workspace.commitTree(ctx, strings.TrimSpace(string(treeOutput)), "", message)
}

func (workspace *gitWorkspace) createRestoreDescriptor(ctx context.Context, staged host.StagedPublication) (string, error) {
	emptyTree, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "mktree")
	if err != nil {
		return "", err
	}
	message := boundMessage("snailmail-pages-restore/v1", publicationMetadata{
		PlanID: staged.PlanID, ChangeID: staged.ChangeID, TreeSHA256: staged.TreeSHA256,
		ManifestSHA256: fileSHA256(staged.Files, "snailmail.repository.json"), PreviousRevision: staged.PreviousRevision,
	})
	return workspace.commitTree(ctx, strings.TrimSpace(string(emptyTree)), staged.PreviousRevision, message)
}

func (workspace *gitWorkspace) commitTree(ctx context.Context, tree, parent, message string) (string, error) {
	arguments := []string{"--git-dir", workspace.gitDir, "commit-tree", tree}
	if parent != "" {
		arguments = append(arguments, "-p", parent)
	}
	environment := []string{
		"GIT_AUTHOR_NAME=snailmail", "GIT_AUTHOR_EMAIL=snailmail@invalid",
		"GIT_COMMITTER_NAME=snailmail", "GIT_COMMITTER_EMAIL=snailmail@invalid",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	}
	output, err := workspace.git(ctx, environment, strings.NewReader(message), arguments...)
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(output))
	if !validGitObject(commit) {
		return "", errors.New("Git returned an invalid commit identity")
	}
	return commit, nil
}

func (workspace *gitWorkspace) inspectPublication(ctx context.Context, commit string) (host.PublishedRevision, []host.File, publicationMetadata, error) {
	_, parents, message, err := workspace.commitEnvelope(ctx, commit)
	if err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	metadata, managed, err := parsePublicationMessage(message)
	if err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	if managed && len(parents) != 0 {
		return host.PublishedRevision{}, nil, publicationMetadata{}, errors.New("managed Pages publication is not an orphan commit")
	}
	checkout := filepath.Join(workspace.root, "checkout-"+commit[:12])
	if err := os.Mkdir(checkout, 0o700); err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	if err := workspace.materializeCommit(ctx, commit, checkout); err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	manifest, err := app.VerifyRepository(checkout)
	if err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	files, err := stagedFiles(checkout)
	if err != nil {
		return host.PublishedRevision{}, nil, publicationMetadata{}, err
	}
	revision := host.PublishedRevision{NativeRevision: commit}
	if managed {
		if metadata.TreeSHA256 != manifest.TreeSHA256 || metadata.ManifestSHA256 != fileSHA256(files, "snailmail.repository.json") {
			return host.PublishedRevision{}, nil, publicationMetadata{}, errors.New("Pages commit metadata does not match its tree")
		}
		revision.TreeSHA256 = metadata.TreeSHA256
		revision.PlanID = metadata.PlanID
		revision.ChangeID = metadata.ChangeID
		revision.ManifestSHA256 = metadata.ManifestSHA256
	}
	return revision, files, metadata, nil
}

func (workspace *gitWorkspace) inspectRestoreDescriptor(ctx context.Context, commit string) (publicationMetadata, string, error) {
	tree, parents, message, err := workspace.commitEnvelope(ctx, commit)
	if err != nil {
		return publicationMetadata{}, "", err
	}
	emptyTree, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "mktree")
	if err != nil || tree != strings.TrimSpace(string(emptyTree)) || len(parents) > 1 {
		return publicationMetadata{}, "", errors.New("invalid restore descriptor commit structure")
	}
	parent := ""
	if len(parents) == 1 {
		parent = parents[0]
		if _, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "cat-file", "-e", parent+"^{commit}"); err != nil {
			return publicationMetadata{}, "", errors.New("restore descriptor parent is unavailable")
		}
	}
	metadata, err := parseBoundMessage(message, "snailmail-pages-restore/v1")
	return metadata, parent, err
}

func (workspace *gitWorkspace) commitEnvelope(ctx context.Context, commit string) (string, []string, string, error) {
	content, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "cat-file", "-p", commit)
	if err != nil {
		return "", nil, "", err
	}
	parts := strings.SplitN(string(content), "\n\n", 2)
	if len(parts) != 2 {
		return "", nil, "", errors.New("invalid Git commit")
	}
	tree := ""
	parents := make([]string, 0, 1)
	for _, line := range strings.Split(parts[0], "\n") {
		if strings.HasPrefix(line, "tree ") {
			tree = strings.TrimPrefix(line, "tree ")
		}
		if strings.HasPrefix(line, "parent ") {
			parents = append(parents, strings.TrimPrefix(line, "parent "))
		}
	}
	if !validGitObject(tree) {
		return "", nil, "", errors.New("invalid Git commit tree")
	}
	return tree, parents, strings.TrimSpace(parts[1]), nil
}

func (workspace *gitWorkspace) fetch(ctx context.Context, remote, ref string) (string, error) {
	commit, err := workspace.lsRemote(ctx, remote, ref)
	if err != nil {
		return "", err
	}
	if _, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "fetch", "--no-tags", "--depth=2", remote, ref); err != nil {
		return "", err
	}
	return commit, nil
}

func (workspace *gitWorkspace) lsRemote(ctx context.Context, remote, ref string) (string, error) {
	output, err := workspace.git(ctx, nil, nil, "ls-remote", "--refs", remote, ref)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return "", errRefNotFound
	}
	if len(fields) != 2 || fields[1] != ref || !validGitObject(fields[0]) {
		return "", errors.New("remote returned an invalid ref")
	}
	return fields[0], nil
}

func (workspace *gitWorkspace) ensureRef(ctx context.Context, remote, ref, commit string) error {
	existing, err := workspace.lsRemote(ctx, remote, ref)
	if err == nil {
		if existing == commit {
			return nil
		}
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "create immutable GitHub Pages ref", Err: errors.New("immutable ref conflicts with reviewed commit")}
	}
	if !errors.Is(err, errRefNotFound) {
		return infrastructure("inspect immutable GitHub Pages ref", err)
	}
	if _, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "push", remote, commit+":"+ref); err != nil {
		observed, observeErr := workspace.lsRemote(ctx, remote, ref)
		if observeErr == nil && observed == commit {
			return nil
		}
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "create immutable GitHub Pages ref", EffectMayHaveOccurred: true, Err: err}
	}
	return nil
}

func (workspace *gitWorkspace) replaceRef(ctx context.Context, remote, ref, commit string) error {
	current, err := workspace.lsRemote(ctx, remote, ref)
	if errors.Is(err, errRefNotFound) {
		current = ""
	} else if err != nil {
		return infrastructure("inspect preview GitHub Pages ref", err)
	}
	return workspace.compareAndSwapRef(ctx, remote, ref, current, commit)
}

func (workspace *gitWorkspace) compareAndSwapRef(ctx context.Context, remote, ref, expected, desired string) error {
	lease := "--force-with-lease=" + ref + ":" + expected
	specification := desired + ":" + ref
	if desired == "" {
		specification = ":" + ref
	}
	if _, err := workspace.git(ctx, nil, nil, "--git-dir", workspace.gitDir, "push", lease, remote, specification); err != nil {
		observed, observeErr := workspace.lsRemote(ctx, remote, ref)
		if desired == "" && errors.Is(observeErr, errRefNotFound) {
			return nil
		}
		if observeErr == nil && observed == desired {
			return nil
		}
		return err
	}
	return nil
}

func (workspace *gitWorkspace) git(ctx context.Context, environment []string, stdin io.Reader, arguments ...string) ([]byte, error) {
	output, err := workspace.gitRaw(ctx, environment, stdin, arguments...)
	return bytes.TrimSpace(output), err
}

func (workspace *gitWorkspace) gitRaw(ctx context.Context, environment []string, stdin io.Reader, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = workspace.root
	command.Stdin = stdin
	command.Env = append(isolatedGitEnvironment(), environment...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (workspace *gitWorkspace) materializeCommit(ctx context.Context, commit, destination string) error {
	listing, err := workspace.gitRaw(ctx, nil, nil, "--git-dir", workspace.gitDir, "ls-tree", "-rz", "--full-tree", commit)
	if err != nil {
		return err
	}
	for _, entry := range bytes.Split(listing, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		metadata, filename, found := bytes.Cut(entry, []byte{'\t'})
		fields := strings.Fields(string(metadata))
		name := string(filename)
		if !found || len(fields) != 3 || fields[0] != "100644" || fields[1] != "blob" || !validGitObject(fields[2]) || name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\\') {
			return errors.New("Pages commit contains an unsafe tree entry")
		}
		content, err := workspace.gitRaw(ctx, nil, nil, "--git-dir", workspace.gitDir, "cat-file", "blob", fields[2])
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func isolatedGitEnvironment() []string {
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "GIT_") {
			environment = append(environment, entry)
		}
	}
	return append(environment,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=credential.https://github.com.helper", "GIT_CONFIG_VALUE_0=!gh auth git-credential",
	)
}

func publicationMessage(metadata publicationMetadata) string {
	return boundMessage(publicationHeader, metadata)
}

func boundMessage(header string, metadata publicationMetadata) string {
	return header + "\nplan-id=" + metadata.PlanID + "\nchange-id=" + metadata.ChangeID + "\ntree-sha256=" + metadata.TreeSHA256 + "\nmanifest-sha256=" + metadata.ManifestSHA256 + "\nprevious-revision=" + metadata.PreviousRevision + "\n"
}

func parsePublicationMessage(message string) (publicationMetadata, bool, error) {
	message = strings.TrimSpace(message)
	if !strings.HasPrefix(message, "snailmail-pages/") {
		return publicationMetadata{}, false, nil
	}
	metadata, err := parseBoundMessage(message, publicationHeader)
	return metadata, true, err
}

func parseBoundMessage(message, header string) (publicationMetadata, error) {
	lines := strings.Split(strings.TrimSpace(message), "\n")
	if len(lines) != 6 || lines[0] != header || !strings.HasPrefix(lines[1], "plan-id=") || !strings.HasPrefix(lines[2], "change-id=") || !strings.HasPrefix(lines[3], "tree-sha256=") || !strings.HasPrefix(lines[4], "manifest-sha256=") || !strings.HasPrefix(lines[5], "previous-revision=") {
		return publicationMetadata{}, errors.New("invalid Pages publication metadata")
	}
	metadata := publicationMetadata{
		PlanID: strings.TrimPrefix(lines[1], "plan-id="), ChangeID: strings.TrimPrefix(lines[2], "change-id="), TreeSHA256: strings.TrimPrefix(lines[3], "tree-sha256="),
		ManifestSHA256: strings.TrimPrefix(lines[4], "manifest-sha256="), PreviousRevision: strings.TrimPrefix(lines[5], "previous-revision="),
	}
	if !hexdigest.ValidSHA256(metadata.PlanID) || metadata.ChangeID == "" || !hexdigest.ValidSHA256(metadata.TreeSHA256) || !hexdigest.ValidSHA256(metadata.ManifestSHA256) || (metadata.PreviousRevision != "" && !validGitObject(metadata.PreviousRevision)) || strings.ContainsAny(metadata.ChangeID, "\r\n") {
		return publicationMetadata{}, errors.New("invalid Pages publication binding")
	}
	return metadata, nil
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func fileSHA256(files []host.File, name string) string {
	for _, file := range files {
		if file.Path == name {
			return file.SHA256
		}
	}
	return ""
}

func validGitObject(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hashFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func stagedFiles(directory string) ([]host.File, error) {
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
		return nil, errors.New("Pages management manifest is missing")
	}
	digest, err := hashFile(management)
	if err != nil {
		return nil, err
	}
	files = append(files, host.File{Path: "snailmail.repository.json", Size: info.Size(), SHA256: digest})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files, nil
}
