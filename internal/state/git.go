package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func AcquireWorkspaceLock(root string) (func(), error) {
	name, err := WorkspacePath(root, filepath.ToSlash(filepath.Join(".snailmail", "workspace.lock")))
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(name)
	if err := makeDirectoriesDurable(directory, 0o755); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("another snailmail workspace operation is running")
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}

func RequireGitRepository(root string) error {
	if _, err := gitOutput(root, "rev-parse", "--git-dir"); err != nil {
		return errors.New("workspace must be inside a Git repository")
	}
	return nil
}

func RequireCleanGit(root string) (string, error) {
	return requireCleanGit(root, nil)
}

func RequireCleanGitAllowingUntracked(root string, relativePaths []string) (string, error) {
	allowed := make(map[string]bool, len(relativePaths))
	for _, name := range relativePaths {
		if err := validateRelativePath(name); err != nil {
			return "", err
		}
		allowed[filepath.ToSlash(name)] = true
	}
	return requireCleanGit(root, allowed)
}

func requireCleanGit(root string, allowedUntracked map[string]bool) (string, error) {
	if err := requireCompleteGitHistory(root); err != nil {
		return "", err
	}
	if _, err := symbolicHead(root); err != nil {
		return "", err
	}
	revision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return "", errors.New("workspace must be a Git repository with at least one commit")
	}
	status, err := gitStatusOutput(root)
	if err != nil {
		return "", err
	}
	authoritative, err := authoritativePaths(root)
	if err != nil {
		return "", err
	}
	if err := validateGitStatusAllowingUntracked(status, allowedUntracked, authoritative); err != nil {
		return "", err
	}
	if err := requireAuthoritativeFilesCommitted(root, revision, authoritative, allowedUntracked); err != nil {
		return "", err
	}
	confirmedRevision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || confirmedRevision != revision {
		return "", errors.New("Git revision changed while validating workspace")
	}
	return revision, nil
}

func validateGitStatusAllowingUntracked(status string, allowedUntracked, authoritative map[string]bool) error {
	for _, line := range strings.Split(status, "\n") {
		if line == "" {
			continue
		}
		if len(line) < 4 {
			return errors.New("cannot parse Git status")
		}
		name := filepath.ToSlash(strings.TrimSpace(line[3:]))
		if strings.HasPrefix(line, "?? ") && allowedUntracked[name] {
			continue
		}
		if err := validateGitStatus(line, nil, authoritative); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePlanGit accepts the reviewed base commit, its exact publication
// ledger commit, or that ledger commit followed by this plan's deployment receipt.
func ValidatePlanGit(root, baseRevision, planID string, repositories []string) (bool, error) {
	if err := requireCompleteGitHistory(root); err != nil {
		return false, err
	}
	if _, err := symbolicHead(root); err != nil {
		return false, err
	}
	current, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}
	if current == baseRevision {
		allowedLedgers := publicationWorkspacePaths(repositories)
		status, err := gitStatusOutput(root)
		if err != nil {
			return false, err
		}
		authoritative, err := authoritativePaths(root)
		if err != nil {
			return false, err
		}
		if err := validateGitStatus(status, allowedLedgers, authoritative); err != nil {
			return false, err
		}
		if err := requireAuthoritativeFilesCommitted(root, baseRevision, authoritative, allowedLedgers); err != nil {
			return false, err
		}
		confirmed, err := gitOutput(root, "rev-parse", "HEAD")
		if err != nil || confirmed != baseRevision {
			return false, errors.New("stale plan: Git revision changed")
		}
		return false, nil
	}
	if _, err := RequireCleanGit(root); err != nil {
		return false, err
	}
	ledgerRevision := current
	if deployment, deploymentErr := isPlanDeploymentCommit(root, current, planID); deploymentErr != nil {
		return false, deploymentErr
	} else if deployment {
		ledgerRevision, err = gitOutput(root, "rev-parse", current+"^")
		if err != nil {
			return false, errors.New("invalid deployment receipt commit")
		}
	}
	parent, err := gitOutput(root, "rev-parse", ledgerRevision+"^")
	if err != nil || parent != baseRevision {
		return false, errors.New("stale plan: Git revision changed")
	}
	message, err := gitOutput(root, "log", "-1", "--format=%B", ledgerRevision)
	if err != nil || !hasPlanTrailer(message, planID) {
		return false, errors.New("stale plan: Git revision changed")
	}
	paths, err := gitChangedPaths(root, ledgerRevision)
	if err != nil || len(paths) == 0 {
		return false, errors.New("invalid publication ledger commit")
	}
	for _, name := range paths {
		relative, inside, err := workspaceRelativeGitPath(root, name)
		if err != nil {
			return false, err
		}
		if !inside || !strings.HasPrefix(relative, "publications/") || !strings.HasSuffix(relative, ".jsonl") {
			return false, errors.New("publication ledger commit changed non-ledger paths")
		}
	}
	return true, nil
}

func PlanLedgerRevision(root, planID string) (string, error) {
	current, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	deployment, err := isPlanDeploymentCommit(root, current, planID)
	if err != nil || !deployment {
		return current, err
	}
	return gitOutput(root, "rev-parse", current+"^")
}

func isPlanDeploymentCommit(root, revision, planID string) (bool, error) {
	message, err := gitOutput(root, "log", "-1", "--format=%B", revision)
	if err != nil || !hasPlanTrailer(message, planID) || !strings.HasPrefix(message, "record snailmail deployments\n") {
		return false, nil
	}
	paths, err := gitChangedPaths(root, revision)
	if err != nil || len(paths) == 0 {
		return false, errors.New("invalid deployment receipt commit")
	}
	for _, name := range paths {
		relative, inside, err := workspaceRelativeGitPath(root, name)
		if err != nil {
			return false, err
		}
		if !inside || !strings.HasPrefix(relative, "deployments/") || !strings.HasSuffix(relative, ".json") {
			return false, errors.New("deployment receipt commit changed unrelated paths")
		}
	}
	return true, nil
}

func CommitPublicationLedgers(root, planID, baseRevision string, repositories []string) (string, error) {
	if len(repositories) == 0 {
		return baseRevision, nil
	}
	headRef, err := symbolicHead(root)
	if err != nil {
		return "", err
	}
	current, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || current != baseRevision {
		return "", errors.New("stale plan: Git changed before ledger commit")
	}
	indexPath, err := resolveGitPath(root, "index")
	if err != nil {
		return "", err
	}
	releaseIndex, err := acquireGitLock(indexPath + ".lock")
	if err != nil {
		return "", errors.New("Git index is busy")
	}
	defer releaseIndex()
	confirmedRef, err := symbolicHead(root)
	if err != nil || confirmedRef != headRef {
		return "", errors.New("Git branch changed before ledger commit")
	}
	confirmedRevision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || confirmedRevision != baseRevision {
		return "", errors.New("stale plan: Git changed before ledger commit")
	}
	authoritative, err := authoritativePaths(root)
	if err != nil {
		return "", err
	}
	status, err := gitStatusOutput(root)
	if err != nil {
		return "", err
	}
	allowedLedgers := publicationWorkspacePaths(repositories)
	if err := validateGitStatus(status, allowedLedgers, authoritative); err != nil {
		return "", err
	}
	if err := requireAuthoritativeFilesCommitted(root, baseRevision, authoritative, allowedLedgers); err != nil {
		return "", err
	}
	expectedPaths, err := publicationGitPaths(root, repositories)
	if err != nil {
		return "", err
	}
	stagedPaths, err := gitPathOutput(root, "diff", "--cached", "--name-only", "-z", baseRevision, "--")
	if err != nil {
		return "", err
	}
	for _, name := range stagedPaths {
		if !expectedPaths[name] {
			return "", errors.New("Git index changed before ledger commit")
		}
	}
	backupIndex, err := copyGitIndex(indexPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(backupIndex)
	temporaryIndex, err := copyGitIndex(indexPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(temporaryIndex)
	indexEnvironment := replaceEnvironment(os.Environ(), "GIT_INDEX_FILE", temporaryIndex)
	arguments := []string{"add", "--"}
	for _, repository := range repositories {
		relative := filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))
		tracked, err := gitOutputEnv(root, indexEnvironment, "ls-files", "--", relative)
		if err != nil {
			return "", err
		}
		if tracked != "" {
			if _, err := gitOutputEnv(root, indexEnvironment, "update-index", "--no-assume-unchanged", "--no-skip-worktree", "--", relative); err != nil {
				return "", fmt.Errorf("normalize publication ledger index flags: %w", err)
			}
		}
		arguments = append(arguments, relative)
	}
	if _, err := gitOutputEnv(root, indexEnvironment, arguments...); err != nil {
		return "", fmt.Errorf("stage publication ledgers: %w", err)
	}
	tree, err := gitOutputEnv(root, indexEnvironment, "write-tree")
	if err != nil {
		return "", fmt.Errorf("write publication ledger tree: %w", err)
	}
	if err := validatePublicationTree(root, baseRevision, tree, expectedPaths); err != nil {
		return "", err
	}
	if err := syncFile(temporaryIndex); err != nil {
		return "", fmt.Errorf("sync publication ledger index: %w", err)
	}
	message := "record snailmail publications\n\nSnailmail-Plan: " + planID + "\n"
	command := gitCommand(root, "commit-tree", tree, "-p", baseRevision)
	command.Stdin = strings.NewReader(message)
	command.Env = replaceEnvironment(indexEnvironment,
		"GIT_AUTHOR_NAME", "snailmail",
		"GIT_AUTHOR_EMAIL", "snailmail@localhost",
		"GIT_COMMITTER_NAME", "snailmail",
		"GIT_COMMITTER_EMAIL", "snailmail@localhost",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("create publication ledger commit: %w: %s", err, strings.TrimSpace(string(output)))
	}
	commit := strings.TrimSpace(string(output))
	if err := os.Rename(temporaryIndex, indexPath); err != nil {
		return "", fmt.Errorf("install publication ledger index: %w", err)
	}
	if err := syncStateDirectory(filepath.Dir(indexPath)); err != nil {
		return "", restoreGitIndex(backupIndex, indexPath, fmt.Errorf("persist publication ledger index: %w", err))
	}
	if err := gitRun(root, "update-ref", headRef, commit, baseRevision); err != nil {
		return "", restoreGitIndex(backupIndex, indexPath, fmt.Errorf("commit publication ledger with compare-and-swap: %w", err))
	}
	confirmedRef, refErr := symbolicHead(root)
	confirmedHead, headErr := gitOutput(root, "rev-parse", "HEAD")
	if refErr != nil || headErr != nil || confirmedRef != headRef || confirmedHead != commit {
		if rollbackErr := gitRun(root, "update-ref", headRef, baseRevision, commit); rollbackErr != nil {
			return "", fmt.Errorf("Git branch changed during ledger commit and rollback failed: %w", rollbackErr)
		}
		return "", restoreGitIndex(backupIndex, indexPath, errors.New("Git branch changed during ledger commit"))
	}
	return commit, nil
}

func ValidatePublicationCommitPaths(root, revision string, repositories []string) error {
	expected, err := publicationGitPaths(root, repositories)
	if err != nil {
		return err
	}
	paths, err := gitChangedPaths(root, revision)
	if err != nil {
		return err
	}
	actual := make(map[string]bool, len(paths))
	for _, name := range paths {
		actual[name] = true
	}
	if len(actual) != len(expected) {
		return errors.New("publication commit changed an unexpected ledger set")
	}
	for name := range expected {
		if !actual[name] {
			return fmt.Errorf("publication commit did not record %q", name)
		}
	}
	return nil
}

func AssertGitRevision(root, expected string) error {
	current, err := RequireCleanGit(root)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("Git revision changed during apply")
	}
	return nil
}

// AcquireGitRevisionLock blocks normal branch, index, and checkout updates while
// a verified target is switched to the tree authorized by expectedRevision.
func AcquireGitRevisionLock(root, expectedRevision string) (func(), error) {
	headRef, err := symbolicHead(root)
	if err != nil {
		return nil, err
	}
	indexPath, err := resolveGitPath(root, "index")
	if err != nil {
		return nil, err
	}
	headPath, err := resolveGitPath(root, "HEAD")
	if err != nil {
		return nil, err
	}
	refPath, err := resolveGitPath(root, headRef)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		return nil, err
	}
	var releases []func()
	releaseAll := func() {
		for index := len(releases) - 1; index >= 0; index-- {
			releases[index]()
		}
	}
	for _, name := range []string{indexPath + ".lock", headPath + ".lock", refPath + ".lock"} {
		release, err := acquireGitLock(name)
		if err != nil {
			releaseAll()
			return nil, errors.New("Git changed or is busy before publication")
		}
		releases = append(releases, release)
	}
	confirmedRef, err := symbolicHead(root)
	if err != nil || confirmedRef != headRef {
		releaseAll()
		return nil, errors.New("Git branch changed before publication")
	}
	if err := AssertGitRevision(root, expectedRevision); err != nil {
		releaseAll()
		return nil, err
	}
	return releaseAll, nil
}

func requireCompleteGitHistory(root string) error {
	shallow, err := gitOutput(root, "rev-parse", "--is-shallow-repository")
	if err != nil || shallow == "true" {
		return errors.New("workspace requires complete, non-shallow Git history")
	}
	command := gitCommand(root, "config", "--get", "extensions.partialClone")
	if output, err := command.Output(); err == nil && strings.TrimSpace(string(output)) != "" {
		return errors.New("workspace requires complete, non-partial Git history")
	}
	return nil
}

func requireAuthoritativeFilesCommitted(root, revision string, authoritative, allowedChanges map[string]bool) error {
	names := make([]string, 0, len(authoritative))
	for name := range authoritative {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if allowedChanges[name] {
			continue
		}
		treePath, err := workspaceGitPath(root, name)
		if err != nil {
			return err
		}
		expected, err := gitOutput(root, "rev-parse", revision+":"+treePath)
		if err != nil {
			return fmt.Errorf("authoritative state %q is not committed to Git", name)
		}
		workspacePath, err := WorkspacePath(root, name)
		if err != nil {
			return err
		}
		info, err := os.Lstat(workspacePath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("authoritative state %q is not a regular committed file", name)
		}
		content, err := os.ReadFile(workspacePath)
		if err != nil {
			return err
		}
		actual, err := gitHashObject(root, content)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("authoritative state %q differs from Git", name)
		}
	}
	return nil
}

func validateGitStatus(status string, allowedChanges, authoritative map[string]bool) error {
	for _, line := range strings.Split(status, "\n") {
		if line == "" {
			continue
		}
		if len(line) < 4 {
			return errors.New("cannot parse Git status")
		}
		name := filepath.ToSlash(strings.TrimSpace(line[3:]))
		if allowedChanges[name] {
			continue
		}
		if strings.HasPrefix(line, "?? ") && !authoritative[name] && !isAuthoritativePath(name) {
			continue
		}
		return fmt.Errorf("workspace has uncommitted authoritative or tracked changes at %q", name)
	}
	return nil
}

func authoritativePaths(root string) (map[string]bool, error) {
	paths := map[string]bool{ManifestFilename: true}
	manifest, err := LoadManifest(root)
	if err != nil {
		return nil, err
	}
	for _, repository := range manifest.Repositories {
		paths[filepath.ToSlash(repository.Lock)] = true
	}
	for _, key := range manifest.Keys {
		paths[filepath.ToSlash(key.PublicKeyPath)] = true
		paths[filepath.ToSlash(key.PublicArmorPath)] = true
	}
	for _, pattern := range []string{
		filepath.Join(root, "repos", "*.lock.toml"),
		filepath.Join(root, "publications", "*.jsonl"),
		filepath.Join(root, "deployments", "*.json"),
		filepath.Join(root, "docs", "install-*.md"),
		filepath.Join(root, "keys", "*.gpg"),
		filepath.Join(root, "keys", "*.asc"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, name := range matches {
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return nil, err
			}
			paths[filepath.ToSlash(relative)] = true
		}
	}
	return paths, nil
}

func isAuthoritativePath(name string) bool {
	return name == ManifestFilename || strings.HasPrefix(name, "repos/") || strings.HasPrefix(name, "publications/") || strings.HasPrefix(name, "deployments/") || strings.HasPrefix(name, "docs/install-") || strings.HasPrefix(name, "keys/")
}

func hasPlanTrailer(message, planID string) bool {
	for _, line := range strings.Split(message, "\n") {
		if strings.TrimSpace(line) == "Snailmail-Plan: "+planID {
			return true
		}
	}
	return false
}

func symbolicHead(root string) (string, error) {
	name, err := gitOutput(root, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || !strings.HasPrefix(name, "refs/") {
		return "", errors.New("workspace requires Git HEAD to be attached to a branch")
	}
	return name, nil
}

func publicationGitPaths(root string, repositories []string) (map[string]bool, error) {
	paths := make(map[string]bool, len(repositories))
	for _, repository := range repositories {
		name, err := workspaceGitPath(root, filepath.ToSlash(filepath.Join("publications", repository+".jsonl")))
		if err != nil {
			return nil, err
		}
		paths[name] = true
	}
	return paths, nil
}

func publicationWorkspacePaths(repositories []string) map[string]bool {
	paths := make(map[string]bool, len(repositories))
	for _, repository := range repositories {
		paths[filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))] = true
	}
	return paths
}

func workspaceGitPath(root, relative string) (string, error) {
	prefix, err := gitOutput(root, "rev-parse", "--show-prefix")
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(filepath.FromSlash(prefix), filepath.FromSlash(relative))), nil
}

func workspaceRelativeGitPath(root, name string) (string, bool, error) {
	prefix, err := gitOutput(root, "rev-parse", "--show-prefix")
	if err != nil {
		return "", false, err
	}
	prefix = filepath.ToSlash(prefix)
	name = filepath.ToSlash(name)
	if prefix == "" {
		return name, true, nil
	}
	if !strings.HasPrefix(name, prefix) {
		return "", false, nil
	}
	return strings.TrimPrefix(name, prefix), true, nil
}

func gitChangedPaths(root, revision string) ([]string, error) {
	return gitPathOutput(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", revision)
}

func validatePublicationTree(root, baseRevision, tree string, expectedPaths map[string]bool) error {
	paths, err := gitPathOutput(root, "diff", "--name-only", "-z", baseRevision, tree, "--")
	if err != nil {
		return err
	}
	actualPaths := make(map[string]bool, len(paths))
	for _, name := range paths {
		actualPaths[name] = true
	}
	if len(actualPaths) != len(expectedPaths) {
		return errors.New("prepared publication tree changed an unexpected ledger set")
	}
	for treePath := range expectedPaths {
		if !actualPaths[treePath] {
			return fmt.Errorf("prepared publication tree did not record %q", treePath)
		}
		relative, inside, err := workspaceRelativeGitPath(root, treePath)
		if err != nil {
			return err
		}
		if !inside {
			return fmt.Errorf("prepared publication path %q is outside workspace", treePath)
		}
		name, err := WorkspacePath(root, relative)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		expectedBlob, err := gitHashObject(root, content)
		if err != nil {
			return err
		}
		actualBlob, err := gitOutput(root, "rev-parse", tree+":"+treePath)
		if err != nil || actualBlob != expectedBlob {
			return fmt.Errorf("prepared publication ledger %q does not match worktree bytes", relative)
		}
	}
	return nil
}

func gitPathOutput(root string, arguments ...string) ([]string, error) {
	output, err := gitCommand(root, arguments...).Output()
	if err != nil {
		return nil, err
	}
	var result []string
	for _, name := range bytes.Split(output, []byte{0}) {
		if len(name) != 0 {
			result = append(result, filepath.ToSlash(string(name)))
		}
	}
	return result, nil
}

func resolveGitPath(root, name string) (string, error) {
	resolved, err := gitOutput(root, "rev-parse", "--git-path", name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(root, resolved)
	}
	return filepath.Clean(resolved), nil
}

func acquireGitLock(name string) (func(), error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	return func() { _ = os.Remove(name) }, nil
}

func copyGitIndex(indexPath string) (string, error) {
	source, err := os.Open(indexPath)
	if err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(indexPath), "snailmail-index-*")
	if err != nil {
		_ = source.Close()
		return "", err
	}
	name := temporary.Name()
	if _, err := io.Copy(temporary, source); err != nil {
		_ = source.Close()
		_ = temporary.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := source.Close(); err != nil {
		_ = temporary.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func syncFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func restoreGitIndex(backup, indexPath string, cause error) error {
	if err := os.Rename(backup, indexPath); err != nil {
		return fmt.Errorf("%v; restore Git index: %w", cause, err)
	}
	if err := syncStateDirectory(filepath.Dir(indexPath)); err != nil {
		return fmt.Errorf("%v; persist restored Git index: %w", cause, err)
	}
	return cause
}

func gitHashObject(root string, content []byte) (string, error) {
	command := gitCommand(root, "hash-object", "--stdin")
	command.Stdin = bytes.NewReader(content)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitCommand(root string, arguments ...string) *exec.Cmd {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = replaceEnvironment(os.Environ(), "GIT_OPTIONAL_LOCKS", "0")
	return command
}

func gitOutput(root string, arguments ...string) (string, error) {
	output, err := gitCommand(root, arguments...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitStatusOutput(root string) (string, error) {
	output, err := gitCommand(root, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(output), "\r\n"), nil
}

func gitOutputEnv(root string, environment []string, arguments ...string) (string, error) {
	command := gitCommand(root, arguments...)
	command.Env = replaceEnvironment(environment, "GIT_OPTIONAL_LOCKS", "0")
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func gitRun(root string, arguments ...string) error {
	command := gitCommand(root, arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func replaceEnvironment(environment []string, values ...string) []string {
	replacements := make(map[string]string, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		replacements[values[index]] = values[index+1]
	}
	result := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := replacements[key]; replaced {
				continue
			}
		}
		result = append(result, entry)
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	return result
}
