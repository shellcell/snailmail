package state

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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
	return RequireGitRepositoryContext(context.Background(), root)
}

func RequireGitRepositoryContext(ctx context.Context, root string) error {
	if _, err := gitOutputContext(ctx, root, "rev-parse", "--git-dir"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("workspace must be inside a Git repository")
	}
	return nil
}

func RequireCompleteGitHistoryContext(ctx context.Context, root string) error {
	return requireCompleteGitHistoryContext(ctx, root)
}

func RequireCleanGit(root string) (string, error) {
	return requireCleanGitContext(context.Background(), root, nil)
}

func RequireCleanGitContext(ctx context.Context, root string) (string, error) {
	return requireCleanGitContext(ctx, root, nil)
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
	return requireCleanGitContext(context.Background(), root, allowedUntracked)
}

func requireCleanGitContext(ctx context.Context, root string, allowedUntracked map[string]bool) (string, error) {
	if err := requireCompleteGitHistoryContext(ctx, root); err != nil {
		return "", err
	}
	if _, err := symbolicHeadContext(ctx, root); err != nil {
		return "", err
	}
	revision, err := gitOutputContext(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("workspace must be a Git repository with at least one commit")
	}
	status, err := gitStatusOutputContext(ctx, root)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	authoritative, err := authoritativePaths(root)
	if err != nil {
		return "", err
	}
	if err := validateGitStatusAllowingUntracked(status, allowedUntracked, authoritative); err != nil {
		return "", err
	}
	if err := requireAuthoritativeFilesCommittedContext(ctx, root, revision, authoritative, allowedUntracked); err != nil {
		return "", err
	}
	confirmedRevision, err := gitOutputContext(ctx, root, "rev-parse", "HEAD")
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil || confirmedRevision != revision {
		return "", errors.New("Git revision changed while validating workspace")
	}
	return revision, nil
}

func validateGitStatusAllowingUntracked(status string, allowedUntracked, authoritative map[string]bool) error {
	entries, err := parseGitStatus(status)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.code == "??" && len(entry.paths) == 1 && allowedUntracked[entry.paths[0]] {
			continue
		}
		for _, name := range entry.paths {
			if entry.code == "??" && !authoritative[name] && !isAuthoritativePath(name) {
				continue
			}
			return fmt.Errorf("workspace has uncommitted authoritative or tracked changes at %q", name)
		}
	}
	return nil
}

// ValidatePlanGit accepts the reviewed base commit, its exact publication
// ledger commit, or that ledger commit followed by this plan's deployment receipt.
func ValidatePlanGit(root, baseRevision, planID string, repositories, deploymentRepositories []string) (bool, error) {
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
		if err := ValidateDeploymentCommitPaths(root, current, deploymentRepositories); err != nil {
			return false, err
		}
		ledgerRevision, err = gitOutput(root, "rev-parse", current+"^")
		if err != nil {
			return false, errors.New("invalid deployment receipt commit")
		}
		if len(repositories) == 0 && ledgerRevision == baseRevision {
			return true, nil
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
	return isPlanDeploymentCommitContext(context.Background(), root, revision, planID)
}

func isPlanDeploymentCommitContext(ctx context.Context, root, revision, planID string) (bool, error) {
	message, err := gitOutputContext(ctx, root, "log", "-1", "--format=%B", revision)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil || !hasPlanTrailer(message, planID) || !strings.HasPrefix(message, "record snailmail deployments\n") {
		return false, nil
	}
	paths, err := gitChangedPathsContext(ctx, root, revision)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
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

func ValidateDeploymentCommitPaths(root, revision string, repositories []string) error {
	expected := make(map[string]bool, len(repositories))
	for _, repository := range repositories {
		if err := ValidateRepositoryName(repository); err != nil {
			return err
		}
		path, err := workspaceGitPath(root, filepath.ToSlash(filepath.Join("deployments", repository+".json")))
		if err != nil {
			return err
		}
		expected[path] = true
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
		return errors.New("deployment commit changed an unexpected receipt set")
	}
	for name := range expected {
		if !actual[name] {
			return fmt.Errorf("deployment commit did not record %q", name)
		}
	}
	return nil
}

func AssertGitRevision(root, expected string) error {
	return AssertGitRevisionContext(context.Background(), root, expected)
}

func AssertGitRevisionContext(ctx context.Context, root, expected string) error {
	current, err := RequireCleanGitContext(ctx, root)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("Git revision changed during operation")
	}
	return nil
}

// AssertGitHeadRevision checks only that HEAD still names the expected commit.
//
// It is for callers holding the locks AcquireGitRevisionLock takes, which
// already prevent Git from moving the branch, updating the index or checking
// anything out. Under those locks the full workspace validation cannot find
// anything new, and repeating it once per repository made a publication cost
// grow with the square of the repository count.
func AssertGitHeadRevision(root, expected string) error {
	current, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("read Git revision during publication: %w", err)
	}
	if current != expected {
		return errors.New("Git revision changed during operation")
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
	names := []string{indexPath + ".lock", headPath + ".lock", refPath + ".lock"}
	for _, name := range names {
		release, err := acquireGitLock(name)
		if err != nil {
			releaseAll()
			return nil, fmt.Errorf("Git changed or is busy before publication: %w", describeGitLockConflict(name, names, err))
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
	return requireCompleteGitHistoryContext(context.Background(), root)
}

func requireCompleteGitHistoryContext(ctx context.Context, root string) error {
	shallow, err := gitOutputContext(ctx, root, "rev-parse", "--is-shallow-repository")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || shallow == "true" {
		return errors.New("workspace requires complete, non-shallow Git history")
	}
	command := gitCommandContext(ctx, root, "config", "--get", "extensions.partialClone")
	output, configErr := command.Output()
	if configErr == nil && strings.TrimSpace(string(output)) != "" {
		return errors.New("workspace requires complete, non-partial Git history")
	}
	if configErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(configErr, &exitErr) || exitErr.ExitCode() != 1 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("inspect partial Git configuration: %w", configErr)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func requireAuthoritativeFilesCommitted(root, revision string, authoritative, allowedChanges map[string]bool) error {
	return requireAuthoritativeFilesCommittedContext(context.Background(), root, revision, authoritative, allowedChanges)
}

// requireAuthoritativeFilesCommittedContext proves that every authoritative
// file is present in revision and identical to the worktree.
//
// Both sides are resolved in one batch each. The worktree side is hashed by Git
// from the file itself rather than through the index, so neither
// assume-unchanged nor skip-worktree can hide a change, and hashing by path
// applies the same .gitattributes and core.autocrlf clean filters that produced
// the committed blob — comparing raw worktree bytes would report every file as
// changed in any repository that converts line endings.
func requireAuthoritativeFilesCommittedContext(ctx context.Context, root, revision string, authoritative, allowedChanges map[string]bool) error {
	names := make([]string, 0, len(authoritative))
	for name := range authoritative {
		if !allowedChanges[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}
	prefix, err := gitPrefix(ctx, root)
	if err != nil {
		return err
	}
	treePaths := make([]string, 0, len(names))
	for _, name := range names {
		// hash-object reads its path list as newline-separated text, so a name
		// carrying a newline could inject an entry. Authoritative names come from
		// validated manifest fields and fixed globs, but a file on disk can still
		// be named adversarially.
		if strings.ContainsAny(name, "\n\r") {
			return fmt.Errorf("authoritative state %q has an unusable name", name)
		}
		// A symlink with the same bytes is not a committed regular file, and a
		// content comparison alone would not tell them apart.
		workspacePath, err := WorkspacePath(root, name)
		if err != nil {
			return err
		}
		info, err := os.Lstat(workspacePath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("authoritative state %q is not a regular committed file", name)
		}
		treePaths = append(treePaths, filepath.ToSlash(filepath.Join(filepath.FromSlash(prefix), filepath.FromSlash(name))))
	}
	committed, err := revisionBlobIDs(ctx, root, revision, treePaths)
	if err != nil {
		return err
	}
	for index, name := range names {
		if committed[index] == "" {
			return fmt.Errorf("authoritative state %q is not committed to Git", name)
		}
	}
	worktree, err := worktreeBlobIDs(ctx, root, treePaths)
	if err != nil {
		return err
	}
	for index, name := range names {
		if worktree[index] != committed[index] {
			return fmt.Errorf("authoritative state %q differs from Git", name)
		}
	}
	return nil
}

// revisionBlobIDs resolves every tree path in revision through one cat-file
// batch, reporting an empty ID for a path revision does not contain.
func revisionBlobIDs(ctx context.Context, root, revision string, treePaths []string) ([]string, error) {
	var query bytes.Buffer
	for _, treePath := range treePaths {
		query.WriteString(revision + ":" + treePath + "\n")
	}
	command := gitCommandContext(ctx, root, "cat-file", "--batch-check")
	command.Stdin = &query
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("resolve committed authoritative state: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(output), "\n"), "\n")
	if len(lines) != len(treePaths) {
		return nil, errors.New("cannot resolve committed authoritative state")
	}
	identifiers := make([]string, len(treePaths))
	for index, line := range lines {
		// A resolvable object answers "<sha> <type> <size>"; anything else, such
		// as "<request> missing", means revision does not contain that path.
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[1] == "blob" {
			identifiers[index] = fields[0]
		}
	}
	return identifiers, nil
}

// maxBatchObjectSize bounds a single object read through catFileBatch. Ledger
// blobs are the only use, and they are line-oriented records.
const maxBatchObjectSize = 64 << 20

type batchObject struct {
	id      string
	content []byte
}

// catFileBatch reads every requested revspec through one cat-file process
// rather than one `git show` per object. Objects the repository does not
// contain come back with an empty id.
func catFileBatch(ctx context.Context, root string, revspecs []string) ([]batchObject, error) {
	if len(revspecs) == 0 {
		return nil, nil
	}
	var query bytes.Buffer
	for _, revspec := range revspecs {
		query.WriteString(revspec)
		query.WriteString("\n")
	}
	command := gitCommandContext(ctx, root, "cat-file", "--batch")
	command.Stdin = &query
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	objects, readErr := readCatFileBatch(bufio.NewReaderSize(output, 64<<10), len(revspecs))
	if readErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, readErr
	}
	if err := command.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("read Git objects: %w", err)
	}
	return objects, nil
}

func readCatFileBatch(reader *bufio.Reader, expected int) ([]batchObject, error) {
	objects := make([]batchObject, 0, expected)
	for len(objects) < expected {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read Git object header: %w", err)
		}
		fields := strings.Fields(strings.TrimSuffix(header, "\n"))
		// "<request> missing" for anything the repository does not contain.
		if len(fields) == 2 && fields[1] == "missing" {
			objects = append(objects, batchObject{})
			continue
		}
		if len(fields) != 3 || fields[1] != "blob" {
			return nil, errors.New("unexpected Git object header")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > maxBatchObjectSize {
			return nil, errors.New("Git object size is invalid or exceeds the read limit")
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			return nil, fmt.Errorf("read Git object: %w", err)
		}
		// cat-file --batch terminates each object with a newline.
		if _, err := reader.Discard(1); err != nil {
			return nil, fmt.Errorf("read Git object terminator: %w", err)
		}
		objects = append(objects, batchObject{id: fields[0], content: content})
	}
	return objects, nil
}

// worktreeBlobIDs hashes each worktree file as Git would when committing it,
// in one batch. Reading the files rather than the index is what keeps
// assume-unchanged and skip-worktree from hiding a modification. Unlike most
// commands, hash-object resolves --stdin-paths entries against the repository
// root rather than the working directory, so these must be tree paths.
func worktreeBlobIDs(ctx context.Context, root string, treePaths []string) ([]string, error) {
	var query bytes.Buffer
	for _, treePath := range treePaths {
		query.WriteString(treePath)
		query.WriteString("\n")
	}
	command := gitCommandContext(ctx, root, "hash-object", "--stdin-paths")
	command.Stdin = &query
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("hash authoritative worktree state: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(output), "\n"), "\n")
	if len(lines) != len(treePaths) {
		return nil, errors.New("cannot hash authoritative worktree state")
	}
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return lines, nil
}

type gitStatusEntry struct {
	code  string
	paths []string
}

// parseGitStatus reads NUL-delimited porcelain v1 records. The NUL format is
// what makes paths trustworthy: it never quotes or escapes, so core.quotePath
// cannot change the bytes, and a rename carries its original path as a separate
// NUL-terminated field instead of an ambiguous "old -> new" string.
func parseGitStatus(status string) ([]gitStatusEntry, error) {
	records := strings.Split(status, "\x00")
	var entries []gitStatusEntry
	for index := 0; index < len(records); index++ {
		record := records[index]
		if record == "" {
			continue
		}
		if len(record) < 4 {
			return nil, errors.New("cannot parse Git status")
		}
		entry := gitStatusEntry{code: record[:2], paths: []string{filepath.ToSlash(record[3:])}}
		if entry.code[0] == 'R' || entry.code[0] == 'C' || entry.code[1] == 'R' || entry.code[1] == 'C' {
			index++
			if index >= len(records) {
				return nil, errors.New("cannot parse Git status")
			}
			entry.paths = append(entry.paths, filepath.ToSlash(records[index]))
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func validateGitStatus(status string, allowedChanges, authoritative map[string]bool) error {
	entries, err := parseGitStatus(status)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		for _, name := range entry.paths {
			if allowedChanges[name] {
				continue
			}
			if entry.code == "??" && !authoritative[name] && !isAuthoritativePath(name) {
				continue
			}
			return fmt.Errorf("workspace has uncommitted authoritative or tracked changes at %q", name)
		}
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
	return symbolicHeadContext(context.Background(), root)
}

func symbolicHeadContext(ctx context.Context, root string) (string, error) {
	name, err := gitOutputContext(ctx, root, "symbolic-ref", "--quiet", "HEAD")
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
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

// gitPrefix returns the workspace's path prefix inside its Git repository.
// The prefix cannot change while a workspace operation holds its lock, and it
// is consulted once per authoritative path, so it is resolved once per root
// rather than through a subprocess per lookup.
var gitPrefixes struct {
	sync.Mutex
	byRoot map[string]string
}

func gitPrefix(ctx context.Context, root string) (string, error) {
	gitPrefixes.Lock()
	cached, found := gitPrefixes.byRoot[root]
	gitPrefixes.Unlock()
	if found {
		return cached, nil
	}
	prefix, err := gitOutputContext(ctx, root, "rev-parse", "--show-prefix")
	if err != nil {
		return "", err
	}
	prefix = filepath.ToSlash(prefix)
	gitPrefixes.Lock()
	if gitPrefixes.byRoot == nil {
		gitPrefixes.byRoot = make(map[string]string)
	}
	gitPrefixes.byRoot[root] = prefix
	gitPrefixes.Unlock()
	return prefix, nil
}

func workspaceGitPath(root, relative string) (string, error) {
	prefix, err := gitPrefix(context.Background(), root)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(filepath.FromSlash(prefix), filepath.FromSlash(relative))), nil
}

func workspaceRelativeGitPath(root, name string) (string, bool, error) {
	prefix, err := gitPrefix(context.Background(), root)
	if err != nil {
		return "", false, err
	}
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
	return gitChangedPathsContext(context.Background(), root, revision)
}

func gitChangedPathsContext(ctx context.Context, root, revision string) ([]string, error) {
	return gitPathOutputContext(ctx, root, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", revision)
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
	return gitPathOutputContext(context.Background(), root, arguments...)
}

func gitPathOutputContext(ctx context.Context, root string, arguments ...string) ([]string, error) {
	output, err := gitCommandContext(ctx, root, arguments...).Output()
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

// gitLockOwnerPrefix marks a lock file this process created, so a lock left
// behind by a crash can be told apart from one Git is genuinely holding.
const gitLockOwnerPrefix = "snailmail publication lock"

func acquireGitLock(name string) (func(), error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	// Git only reads a lock file it created itself, so recording who holds this
	// one is free and turns an opaque "File exists" into something actionable.
	owner := fmt.Sprintf("%s\npid=%d\nsince=%s\n", gitLockOwnerPrefix, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	if _, err := file.WriteString(owner); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	return func() { _ = os.Remove(name) }, nil
}

// describeGitLockConflict explains which lock blocked publication and, when it
// was left behind by an interrupted snailmail run, says so and names every file
// that has to be removed to recover.
func describeGitLockConflict(blocked string, names []string, cause error) error {
	if !errors.Is(cause, os.ErrExist) {
		return fmt.Errorf("%s: %w", blocked, cause)
	}
	content, readErr := os.ReadFile(blocked)
	if readErr != nil || !strings.HasPrefix(string(content), gitLockOwnerPrefix) {
		return fmt.Errorf("%s is held by another Git process", blocked)
	}
	details := strings.ReplaceAll(strings.TrimSpace(string(content)), "\n", " ")
	if owner, found := gitLockOwnerProcess(content); found && processExists(owner) {
		return fmt.Errorf("%s is held by a running snailmail process (%s)", blocked, details)
	}
	return fmt.Errorf("%s was left behind by a snailmail run that did not finish (%s); "+
		"if no snailmail process is publishing this repository, remove %s to recover",
		blocked, details, strings.Join(names, ", "))
}

func gitLockOwnerProcess(content []byte) (int, bool) {
	for _, line := range strings.Split(string(content), "\n") {
		if value, found := strings.CutPrefix(line, "pid="); found {
			pid, err := strconv.Atoi(strings.TrimSpace(value))
			return pid, err == nil && pid > 0
		}
	}
	return 0, false
}

// processExists reports whether a process id is live. A recycled id can make
// this a false positive, which is why the caller only uses it to soften the
// wording rather than to remove anything.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
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
	return gitHashObjectContext(context.Background(), root, content)
}

func gitHashObjectContext(ctx context.Context, root string, content []byte) (string, error) {
	command := gitCommandContext(ctx, root, "hash-object", "--stdin")
	command.Stdin = bytes.NewReader(content)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitCommand(root string, arguments ...string) *exec.Cmd {
	return gitCommandContext(context.Background(), root, arguments...)
}

// gitConfigOverrides neutralise user configuration that would otherwise change
// output this package parses. They are applied as -c overrides rather than by
// disabling global and system configuration wholesale, so that settings the
// repository genuinely needs — safe.directory in particular, which Git accepts
// only from those files — keep working.
var gitConfigOverrides = []string{
	// Prepends signature verification output to `log --format=%B`.
	"-c", "log.showSignature=false",
	// Can answer from a stale daemon view of the worktree.
	"-c", "core.fsmonitor=",
	// Quoting would change the path bytes read back from status output.
	"-c", "core.quotePath=false",
}

func gitCommandContext(ctx context.Context, root string, arguments ...string) *exec.Cmd {
	full := append([]string{"-C", root}, gitConfigOverrides...)
	command := exec.CommandContext(ctx, "git", append(full, arguments...)...)
	command.Env = replaceEnvironment(os.Environ(), "GIT_OPTIONAL_LOCKS", "0", "GIT_TERMINAL_PROMPT", "0")
	return command
}

func gitOutput(root string, arguments ...string) (string, error) {
	output, err := gitCommand(root, arguments...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitOutputContext(ctx context.Context, root string, arguments ...string) (string, error) {
	output, err := gitCommandContext(ctx, root, arguments...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitStatusOutput(root string) (string, error) {
	return gitStatusOutputContext(context.Background(), root)
}

func gitStatusOutputContext(ctx context.Context, root string) (string, error) {
	output, err := gitCommandContext(ctx, root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames").Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
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
	// Map iteration order is random; sort so the child environment is a
	// deterministic function of its inputs.
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+replacements[key])
	}
	return result
}
