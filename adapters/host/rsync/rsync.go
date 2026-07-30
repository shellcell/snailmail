package rsynchost

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

// Publishing to a directory on a machine reached over ssh — the shape most people
// already have, where a web server serves a filesystem path and deployment means
// getting files onto it.
//
// The two primitives are POSIX rather than anything the transport provides.
// rename(2) makes a publication atomic: the published path is a symlink into
// .snailmail/releases/<tree>/, and a revision becomes live when a new symlink is
// renamed over the old one, so a client follows one whole revision or the other and
// never a half-copied tree. mkdir(2) makes it conditional: there is no
// compare-and-swap on a symlink, so the expected revision is checked and the swap
// performed while holding a lock directory whose creation fails if it exists.
//
// The requirement that follows, and which cannot be checked from this side: the
// published path and the release directory must be on one filesystem, because
// rename is not atomic across mount points.
type Adapter struct {
	runner Runner
}

func New(runner Runner) *Adapter { return &Adapter{runner: runner} }

const (
	releasesDirectory = ".snailmail/releases"
	lockDirectory     = ".snailmail/lock"
	stagingDirectory  = ".snailmail/staging"
)

func (adapter *Adapter) Capabilities(_ context.Context, repository host.Repository) (host.Capabilities, error) {
	if _, err := remoteRoot(repository); err != nil {
		return host.Capabilities{}, err
	}
	return host.Capabilities{
		// The lock makes the swap conditional, so a stale publication is refused
		// rather than overwriting a revision it did not expect.
		ConditionalCommit: true,
		// Not offered: see Restore.
		ConditionalRestore: false,
		// A directory served by a web server is as public as that server makes it;
		// this adapter has no way to issue scoped read credentials.
		PrivateRead: false,
	}, nil
}

func (adapter *Adapter) Observe(ctx context.Context, repository host.Repository) (host.PublishedRevision, error) {
	root, err := remoteRoot(repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	target, err := adapter.runner.Run(ctx, []string{"readlink", root})
	if err != nil {
		if _, exited := exitCode(err); exited {
			// No symlink: either nothing has been published, or the path is a real
			// directory this adapter did not create. Both are "no managed revision",
			// and Commit refuses to replace a real directory rather than deleting
			// somebody's files.
			return host.PublishedRevision{}, nil
		}
		return host.PublishedRevision{}, infrastructure("observe rsync repository", err)
	}
	tree := treeFromTarget(strings.TrimSpace(string(target)))
	if tree == "" {
		return host.PublishedRevision{}, nil
	}
	return host.PublishedRevision{NativeRevision: tree, TreeSHA256: tree}, nil
}

func (adapter *Adapter) ReadAccess(_ context.Context, repository host.Repository, _ host.PublishedRevision) (host.ClientAccess, error) {
	return host.ClientAccess{Endpoint: repository.CanonicalEndpoint}, nil
}

func (adapter *Adapter) Stage(_ context.Context, repository host.Repository, request host.StageRequest) (host.StagedPublication, error) {
	if _, err := remoteRoot(repository); err != nil {
		return host.StagedPublication{}, err
	}
	// Verified locally before anything is sent, so a tree that does not match what
	// the plan describes never reaches the far side at all.
	manifest, err := app.VerifyRepository(request.Directory)
	if err != nil {
		return host.StagedPublication{}, fmt.Errorf("stage rsync repository: %w", err)
	}
	if manifest.TreeSHA256 != request.TreeSHA256 {
		return host.StagedPublication{}, errors.New("staged rsync repository tree changed")
	}
	return host.StagedPublication{
		ID: request.Directory, PlanID: request.PlanID, ChangeID: request.ChangeID,
		TreeSHA256: request.TreeSHA256, Files: request.Files, CommitPaths: request.CommitPaths,
	}, nil
}

// Commit copies the tree, then switches the symlink under a lock.
func (adapter *Adapter) Commit(ctx context.Context, repository host.Repository, staged host.StagedPublication,
	expected host.ExpectedRevision) (host.CommitResult, error) {
	root, err := remoteRoot(repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	if !hexdigest.ValidSHA256(staged.TreeSHA256) {
		return host.CommitResult{}, invalid("commit rsync repository", errors.New("staged tree digest is not a SHA-256"))
	}
	base := path.Dir(root)
	release := path.Join(base, releasesDirectory, staged.TreeSHA256)
	staging := path.Join(base, stagingDirectory, staged.TreeSHA256)

	// The tree goes to a staging path and is renamed into its release directory,
	// so the release either does not exist or is complete. A reader following the
	// symlink can never reach a directory that is still being written.
	if _, err := adapter.runner.Run(ctx, []string{"mkdir", "-p", staging}); err != nil {
		return host.CommitResult{}, infrastructure("prepare rsync staging directory", err)
	}
	if err := adapter.runner.Send(ctx, staged.ID, staging); err != nil {
		return host.CommitResult{}, infrastructure("copy rsync repository", err)
	}
	if _, err := adapter.runner.Run(ctx, []string{"mkdir", "-p", path.Join(base, releasesDirectory)}); err != nil {
		return host.CommitResult{}, infrastructure("prepare rsync release directory", err)
	}
	// A release is named by its tree digest and its contents are fixed by it, so a
	// release that already exists is the same bytes and re-sending is not an error.
	if _, err := adapter.runner.Run(ctx, []string{"rm", "-rf", release}); err != nil {
		return host.CommitResult{}, infrastructure("replace rsync release", err)
	}
	if _, err := adapter.runner.Run(ctx, []string{"mv", staging, release}); err != nil {
		return host.CommitResult{}, infrastructure("publish rsync release", err)
	}

	unlock, err := adapter.lock(ctx, base)
	if err != nil {
		return host.CommitResult{}, err
	}
	defer unlock()

	// Read under the lock, not before it: the whole point of the lock is that
	// nothing changes between the check and the swap.
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	if observed.TreeSHA256 == staged.TreeSHA256 {
		// Already live. A retried apply is not a second publication.
		return adapter.result(repository, staged), nil
	}
	if observed.TreeSHA256 != expected.TreeSHA256 {
		return host.CommitResult{}, &host.Error{
			Kind: host.ErrorStale, Operation: "commit rsync repository",
			Err: fmt.Errorf("expected revision %q but found %q", expected.TreeSHA256, observed.TreeSHA256),
		}
	}
	if observed.TreeSHA256 == "" {
		// Nothing managed is there. It may be an unrelated directory, which must not
		// be replaced by a symlink — that would unpublish somebody else's files.
		if err := adapter.requireAbsentOrSymlink(ctx, root); err != nil {
			return host.CommitResult{}, err
		}
	}
	if err := adapter.swapRoot(ctx, root, release); err != nil {
		return host.CommitResult{}, err
	}
	return adapter.result(repository, staged), nil
}

// swapRoot points the published path at a release by renaming a symlink over it.
func (adapter *Adapter) swapRoot(ctx context.Context, root, release string) error {
	pending := root + ".snailmail-pending"
	if _, err := adapter.runner.Run(ctx, []string{"ln", "-sfn", release, pending}); err != nil {
		return infrastructure("prepare rsync root symlink", err)
	}
	// The rename must replace the symlink itself rather than move the new one into
	// the directory the old one points at — the difference between publishing and
	// creating a nested copy nobody serves. Two spellings say that, and which one
	// exists depends on whose userland the target runs: GNU coreutils has -T, BSD
	// and macOS have -h. Both are a plain rename(2), so both are atomic; there is
	// no portable single spelling, and guessing from `uname` would be one more
	// thing to be wrong about. So it tries one and falls back to the other.
	var lastErr error
	for _, flag := range []string{"-T", "-h"} {
		_, err := adapter.runner.Run(ctx, []string{"mv", flag, pending, root})
		if err == nil {
			return nil
		}
		if _, exited := exitCode(err); !exited {
			// A transport failure rather than an unrecognised option; retrying with
			// different flags would only repeat it.
			return &host.Error{
				Kind: host.ErrorIndeterminate, Operation: "switch rsync root symlink",
				EffectMayHaveOccurred: true, Err: err,
			}
		}
		lastErr = err
	}
	return &host.Error{
		Kind: host.ErrorIndeterminate, Operation: "switch rsync root symlink",
		EffectMayHaveOccurred: true, Err: lastErr,
	}
}

// requireAbsentOrSymlink refuses to replace a real directory or file.
func (adapter *Adapter) requireAbsentOrSymlink(ctx context.Context, root string) error {
	_, err := adapter.runner.Run(ctx, []string{"test", "-e", root})
	if err != nil {
		if _, exited := exitCode(err); exited {
			return nil // Absent, which is the first publication.
		}
		return infrastructure("inspect rsync publication path", err)
	}
	// It exists and Observe found no managed revision, so it is not our symlink.
	return invalid("commit rsync repository", fmt.Errorf(
		"%s exists and was not published by snailmail; move it aside rather than having a publication delete it", root))
}

// lock takes the publication lock by creating a directory, which fails if it
// exists. There is no compare-and-swap on a symlink, and this is the primitive that
// stands in for one.
func (adapter *Adapter) lock(ctx context.Context, base string) (func(), error) {
	name := path.Join(base, lockDirectory)
	if _, err := adapter.runner.Run(ctx, []string{"mkdir", "-p", path.Dir(name)}); err != nil {
		return nil, infrastructure("prepare rsync lock directory", err)
	}
	if _, err := adapter.runner.Run(ctx, []string{"mkdir", name}); err != nil {
		if _, exited := exitCode(err); exited {
			// Another publication holds it. One run fails rather than one run waits,
			// which is the same answer every other host here gives.
			return nil, &host.Error{
				Kind: host.ErrorStale, Operation: "commit rsync repository",
				Err: fmt.Errorf("another publication holds %s; if none is running, remove it", name),
			}
		}
		return nil, infrastructure("take rsync publication lock", err)
	}
	return func() {
		// Best effort: the publication has already happened, and failing it because
		// the lock could not be released would misreport a success. A lock left
		// behind is visible and its removal is named in the error above.
		_, _ = adapter.runner.Run(context.WithoutCancel(ctx), []string{"rmdir", name})
	}, nil
}

func (adapter *Adapter) result(repository host.Repository, staged host.StagedPublication) host.CommitResult {
	return host.CommitResult{
		Revision: host.PublishedRevision{
			NativeRevision: staged.TreeSHA256, TreeSHA256: staged.TreeSHA256,
			PlanID: staged.PlanID, ChangeID: staged.ChangeID,
		},
		CanonicalEndpoint: repository.CanonicalEndpoint,
	}
}

// Restore is not offered. Pointing the symlink at an earlier release is mechanically
// easy; establishing that the earlier release is still intact is not, because
// nothing on the far side verifies it and this adapter would be asserting a
// rollback it cannot check. The local adapter declines for the same reason.
func (adapter *Adapter) Restore(context.Context, host.Repository, host.RestoreRef, host.ExpectedRevision) (host.PublishedRevision, error) {
	return host.PublishedRevision{}, &host.Error{
		Kind: host.ErrorInvalidConfiguration, Operation: "restore rsync repository",
		Err: errors.New("rsync restore is not offered, because the adapter cannot verify the release it would roll back to"),
	}
}

// Abort removes a staging directory a failed publication left behind. A release
// that was already renamed into place is left: it is named by its digest, nothing
// points at it, and removing it is collection's job rather than an abort's.
func (adapter *Adapter) Abort(ctx context.Context, repository host.Repository, staged host.StagedPublication) error {
	root, err := remoteRoot(repository)
	if err != nil {
		return err
	}
	if !hexdigest.ValidSHA256(staged.TreeSHA256) {
		return nil
	}
	staging := path.Join(path.Dir(root), stagingDirectory, staged.TreeSHA256)
	if _, err := adapter.runner.Run(ctx, []string{"rm", "-rf", staging}); err != nil {
		return infrastructure("abort rsync publication", err)
	}
	return nil
}

// remoteRoot is the published path on the far side.
func remoteRoot(repository host.Repository) (string, error) {
	if repository.Path == "" {
		return "", invalid("configure rsync host", errors.New("rsync host path is required"))
	}
	if !strings.HasPrefix(repository.Path, "/") {
		// Relative to a remote home directory is ambiguous — whose home depends on
		// the ssh user, which ssh_config may change without this adapter knowing.
		return "", invalid("configure rsync host", errors.New("rsync host path must be absolute"))
	}
	cleaned := path.Clean(repository.Path)
	if cleaned == "/" {
		return "", invalid("configure rsync host", errors.New("rsync host path must not be the filesystem root"))
	}
	return cleaned, nil
}

// treeFromTarget reads the revision out of a symlink target, and reports empty for
// a target this adapter did not write.
func treeFromTarget(target string) string {
	if target == "" {
		return ""
	}
	directory, tree := path.Split(path.Clean(target))
	if !strings.HasSuffix(path.Clean(directory), releasesDirectory) {
		return ""
	}
	if !hexdigest.ValidSHA256(tree) {
		return ""
	}
	return tree
}

func infrastructure(operation string, err error) error {
	return &host.Error{Kind: host.ErrorInfrastructure, Operation: operation, Retryable: true, Err: err}
}

func invalid(operation string, err error) error {
	return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: operation, Err: err}
}
