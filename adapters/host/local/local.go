package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/state"
)

type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (adapter *Adapter) Capabilities(context.Context, host.Repository) (host.Capabilities, error) {
	return host.Capabilities{FaithfulPreview: true, ConditionalCommit: true}, nil
}

func (adapter *Adapter) Observe(_ context.Context, repository host.Repository) (host.PublishedRevision, error) {
	output, err := localPath(repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if _, err := os.Lstat(output); errors.Is(err, os.ErrNotExist) {
		return host.PublishedRevision{}, nil
	} else if err != nil {
		return host.PublishedRevision{}, err
	}
	manifest, err := app.VerifyRepository(output)
	if err != nil {
		return host.PublishedRevision{}, fmt.Errorf("observe local repository: %w", err)
	}
	return host.PublishedRevision{NativeRevision: manifest.TreeSHA256, TreeSHA256: manifest.TreeSHA256}, nil
}

func (adapter *Adapter) Stage(_ context.Context, _ host.Repository, request host.StageRequest) (host.StagedPublication, error) {
	manifest, err := app.VerifyRepository(request.Directory)
	if err != nil {
		return host.StagedPublication{}, fmt.Errorf("stage local repository: %w", err)
	}
	if manifest.TreeSHA256 != request.TreeSHA256 {
		return host.StagedPublication{}, errors.New("staged local repository tree changed")
	}
	return host.StagedPublication{
		ID: request.Directory, PlanID: request.PlanID, ChangeID: request.ChangeID, TreeSHA256: request.TreeSHA256,
		Files: request.Files, CommitPaths: request.CommitPaths,
	}, nil
}

func (adapter *Adapter) Commit(ctx context.Context, repository host.Repository, staged host.StagedPublication, expected host.ExpectedRevision) (host.CommitResult, error) {
	output, err := localPath(repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	if err := app.PublishVerifiedDirectory(ctx, staged.ID, output, expected.TreeSHA256, staged.TreeSHA256); err != nil {
		return host.CommitResult{}, &host.Error{Kind: host.ErrorStale, Operation: "commit local repository", Err: err}
	}
	revision := host.PublishedRevision{NativeRevision: staged.TreeSHA256, TreeSHA256: staged.TreeSHA256, PlanID: staged.PlanID, ChangeID: staged.ChangeID}
	return host.CommitResult{Revision: revision, CanonicalEndpoint: output}, nil
}

func (adapter *Adapter) Restore(context.Context, host.Repository, host.RestoreRef, host.ExpectedRevision) (host.PublishedRevision, error) {
	return host.PublishedRevision{}, &host.Error{
		Kind: host.ErrorInvalidConfiguration, Operation: "restore local repository",
		Err: errors.New("local restore is not exposed by this adapter"),
	}
}

func (adapter *Adapter) Abort(context.Context, host.Repository, host.StagedPublication) error {
	return nil
}

func localPath(repository host.Repository) (string, error) {
	if repository.Path == "" {
		return "", errors.New("local host path is required")
	}
	if filepath.IsAbs(repository.Path) {
		return filepath.Clean(repository.Path), nil
	}
	if repository.WorkspaceRoot == "" {
		return "", errors.New("local host workspace root is required")
	}
	return state.WorkspacePath(repository.WorkspaceRoot, filepath.ToSlash(repository.Path))
}
