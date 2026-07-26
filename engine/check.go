package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
)

type CheckFinding struct {
	State   string
	Subject string
	Message string
}

type CheckWorkspaceRequest struct {
	Root  string
	Blobs blob.Resolver
}

type CheckWorkspaceResult struct {
	Repositories    int
	PackageVersions int
	Artifacts       int
	Findings        []CheckFinding
}

type authorityFetchError struct{ err error }

func (err authorityFetchError) Error() string { return err.err.Error() }
func (err authorityFetchError) Unwrap() error { return err.err }

func CheckWorkspace(ctx context.Context, request CheckWorkspaceRequest) (CheckWorkspaceResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return CheckWorkspaceResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return CheckWorkspaceResult{}, err
	}
	defer unlock()
	if err := state.RequireGitRepositoryContext(ctx, root); err != nil {
		return CheckWorkspaceResult{}, err
	}
	if err := state.RequireCompleteGitHistoryContext(ctx, root); err != nil {
		return CheckWorkspaceResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return CheckWorkspaceResult{}, err
	}
	store, err := resolveBlobStore(ctx, manifest, request.Blobs)
	if err != nil {
		return CheckWorkspaceResult{}, err
	}
	result := CheckWorkspaceResult{Repositories: len(manifest.Repositories)}
	for _, repositoryName := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[repositoryName]
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return CheckWorkspaceResult{}, err
		}
		if err := state.ValidateLock(lock, repositoryName, repository.Format); err != nil {
			return CheckWorkspaceResult{}, err
		}
		ledger, err := state.LoadLedgerHistoryContext(ctx, root, repositoryName)
		if err != nil {
			return CheckWorkspaceResult{}, err
		}
		if err := state.ValidatePublicationHistory(repositoryName, ledger); err != nil {
			return CheckWorkspaceResult{}, err
		}
		if err := state.ValidatePublishedBindings(lock, ledger); err != nil {
			return CheckWorkspaceResult{}, err
		}
		result.PackageVersions += len(lock.PackageVersion)
		for _, packageVersion := range lock.PackageVersion {
			for _, locked := range packageVersion.Blobs {
				if err := ctx.Err(); err != nil {
					return result, err
				}
				result.Artifacts++
				subject := fmt.Sprintf("repo/%s/%s@%s/%s", repositoryName, packageVersion.Package, packageVersion.Version, locked.Filename)
				validated, checkErr := checkLockedBlob(ctx, root, repository.Format, locked, store)
				if checkErr != nil {
					if errors.Is(checkErr, context.Canceled) || errors.Is(checkErr, context.DeadlineExceeded) {
						return result, checkErr
					}
					findingState := "unknown"
					if errors.Is(checkErr, blob.ErrNotFound) || errors.Is(checkErr, os.ErrNotExist) {
						findingState = "missing"
					} else if errors.Is(checkErr, blob.ErrCorrupt) {
						findingState = "changed"
					}
					result.Findings = append(result.Findings, CheckFinding{State: findingState, Subject: subject, Message: checkErr.Error()})
					continue
				}
				if nativePackageName(repository.Format, validated.Facts.Name) != packageVersion.Package || validated.Facts.Version != packageVersion.Version {
					result.Findings = append(result.Findings, CheckFinding{
						State: "changed", Subject: subject,
						Message: fmt.Sprintf("artifact facts identify %s@%s", nativePackageName(repository.Format, validated.Facts.Name), validated.Facts.Version),
					})
				}
			}
		}
	}
	sort.Slice(result.Findings, func(left, right int) bool {
		if result.Findings[left].Subject != result.Findings[right].Subject {
			return result.Findings[left].Subject < result.Findings[right].Subject
		}
		if result.Findings[left].State != result.Findings[right].State {
			return result.Findings[left].State < result.Findings[right].State
		}
		return result.Findings[left].Message < result.Findings[right].Message
	})
	return result, nil
}

func checkLockedBlob(ctx context.Context, root, format string, locked state.LockedBlob, store blob.Store) (domain.Blob, error) {
	if err := state.ValidateLockedBlobReference(format, locked); err != nil {
		return domain.Blob{}, err
	}
	if store == nil {
		validated, _, err := state.LoadBlobContext(ctx, root, format, locked)
		return validated, err
	}
	temporary, err := os.CreateTemp("", ".snailmail-check-*")
	if err != nil {
		return domain.Blob{}, err
	}
	name := temporary.Name()
	if err := os.Remove(name); err != nil {
		_ = temporary.Close()
		return domain.Blob{}, fmt.Errorf("%w: unlink checked blob: %v", blob.ErrUnavailable, err)
	}
	fetchErr := store.Fetch(ctx, blobref(locked), temporary)
	if fetchErr != nil {
		_ = temporary.Close()
		return domain.Blob{}, authorityFetchError{err: fetchErr}
	}
	if err := ctx.Err(); err != nil {
		_ = temporary.Close()
		return domain.Blob{}, err
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return domain.Blob{}, fmt.Errorf("%w: stat checked blob: %v", blob.ErrUnavailable, err)
	}
	if _, err := temporary.Seek(0, 0); err != nil {
		_ = temporary.Close()
		return domain.Blob{}, fmt.Errorf("%w: seek checked blob: %v", blob.ErrUnavailable, err)
	}
	validated, err := state.ValidateLockedBlobOpenContext(ctx, temporary, info, name, format, locked)
	if err != nil {
		return domain.Blob{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.Blob{}, err
	}
	return validated, nil
}
