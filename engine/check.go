package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

type CheckFinding struct {
	State   string `json:"state"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type CheckWorkspaceRequest struct {
	Root         string
	Blobs        blob.Resolver
	Origins      bool
	Sources      source.Fetcher
	MaxOrigins   int
	OriginOffset int
}

type CheckWorkspaceResult struct {
	Repositories    int            `json:"repositories"`
	PackageVersions int            `json:"package_versions"`
	Artifacts       int            `json:"artifacts"`
	OriginsChecked  int            `json:"origins_checked"`
	OriginsSkipped  int            `json:"origins_skipped"`
	Findings        []CheckFinding `json:"findings"`
}

type authorityFetchError struct{ err error }

func (err authorityFetchError) Error() string { return err.err.Error() }
func (err authorityFetchError) Unwrap() error { return err.err }

func CheckWorkspace(ctx context.Context, request CheckWorkspaceRequest) (CheckWorkspaceResult, error) {
	if request.Origins {
		if request.MaxOrigins == 0 {
			request.MaxOrigins = 2
		}
		if request.MaxOrigins < 1 || request.MaxOrigins > 4 {
			return CheckWorkspaceResult{}, errors.New("origin check limit must be between 1 and 4")
		}
		if request.OriginOffset < 0 {
			return CheckWorkspaceResult{}, errors.New("origin check offset must not be negative")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
	}
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
	store, storeErr := resolveBlobStore(ctx, manifest, request.Blobs)
	originAudit := originAuditState{enabled: request.Origins, fetcher: request.Sources, maximum: request.MaxOrigins, offset: request.OriginOffset}
	result := CheckWorkspaceResult{Repositories: len(manifest.Repositories)}
	if storeErr != nil {
		result.Findings = append(result.Findings, CheckFinding{State: "unknown", Subject: "blob-authority", Message: storeErr.Error()})
	}
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
				var validated domain.Blob
				var checkErr error
				if storeErr != nil {
					checkErr = authorityFetchError{err: storeErr}
				} else {
					validated, checkErr = checkLockedBlob(ctx, root, repository.Format, locked, store)
				}
				if checkErr != nil {
					if ctx.Err() != nil {
						return result, ctx.Err()
					}
					findingState := "unknown"
					if errors.Is(checkErr, blob.ErrNotFound) || errors.Is(checkErr, os.ErrNotExist) {
						findingState = "missing"
					} else if errors.Is(checkErr, blob.ErrCorrupt) {
						findingState = "changed"
					}
					result.Findings = append(result.Findings, CheckFinding{State: findingState, Subject: subject, Message: checkErr.Error()})
					if err := auditLockedOrigin(ctx, &originAudit, locked, subject, &result); err != nil {
						return result, err
					}
					continue
				}
				if nativePackageName(repository.Format, validated.Facts.Name) != packageVersion.Package || validated.Facts.Version != packageVersion.Version {
					result.Findings = append(result.Findings, CheckFinding{
						State: "changed", Subject: subject,
						Message: fmt.Sprintf("artifact facts identify %s@%s", nativePackageName(repository.Format, validated.Facts.Name), validated.Facts.Version),
					})
				}
				if err := auditLockedOrigin(ctx, &originAudit, locked, subject, &result); err != nil {
					return result, err
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

type originAuditState struct {
	enabled bool
	fetcher source.Fetcher
	maximum int
	offset  int
	seen    int
	used    int
}

func auditLockedOrigin(ctx context.Context, audit *originAuditState, locked state.LockedBlob, subject string, result *CheckWorkspaceResult) error {
	if !audit.enabled || locked.Origin == nil {
		return nil
	}
	position := audit.seen
	audit.seen++
	if position < audit.offset {
		result.OriginsSkipped++
		return nil
	}
	if audit.used >= audit.maximum {
		result.OriginsSkipped++
		return nil
	}
	audit.used++
	result.OriginsChecked++
	originErr := checkLockedOrigin(ctx, locked, audit.fetcher)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if originErr == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	findingState := "unknown"
	if errors.Is(originErr, blob.ErrNotFound) {
		findingState = "missing"
	} else if errors.Is(originErr, blob.ErrCorrupt) {
		findingState = "changed"
	}
	result.Findings = append(result.Findings, CheckFinding{State: findingState, Subject: subject + "/origin", Message: originErr.Error()})
	return nil
}

func checkLockedOrigin(ctx context.Context, locked state.LockedBlob, fetcher source.Fetcher) error {
	if fetcher == nil {
		return errors.New("origin fetcher is required")
	}
	response, err := fetcher.Fetch(ctx, locked.Origin.URL, maximumAdoptBytes)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if response.StatusCode == 404 {
		return blob.ErrNotFound
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("origin returned HTTP %d", response.StatusCode)
	}
	digest := sha256.Sum256(response.Body)
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(response.Body)) != locked.Size || hex.EncodeToString(digest[:]) != locked.SHA256 {
		return blob.ErrCorrupt
	}
	return nil
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
