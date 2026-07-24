package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shellcell/snailmail/internal/domain"
)

// Materialize writes a finalized artifact to an immutable release directory,
// then atomically switches the public output symlink to that release.
func Materialize(ctx context.Context, output string, artifact domain.RepositoryArtifact, sources map[string]string) error {
	absolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create output parent: %w", err)
	}
	unlock, err := lockOutput(absolute)
	if err != nil {
		return err
	}
	defer unlock()
	expectedLink, err := currentManagedRelease(absolute)
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(absolute)+".snailmail-release-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}

	for _, file := range artifact.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := materializeFile(staging, file, sources); err != nil {
			return err
		}
	}
	_, err = publishRelease(absolute, staging, expectedLink)
	if err != nil {
		return err
	}
	return nil
}

func lockOutput(output string) (func(), error) {
	lockName := filepath.Join(filepath.Dir(output), "."+filepath.Base(output)+".snailmail.lock")
	lock, err := os.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open output lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("another build is publishing %q", output)
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}

func materializeFile(root string, file domain.File, sources map[string]string) error {
	target := filepath.Join(root, filepath.FromSlash(file.Path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent for %q: %w", file.Path, err)
	}
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", file.Path, err)
	}
	closeWithError := func(writeErr error) error {
		if closeErr := destination.Close(); writeErr == nil && closeErr != nil {
			return closeErr
		}
		return writeErr
	}

	hash := sha256.New()
	var size int64
	if file.BlobSHA256 == "" {
		size, err = io.Copy(io.MultiWriter(destination, hash), bytes.NewReader(file.Content))
	} else {
		sourcePath := sources[file.BlobSHA256]
		if sourcePath == "" {
			err = fmt.Errorf("blob sha256:%s is unavailable", file.BlobSHA256)
		} else {
			var source *os.File
			source, err = os.Open(sourcePath)
			if err == nil {
				size, err = io.Copy(io.MultiWriter(destination, hash), source)
				if closeErr := source.Close(); err == nil && closeErr != nil {
					err = closeErr
				}
			}
		}
	}
	if err = closeWithError(err); err != nil {
		return fmt.Errorf("write %q: %w", file.Path, err)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if size != file.Size || actualHash != file.SHA256 {
		return fmt.Errorf("materialized %q does not match its planned digest", file.Path)
	}
	return nil
}

func currentManagedRelease(output string) (string, error) {
	control := controlDirectory(output)
	info, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		if _, controlErr := os.Lstat(control); controlErr == nil {
			return "", fmt.Errorf("refusing to publish %q because an unreferenced control directory exists", output)
		} else if !errors.Is(controlErr, os.ErrNotExist) {
			return "", fmt.Errorf("inspect output control directory: %w", controlErr)
		}
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect output: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("refusing to replace %q because it is not a snailmail release symlink", output)
	}
	outerLink, err := os.Readlink(output)
	if err != nil {
		return "", fmt.Errorf("read output release link: %w", err)
	}
	expectedOuterLink := filepath.Join(filepath.Base(control), "current")
	if outerLink != expectedOuterLink {
		return "", fmt.Errorf("refusing to replace %q because its release link is unmanaged", output)
	}
	controlInfo, err := os.Lstat(control)
	if err != nil {
		return "", fmt.Errorf("inspect output control directory: %w", err)
	}
	if !controlInfo.IsDir() || controlInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output control path %q is not a directory", control)
	}
	current := filepath.Join(control, "current")
	link, err := os.Readlink(current)
	if err != nil {
		return "", fmt.Errorf("read current release link: %w", err)
	}
	prefix := "." + filepath.Base(output) + ".snailmail-release-"
	releaseBase := filepath.Base(link)
	if filepath.IsAbs(link) || link != filepath.Join("..", releaseBase) || !strings.HasPrefix(releaseBase, prefix) {
		return "", fmt.Errorf("refusing to replace %q because its current release is unmanaged", output)
	}
	target := filepath.Join(control, link)
	if _, err := VerifyRepository(target); err != nil {
		return "", fmt.Errorf("refusing to replace invalid repository %q: %w", output, err)
	}
	return link, nil
}

func publishRelease(output, staging, expectedLink string) (bool, error) {
	parent := filepath.Dir(output)
	control := controlDirectory(output)
	newLink := filepath.Join("..", filepath.Base(staging))
	if expectedLink == "" {
		if err := os.Mkdir(control, 0o700); err != nil {
			return false, fmt.Errorf("create output control directory: %w", err)
		}
		if err := os.Symlink(newLink, filepath.Join(control, "current")); err != nil {
			return false, fmt.Errorf("create current release link: %w", err)
		}
		temporaryName, err := reserveSymlink(parent, "."+filepath.Base(output)+".snailmail-link-*", filepath.Join(filepath.Base(control), "current"))
		if err != nil {
			return false, err
		}
		committed, err := commitReleaseLink(temporaryName, output, "")
		if err != nil {
			return committed, fmt.Errorf("commit initial release link: %w", err)
		}
		return true, nil
	}

	observedLink, err := currentManagedRelease(output)
	if err != nil {
		return false, err
	}
	if observedLink != expectedLink {
		return false, fmt.Errorf("current release changed during publication")
	}
	temporaryName, err := reserveSymlink(control, ".current-*", newLink)
	if err != nil {
		return false, err
	}
	committed, err := commitReleaseLink(temporaryName, filepath.Join(control, "current"), expectedLink)
	if err != nil {
		return committed, fmt.Errorf("commit current release: %w", err)
	}
	outerLink, readErr := os.Readlink(output)
	if readErr != nil || outerLink != filepath.Join(filepath.Base(control), "current") {
		return true, fmt.Errorf("output changed concurrently after the managed release was committed")
	}
	return true, nil
}

func reserveSymlink(directory, pattern, target string) (string, error) {
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", fmt.Errorf("reserve release link: %w", err)
	}
	temporaryName := temporary.Name()
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close release link reservation: %w", err)
	}
	if err := os.Remove(temporaryName); err != nil {
		return "", fmt.Errorf("prepare release link: %w", err)
	}
	if err := os.Symlink(target, temporaryName); err != nil {
		return "", fmt.Errorf("create release link: %w", err)
	}
	return temporaryName, nil
}

func controlDirectory(output string) string {
	return filepath.Join(filepath.Dir(output), "."+filepath.Base(output)+".snailmail-control")
}
