package app

import (
	"bytes"
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
	"syscall"

	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
)

// Materialize writes a finalized artifact to an immutable release directory,
// then atomically switches the public output symlink to that release.
func Materialize(ctx context.Context, output string, artifact domain.RepositoryArtifact, sources map[string]string) error {
	return materialize(ctx, output, artifact, sources, nil)
}

func materialize(ctx context.Context, output string, artifact domain.RepositoryArtifact, sources map[string]string, expectedTree *string) error {
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
	expectedLink, currentTree, err := currentManagedRelease(absolute)
	if err != nil {
		return err
	}
	if expectedTree != nil && currentTree != *expectedTree {
		return fmt.Errorf("stale target: expected tree %q, found %q", *expectedTree, currentTree)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(absolute)+".snailmail-release-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()

	for _, file := range artifact.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := materializeFile(staging, file, sources); err != nil {
			return err
		}
	}
	if err := syncTreeDirectories(staging); err != nil {
		return err
	}
	committed, err := publishRelease(absolute, staging, expectedLink, currentTree)
	published = committed
	if err != nil {
		return err
	}
	return nil
}

// PublishVerifiedDirectory atomically publishes the exact files from a
// structurally verified staged tree while enforcing the plan's target tree.
func PublishVerifiedDirectory(ctx context.Context, source, output, expectedCurrent, desiredTree string) error {
	manifest, err := VerifyRepository(source)
	if err != nil {
		return err
	}
	if manifest.TreeSHA256 != desiredTree {
		return fmt.Errorf("staged tree %s does not match planned tree %s", manifest.TreeSHA256, desiredTree)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	artifact := domain.RepositoryArtifact{Format: manifest.Format}
	sources := make(map[string]string, len(manifest.Files)+1)
	for _, file := range manifest.Files {
		artifact.Files = append(artifact.Files, domain.File{Path: file.Path, Size: file.Size, SHA256: file.SHA256, BlobSHA256: file.SHA256})
		sources[file.SHA256] = filepath.Join(source, filepath.FromSlash(file.Path))
	}
	managementContent, err := snapshotVerifiedManifest(source, manifest)
	if err != nil {
		return err
	}
	managementHash := sha256.Sum256(managementContent)
	managementDigest := hex.EncodeToString(managementHash[:])
	artifact.Files = append(artifact.Files, domain.File{
		Path: buildgraph.ManifestFilename, Size: int64(len(managementContent)), SHA256: managementDigest, Content: managementContent,
	})
	return materialize(ctx, output, artifact, sources, &expectedCurrent)
}

func snapshotVerifiedManifest(root string, expected buildgraph.RepositoryManifest) ([]byte, error) {
	file, err := os.Open(filepath.Join(root, buildgraph.ManifestFilename))
	if err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxManifestSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(content) > maxManifestSize {
		return nil, errors.New("repository manifest exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var actual buildgraph.RepositoryManifest
	if err := decoder.Decode(&actual); err != nil {
		return nil, fmt.Errorf("decode staged repository manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(actual, expected) {
		return nil, errors.New("staged repository manifest changed after verification")
	}
	return content, nil
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
		if syncErr := destination.Sync(); writeErr == nil && syncErr != nil {
			writeErr = syncErr
		}
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

func currentManagedRelease(output string) (string, string, error) {
	control := controlDirectory(output)
	info, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		if _, controlErr := os.Lstat(control); controlErr == nil {
			if err := removeOrphanedControl(output); err != nil {
				return "", "", err
			}
		} else if !errors.Is(controlErr, os.ErrNotExist) {
			return "", "", fmt.Errorf("inspect output control directory: %w", controlErr)
		}
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("inspect output: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", "", fmt.Errorf("refusing to replace %q because it is not a snailmail release symlink", output)
	}
	outerLink, err := os.Readlink(output)
	if err != nil {
		return "", "", fmt.Errorf("read output release link: %w", err)
	}
	expectedOuterLink := filepath.Join(filepath.Base(control), "current")
	if outerLink != expectedOuterLink {
		return "", "", fmt.Errorf("refusing to replace %q because its release link is unmanaged", output)
	}
	controlInfo, err := os.Lstat(control)
	if err != nil {
		return "", "", fmt.Errorf("inspect output control directory: %w", err)
	}
	if !controlInfo.IsDir() || controlInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("output control path %q is not a directory", control)
	}
	current := filepath.Join(control, "current")
	link, err := os.Readlink(current)
	if err != nil {
		return "", "", fmt.Errorf("read current release link: %w", err)
	}
	prefix := "." + filepath.Base(output) + ".snailmail-release-"
	releaseBase := filepath.Base(link)
	if filepath.IsAbs(link) || link != filepath.Join("..", releaseBase) || !strings.HasPrefix(releaseBase, prefix) {
		return "", "", fmt.Errorf("refusing to replace %q because its current release is unmanaged", output)
	}
	target := filepath.Join(control, link)
	manifest, err := VerifyRepository(target)
	if err != nil {
		return "", "", fmt.Errorf("refusing to replace invalid repository %q: %w", output, err)
	}
	return link, manifest.TreeSHA256, nil
}

func removeOrphanedControl(output string) error {
	control := controlDirectory(output)
	info, err := os.Lstat(control)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unreferenced output control path %q is not a directory", control)
	}
	current := filepath.Join(control, "current")
	link, err := os.Readlink(current)
	release := ""
	if err == nil {
		releaseBase := filepath.Base(link)
		prefix := "." + filepath.Base(output) + ".snailmail-release-"
		if filepath.IsAbs(link) || link != filepath.Join("..", releaseBase) || !strings.HasPrefix(releaseBase, prefix) {
			return fmt.Errorf("unreferenced output control directory %q has an unmanaged release", control)
		}
		release = filepath.Join(filepath.Dir(output), releaseBase)
		if _, statErr := os.Lstat(release); statErr == nil {
			if _, verifyErr := VerifyRepository(release); verifyErr != nil {
				return fmt.Errorf("refusing to remove unverified orphan release %q: %w", release, verifyErr)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if err := os.Remove(current); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(control); err != nil {
		return fmt.Errorf("remove unreferenced output control directory: %w", err)
	}
	if release != "" {
		if err := os.RemoveAll(release); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(output))
}

func publishRelease(output, staging, expectedLink, expectedTree string) (bool, error) {
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
		// os.Symlink is itself the atomic create-if-absent commit: it fails with
		// EEXIST rather than replacing an entry another writer published.
		if err := os.Symlink(filepath.Join(filepath.Base(control), "current"), output); err != nil {
			return false, fmt.Errorf("commit initial release link: %w", err)
		}
		if err := syncDirectory(control); err != nil {
			return true, err
		}
		if err := syncDirectory(parent); err != nil {
			return true, err
		}
		return true, nil
	}

	observedLink, observedTree, err := currentManagedRelease(output)
	if err != nil {
		return false, err
	}
	if observedLink != expectedLink || observedTree != expectedTree {
		return false, fmt.Errorf("current release changed during publication")
	}
	temporaryName, err := reserveSymlink(control, ".current-*", newLink)
	if err != nil {
		return false, err
	}
	committed, err := exchangeReleaseLink(temporaryName, filepath.Join(control, "current"), expectedLink)
	if err != nil {
		return committed, fmt.Errorf("commit current release: %w", err)
	}
	if err := os.Remove(temporaryName); err != nil {
		return true, fmt.Errorf("remove prior release link: %w", err)
	}
	outerLink, readErr := os.Readlink(output)
	if readErr != nil || outerLink != filepath.Join(filepath.Base(control), "current") {
		return true, fmt.Errorf("output changed concurrently after the managed release was committed")
	}
	if err := syncDirectory(control); err != nil {
		return true, err
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		return true, err
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

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func syncTreeDirectories(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, name)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool {
		return len(directories[left]) > len(directories[right])
	})
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}
