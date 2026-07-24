package app

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/domain"
)

// PyPISnapshot holds immutable copies used for both metadata inspection and
// materialization. Sources are addressed only by their content digest.
type PyPISnapshot struct {
	Blobs   []domain.Blob
	Sources map[string]string
	root    string
}

func (snapshot *PyPISnapshot) Close() error {
	if snapshot.root == "" {
		return nil
	}
	err := os.RemoveAll(snapshot.root)
	snapshot.root = ""
	return err
}

// ScanPyPI snapshots supported distributions and derives facts from those exact
// immutable bytes.
func ScanPyPI(ctx context.Context, root string) (*PyPISnapshot, error) {
	snapshotRoot, err := os.MkdirTemp("", ".snailmail-input-*")
	if err != nil {
		return nil, fmt.Errorf("create input snapshot: %w", err)
	}
	snapshot := &PyPISnapshot{Sources: make(map[string]string), root: snapshotRoot}
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !pypi.IsDistributionFilename(entry.Name()) {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("distribution %q is a symbolic link", name)
		}
		blob, source, err := snapshotPyPIFile(name, entry.Name(), snapshotRoot)
		if err != nil {
			return err
		}
		if existing := snapshot.Sources[blob.SHA256]; existing != "" {
			if err := os.Remove(source); err != nil {
				return fmt.Errorf("remove duplicate snapshot: %w", err)
			}
		} else {
			snapshot.Sources[blob.SHA256] = source
		}
		snapshot.Blobs = append(snapshot.Blobs, blob)
		return nil
	})
	if err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("scan PyPI distributions: %w", err)
	}
	if len(snapshot.Blobs) == 0 {
		_ = snapshot.Close()
		return nil, fmt.Errorf("no supported PyPI distributions found in %q", root)
	}
	return snapshot, nil
}

func snapshotPyPIFile(name, filename, snapshotRoot string) (domain.Blob, string, error) {
	source, err := os.Open(name)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("open %q: %w", name, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("stat %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return domain.Blob{}, "", fmt.Errorf("distribution %q is not a regular file", name)
	}
	if info.Size() > pypi.MaxArtifactSize {
		return domain.Blob{}, "", fmt.Errorf("distribution %q exceeds the %d byte limit", name, pypi.MaxArtifactSize)
	}

	snapshot, err := os.CreateTemp(snapshotRoot, "blob-*")
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("create snapshot for %q: %w", name, err)
	}
	snapshotName := snapshot.Name()
	keep := false
	defer func() {
		_ = snapshot.Close()
		if !keep {
			_ = os.Remove(snapshotName)
		}
	}()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(snapshot, md5Hash, sha1Hash, sha256Hash), io.LimitReader(source, pypi.MaxArtifactSize+1))
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("snapshot %q: %w", name, err)
	}
	if size != info.Size() {
		return domain.Blob{}, "", fmt.Errorf("distribution %q changed while snapshotting", name)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return domain.Blob{}, "", fmt.Errorf("rewind snapshot for %q: %w", name, err)
	}
	facts, err := pypi.Inspect(filename, snapshot, size)
	if err != nil {
		return domain.Blob{}, "", err
	}
	if err := snapshot.Close(); err != nil {
		return domain.Blob{}, "", fmt.Errorf("close snapshot for %q: %w", name, err)
	}
	keep = true
	return domain.Blob{
		Filename: filename,
		Size:     size,
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:     hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
		Facts:    facts,
	}, snapshotName, nil
}
