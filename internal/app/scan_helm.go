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

	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/internal/domain"
)

type HelmSnapshot struct {
	Blobs   []domain.Blob
	Sources map[string]string
	root    string
}

func (snapshot *HelmSnapshot) Close() error {
	if snapshot.root == "" {
		return nil
	}
	err := os.RemoveAll(snapshot.root)
	snapshot.root = ""
	return err
}

func ScanHelm(ctx context.Context, root string) (*HelmSnapshot, error) {
	snapshotRoot, err := os.MkdirTemp("", ".snailmail-helm-input-*")
	if err != nil {
		return nil, fmt.Errorf("create Helm input snapshot: %w", err)
	}
	snapshot := &HelmSnapshot{Sources: make(map[string]string), root: snapshotRoot}
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !helm.IsChartFilename(entry.Name()) {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("Helm chart %q is a symbolic link", name)
		}
		blob, source, err := snapshotHelmFile(name, entry.Name(), snapshotRoot)
		if err != nil {
			return err
		}
		if existing := snapshot.Sources[blob.SHA256]; existing != "" {
			if err := os.Remove(source); err != nil {
				return fmt.Errorf("remove duplicate Helm snapshot: %w", err)
			}
		} else {
			snapshot.Sources[blob.SHA256] = source
		}
		snapshot.Blobs = append(snapshot.Blobs, blob)
		return nil
	})
	if err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("scan Helm charts: %w", err)
	}
	if len(snapshot.Blobs) == 0 {
		_ = snapshot.Close()
		return nil, fmt.Errorf("no Helm charts found in %q", root)
	}
	return snapshot, nil
}

func snapshotHelmFile(name, filename, snapshotRoot string) (domain.Blob, string, error) {
	source, err := os.Open(name)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("open %q: %w", name, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("stat %q: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Size() > helm.MaxArtifactSize {
		return domain.Blob{}, "", fmt.Errorf("Helm chart %q is not a bounded regular file", name)
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
	size, err := io.Copy(io.MultiWriter(snapshot, md5Hash, sha1Hash, sha256Hash), io.LimitReader(source, helm.MaxArtifactSize+1))
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("snapshot %q: %w", name, err)
	}
	if size != info.Size() {
		return domain.Blob{}, "", fmt.Errorf("Helm chart %q changed while snapshotting", name)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return domain.Blob{}, "", fmt.Errorf("rewind snapshot for %q: %w", name, err)
	}
	facts, err := helm.Inspect(filename, snapshot, size)
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
