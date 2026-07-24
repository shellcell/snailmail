package state

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/domain"
)

func PutArtifact(root, format, sourceName string) (domain.Blob, error) {
	info, err := os.Lstat(sourceName)
	if err != nil {
		return domain.Blob{}, err
	}
	if !info.Mode().IsRegular() {
		return domain.Blob{}, fmt.Errorf("artifact %q is not a regular file", sourceName)
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return domain.Blob{}, err
	}
	if info.Size() > maximum {
		return domain.Blob{}, fmt.Errorf("artifact %q exceeds format size limit", sourceName)
	}
	casRoot := filepath.Join(root, ".snailmail", "cas", "sha256")
	if err := os.MkdirAll(casRoot, 0o755); err != nil {
		return domain.Blob{}, err
	}
	temporary, err := os.CreateTemp(casRoot, ".blob-*")
	if err != nil {
		return domain.Blob{}, err
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	source, err := os.Open(sourceName)
	if err != nil {
		return domain.Blob{}, err
	}
	md5Hash, sha1Hash, sha256Hash := md5.New(), sha1.New(), sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, md5Hash, sha1Hash, sha256Hash), io.LimitReader(source, maximum+1))
	closeSourceErr := source.Close()
	if copyErr != nil {
		return domain.Blob{}, copyErr
	}
	if closeSourceErr != nil {
		return domain.Blob{}, closeSourceErr
	}
	if size != info.Size() {
		return domain.Blob{}, fmt.Errorf("artifact %q changed while importing", sourceName)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return domain.Blob{}, err
	}
	filename := filepath.Base(sourceName)
	facts, err := inspect(format, filename, temporary, size)
	if err != nil {
		return domain.Blob{}, err
	}
	digest := hex.EncodeToString(sha256Hash.Sum(nil))
	targetDirectory := filepath.Join(casRoot, digest[:2])
	if err := os.MkdirAll(targetDirectory, 0o755); err != nil {
		return domain.Blob{}, err
	}
	target := filepath.Join(targetDirectory, digest)
	if err := temporary.Close(); err != nil {
		return domain.Blob{}, err
	}
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		if err := os.Chmod(temporaryName, 0o444); err != nil {
			return domain.Blob{}, err
		}
		if err := os.Rename(temporaryName, target); err != nil {
			return domain.Blob{}, err
		}
		keep = true
	} else if err != nil {
		return domain.Blob{}, err
	}
	return domain.Blob{
		Filename: filename,
		Size:     size,
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:     hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:   digest,
		Facts:    facts,
	}, nil
}

func LoadBlob(root, format string, locked LockedBlob) (domain.Blob, string, error) {
	name := CASPath(root, locked.SHA256)
	file, err := os.Open(name)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("open blob sha256:%s: %w", locked.SHA256, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return domain.Blob{}, "", err
	}
	md5Hash, sha1Hash, sha256Hash := md5.New(), sha1.New(), sha256.New()
	size, err := io.Copy(io.MultiWriter(md5Hash, sha1Hash, sha256Hash), file)
	if err != nil {
		return domain.Blob{}, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return domain.Blob{}, "", err
	}
	facts, err := inspect(format, locked.Filename, file, size)
	if err != nil {
		return domain.Blob{}, "", err
	}
	blob := domain.Blob{
		Filename: locked.Filename,
		Size:     size,
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:     hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
		Facts:    facts,
	}
	if size != info.Size() || blob.Size != locked.Size || blob.SHA256 != locked.SHA256 || (locked.MD5 != "" && blob.MD5 != locked.MD5) || (locked.SHA1 != "" && blob.SHA1 != locked.SHA1) || facts.Architecture != locked.Architecture {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s disagrees with its lock", locked.SHA256)
	}
	return blob, name, nil
}

func CASPath(root, digest string) string {
	if len(digest) < 2 {
		return ""
	}
	return filepath.Join(root, ".snailmail", "cas", "sha256", digest[:2], digest)
}

func ToLockedBlob(blob domain.Blob) LockedBlob {
	return LockedBlob{
		Filename:     blob.Filename,
		Architecture: blob.Facts.Architecture,
		Size:         blob.Size,
		MD5:          blob.MD5,
		SHA1:         blob.SHA1,
		SHA256:       blob.SHA256,
	}
}

func inspect(format, filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	switch format {
	case "pypi":
		return pypi.Inspect(filename, reader, size)
	case "deb":
		return deb.Inspect(filename, reader, size)
	case "helm":
		return helm.Inspect(filename, reader, size)
	default:
		return domain.PackageFacts{}, fmt.Errorf("unsupported format %q", format)
	}
}

func formatMaximum(format string) (int64, error) {
	switch format {
	case "pypi":
		return pypi.MaxArtifactSize, nil
	case "deb":
		return deb.MaxArtifactSize, nil
	case "helm":
		return helm.MaxArtifactSize, nil
	default:
		return 0, fmt.Errorf("unsupported format %q", format)
	}
}
