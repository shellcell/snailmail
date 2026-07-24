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
	casRoot, err := WorkspacePath(root, filepath.ToSlash(filepath.Join(".snailmail", "cas", "sha256")))
	if err != nil {
		return domain.Blob{}, err
	}
	if err := makeDirectoriesDurable(casRoot, 0o755); err != nil {
		return domain.Blob{}, err
	}
	temporary, err := os.CreateTemp(casRoot, ".blob-*")
	if err != nil {
		return domain.Blob{}, err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
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
	if err := makeDirectoriesDurable(targetDirectory, 0o755); err != nil {
		return domain.Blob{}, err
	}
	target := filepath.Join(targetDirectory, digest)
	if err := temporary.Sync(); err != nil {
		return domain.Blob{}, err
	}
	if err := temporary.Close(); err != nil {
		return domain.Blob{}, err
	}
	if err := os.Chmod(temporaryName, 0o444); err != nil {
		return domain.Blob{}, err
	}
	if err := os.Link(temporaryName, target); err == nil {
		directory, err := os.Open(targetDirectory)
		if err != nil {
			return domain.Blob{}, err
		}
		if err := directory.Sync(); err != nil {
			_ = directory.Close()
			return domain.Blob{}, err
		}
		if err := directory.Close(); err != nil {
			return domain.Blob{}, err
		}
	} else if errors.Is(err, os.ErrExist) {
		if err := verifyStoredBlob(target, digest, size); err != nil {
			return domain.Blob{}, err
		}
	} else {
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

func verifyStoredBlob(name, expectedDigest string, expectedSize int64) error {
	pathInfo, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("CAS object %q is not a regular file", name)
	}
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("CAS object %q is not a regular file", name)
	}
	if !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return fmt.Errorf("CAS object %q changed while opening", name)
	}
	hash := sha256.New()
	size, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if size != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return fmt.Errorf("existing CAS object sha256:%s is corrupt", expectedDigest)
	}
	return nil
}

func LoadBlob(root, format string, locked LockedBlob) (domain.Blob, string, error) {
	if len(locked.SHA256) != sha256.Size*2 {
		return domain.Blob{}, "", errors.New("locked blob has invalid SHA-256 length")
	}
	name, err := WorkspacePath(root, filepath.ToSlash(filepath.Join(".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)))
	if err != nil {
		return domain.Blob{}, "", err
	}
	pathInfo, err := os.Lstat(name)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s is not a regular CAS object", locked.SHA256)
	}
	file, err := os.Open(name)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("open blob sha256:%s: %w", locked.SHA256, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return domain.Blob{}, "", err
	}
	if !os.SameFile(pathInfo, info) {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s changed while opening", locked.SHA256)
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
