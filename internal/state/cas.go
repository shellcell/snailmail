package state

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/factscache"
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

func InspectArtifactBytes(format, filename string, content []byte) (domain.Blob, error) {
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, "\x00\r\n/\\") {
		return domain.Blob{}, errors.New("artifact filename is unsafe")
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return domain.Blob{}, err
	}
	if int64(len(content)) > maximum {
		return domain.Blob{}, errors.New("artifact exceeds format size limit")
	}
	reader := bytes.NewReader(content)
	facts, err := inspect(format, filename, reader, int64(len(content)))
	if err != nil {
		return domain.Blob{}, err
	}
	md5Digest := md5.Sum(content)
	sha1Digest := sha1.Sum(content)
	sha256Digest := sha256.Sum256(content)
	return domain.Blob{
		Filename: filename, Size: int64(len(content)), MD5: hex.EncodeToString(md5Digest[:]),
		SHA1: hex.EncodeToString(sha1Digest[:]), SHA256: hex.EncodeToString(sha256Digest[:]), Facts: facts,
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
	size, readErr := io.Copy(hash, io.LimitReader(file, expectedSize+1))
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
	return LoadBlobContext(context.Background(), root, format, locked)
}

func LoadBlobContext(ctx context.Context, root, format string, locked LockedBlob) (domain.Blob, string, error) {
	if len(locked.SHA256) != sha256.Size*2 {
		return domain.Blob{}, "", errors.New("locked blob has invalid SHA-256 length")
	}
	// The relative path is built from an already-validated hex digest, so there
	// is no caller-supplied component to sanitise, and the os.Root handle below
	// refuses to traverse a symlink out of the workspace. Running the general
	// path check as well would repeat that containment once per blob.
	relativeName := filepath.Join(".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)
	resolvedRoot, err := ResolveWorkspaceRoot(root)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("%w: resolve workspace root: %v", blob.ErrUnavailable, err)
	}
	name := filepath.Join(resolvedRoot, relativeName)
	rootHandle, err := os.OpenRoot(resolvedRoot)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("%w: open workspace root: %v", blob.ErrUnavailable, err)
	}
	defer rootHandle.Close()
	pathInfo, err := rootHandle.Lstat(relativeName)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("%w: blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return domain.Blob{}, "", fmt.Errorf("%w: blob sha256:%s is not a regular CAS object", blob.ErrCorrupt, locked.SHA256)
	}
	file, err := rootHandle.Open(relativeName)
	if err != nil {
		return domain.Blob{}, "", fmt.Errorf("%w: open blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	result, err := validateLockedBlobOpenContext(ctx, file, pathInfo, name, format, locked)
	if err != nil {
		return domain.Blob{}, "", err
	}
	return result, name, nil
}

func ValidateLockedBlobReference(format string, locked LockedBlob) error {
	decoded, err := hex.DecodeString(locked.SHA256)
	if err != nil || len(decoded) != sha256.Size || locked.SHA256 != strings.ToLower(locked.SHA256) {
		return fmt.Errorf("%w: locked blob has invalid SHA-256", blob.ErrCorrupt)
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return err
	}
	if locked.Size < 0 || locked.Size > maximum {
		return fmt.Errorf("%w: blob sha256:%s exceeds format size limit", blob.ErrCorrupt, locked.SHA256)
	}
	return nil
}

func ValidateLockedBlobOpenContext(ctx context.Context, file *os.File, info os.FileInfo, name, format string, locked LockedBlob) (domain.Blob, error) {
	return validateLockedBlobOpenContext(ctx, file, info, name, format, locked)
}

func EnsureBlob(ctx context.Context, root, format string, locked LockedBlob, store blob.Store) (domain.Blob, string, error) {
	decoded, err := hex.DecodeString(locked.SHA256)
	if err != nil || len(decoded) != sha256.Size || locked.SHA256 != strings.ToLower(locked.SHA256) {
		return domain.Blob{}, "", errors.New("locked blob has invalid SHA-256")
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return domain.Blob{}, "", err
	}
	if locked.Size < 0 || locked.Size > maximum {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s exceeds format size limit", locked.SHA256)
	}
	loaded, name, localErr := LoadBlob(root, format, locked)
	if localErr == nil {
		return loaded, name, nil
	}
	if store == nil {
		return domain.Blob{}, "", localErr
	}
	relativeName := filepath.Join(".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)
	resolvedRoot, err := ResolveWorkspaceRoot(root)
	if err != nil {
		return domain.Blob{}, "", err
	}
	name = filepath.Join(resolvedRoot, relativeName)
	rootHandle, err := os.OpenRoot(resolvedRoot)
	if err != nil {
		return domain.Blob{}, "", err
	}
	defer rootHandle.Close()
	if info, err := rootHandle.Lstat(relativeName); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return domain.Blob{}, "", fmt.Errorf("blob sha256:%s is not a regular CAS object", locked.SHA256)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return domain.Blob{}, "", err
	}
	relativeDirectory := filepath.Dir(relativeName)
	if err := rootHandle.MkdirAll(relativeDirectory, 0o755); err != nil {
		return domain.Blob{}, "", err
	}
	temporaryBase, err := randomCacheName()
	if err != nil {
		return domain.Blob{}, "", err
	}
	temporaryName := filepath.Join(relativeDirectory, temporaryBase)
	temporary, err := rootHandle.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return domain.Blob{}, "", err
	}
	defer func() {
		_ = temporary.Close()
		_ = rootHandle.Remove(temporaryName)
	}()
	if err := store.Fetch(ctx, blob.Ref{SHA256: locked.SHA256, Size: locked.Size}, temporary); err != nil {
		return domain.Blob{}, "", fmt.Errorf("fetch blob sha256:%s: %w", locked.SHA256, err)
	}
	if err := temporary.Sync(); err != nil {
		return domain.Blob{}, "", err
	}
	if err := temporary.Close(); err != nil {
		return domain.Blob{}, "", err
	}
	pathInfo, err := rootHandle.Lstat(temporaryName)
	if err != nil {
		return domain.Blob{}, "", err
	}
	verifiedFile, err := rootHandle.Open(temporaryName)
	if err != nil {
		return domain.Blob{}, "", err
	}
	if _, err := validateLockedBlobOpen(verifiedFile, pathInfo, temporaryName, format, locked); err != nil {
		return domain.Blob{}, "", err
	}
	if err := rootHandle.Chmod(temporaryName, 0o444); err != nil {
		return domain.Blob{}, "", err
	}
	if err := rootHandle.Rename(temporaryName, relativeName); err != nil {
		return domain.Blob{}, "", err
	}
	directory, err := rootHandle.Open(relativeDirectory)
	if err != nil {
		return domain.Blob{}, "", err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return domain.Blob{}, "", syncErr
	}
	if closeErr != nil {
		return domain.Blob{}, "", closeErr
	}
	return LoadBlob(root, format, locked)
}

func validateLockedBlob(name, format string, locked LockedBlob) (domain.Blob, error) {
	pathInfo, err := os.Lstat(name)
	if err != nil {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s is not a regular CAS object", blob.ErrCorrupt, locked.SHA256)
	}
	file, err := os.Open(name)
	if err != nil {
		return domain.Blob{}, fmt.Errorf("%w: open blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	return validateLockedBlobOpen(file, pathInfo, name, format, locked)
}

func validateLockedBlobOpen(file *os.File, pathInfo os.FileInfo, name, format string, locked LockedBlob) (domain.Blob, error) {
	return validateLockedBlobOpenContext(context.Background(), file, pathInfo, name, format, locked)
}

func validateLockedBlobOpenContext(ctx context.Context, file *os.File, pathInfo os.FileInfo, name, format string, locked LockedBlob) (domain.Blob, error) {
	defer file.Close()
	maximum, err := formatMaximum(format)
	if err != nil {
		return domain.Blob{}, err
	}
	if locked.Size < 0 || locked.Size > maximum {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s exceeds format size limit", blob.ErrCorrupt, locked.SHA256)
	}
	info, err := file.Stat()
	if err != nil {
		return domain.Blob{}, fmt.Errorf("%w: stat blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	if !os.SameFile(pathInfo, info) {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s changed while opening", blob.ErrCorrupt, locked.SHA256)
	}
	md5Hash, sha1Hash, sha256Hash := md5.New(), sha1.New(), sha256.New()
	size, err := io.Copy(io.MultiWriter(md5Hash, sha1Hash, sha256Hash), io.LimitReader(contextReader{ctx: ctx, reader: file}, locked.Size+1))
	if err != nil {
		return domain.Blob{}, fmt.Errorf("%w: read blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	validated := domain.Blob{
		Filename: locked.Filename,
		Size:     size,
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:     hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
	}
	// Establish that these bytes are exactly the locked content before consulting
	// any memo, so a cached parse is only ever reused for content this call has
	// itself just verified.
	if size != info.Size() || validated.Size != locked.Size || validated.SHA256 != locked.SHA256 ||
		(locked.MD5 != "" && validated.MD5 != locked.MD5) || (locked.SHA1 != "" && validated.SHA1 != locked.SHA1) {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s disagrees with its lock", blob.ErrCorrupt, locked.SHA256)
	}
	facts, cached := factscache.Lookup(format, validated.SHA256)
	if !cached {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return domain.Blob{}, fmt.Errorf("%w: seek blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
		}
		facts, err = inspect(format, locked.Filename, contextReaderAt{ctx: ctx, reader: file}, size)
		if err != nil {
			if ctx.Err() != nil {
				return domain.Blob{}, ctx.Err()
			}
			return domain.Blob{}, fmt.Errorf("%w: inspect blob sha256:%s: %v", blob.ErrCorrupt, locked.SHA256, err)
		}
		factscache.Store(format, validated.SHA256, facts)
	}
	validated.Facts = facts
	if facts.Architecture != locked.Architecture {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s disagrees with its lock", blob.ErrCorrupt, locked.SHA256)
	}
	if err := ctx.Err(); err != nil {
		return domain.Blob{}, err
	}
	return validated, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

type contextReaderAt struct {
	ctx    context.Context
	reader io.ReaderAt
}

func (reader contextReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.ReadAt(buffer, offset)
}

func randomCacheName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return ".fetch-" + hex.EncodeToString(value[:]), nil
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
