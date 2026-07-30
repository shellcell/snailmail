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
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/factscache"
)

// legacyDigests decides whether MD5 and SHA-1 have to be computed over an
// artifact's bytes.
//
// Only a Debian repository publishes them, and computing all three digests runs
// at about a fifth the speed of SHA-256 alone — a cost paid on every plan and
// every apply, over every artifact.
//
// Locks written before this distinction existed record both for every format.
// Those recorded values are no longer checked, and that costs nothing: the
// content is pinned by SHA-256, so bytes that match it match every other digest
// of them too. An MD5 could only disagree if a lock had been hand-edited into
// contradicting itself, which the SHA-256 it also records already catches. They
// stop being written the next time a lock is rewritten.
type legacyDigests struct {
	md5Hash  hash.Hash
	sha1Hash hash.Hash
}

func newLegacyDigests(format string, _ LockedBlob) legacyDigests {
	selected, err := formats.For(format)
	if err != nil {
		// An unknown format is not a reason to compute less than before.
		return legacyDigests{md5Hash: md5.New(), sha1Hash: sha1.New()}
	}
	if !selected.RequiresLegacyDigests() {
		return legacyDigests{}
	}
	return legacyDigests{md5Hash: md5.New(), sha1Hash: sha1.New()}
}

// writers returns the hashers to tee the artifact through, SHA-256 always
// included because everything is pinned by it.
func (digests legacyDigests) writers(sha256Hash hash.Hash) io.Writer {
	if digests.md5Hash == nil {
		return sha256Hash
	}
	return io.MultiWriter(digests.md5Hash, digests.sha1Hash, sha256Hash)
}

func (digests legacyDigests) md5Hex() string {
	if digests.md5Hash == nil {
		return ""
	}
	return hex.EncodeToString(digests.md5Hash.Sum(nil))
}

func (digests legacyDigests) sha1Hex() string {
	if digests.sha1Hash == nil {
		return ""
	}
	return hex.EncodeToString(digests.sha1Hash.Sum(nil))
}

// PutArtifact stores an artifact and derives its facts. Supplied identity is
// used only by formats whose artifacts carry none; the rest reject it.
func PutArtifact(root, format, sourceName string, supplied formats.Identity) (domain.Blob, error) {
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
	sha256Hash := sha256.New()
	legacy := newLegacyDigests(format, LockedBlob{})
	size, copyErr := io.Copy(io.MultiWriter(temporary, legacy.writers(sha256Hash)), io.LimitReader(source, maximum+1))
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
	facts, err := inspect(format, filename, temporary, size, supplied)
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
		MD5:      legacy.md5Hex(),
		SHA1:     legacy.sha1Hex(),
		SHA256:   digest,
		Facts:    facts,
	}, nil
}

func InspectArtifactBytes(format, filename string, content []byte, supplied formats.Identity) (domain.Blob, error) {
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
	facts, err := inspect(format, filename, reader, int64(len(content)), supplied)
	if err != nil {
		return domain.Blob{}, err
	}
	// The same rule the import path uses, so an artifact adopted and the same
	// artifact added agree about what the lock records for it.
	legacy := newLegacyDigests(format, LockedBlob{})
	sha256Hash := sha256.New()
	if _, err := legacy.writers(sha256Hash).Write(content); err != nil {
		return domain.Blob{}, err
	}
	return domain.Blob{
		Filename: filename, Size: int64(len(content)), MD5: legacy.md5Hex(),
		SHA1: legacy.sha1Hex(), SHA256: hex.EncodeToString(sha256Hash.Sum(nil)), Facts: facts,
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

func LoadBlob(root, format string, locked LockedBlob, supplied formats.Identity) (domain.Blob, string, error) {
	return LoadBlobContext(context.Background(), root, format, locked, supplied)
}

func LoadBlobContext(ctx context.Context, root, format string, locked LockedBlob, supplied formats.Identity) (domain.Blob, string, error) {
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
	result, err := validateLockedBlobOpenContext(ctx, file, pathInfo, name, format, locked, supplied)
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

func ValidateLockedBlobOpenContext(ctx context.Context, file *os.File, info os.FileInfo, name, format string, locked LockedBlob, supplied formats.Identity) (domain.Blob, error) {
	return validateLockedBlobOpenContext(ctx, file, info, name, format, locked, supplied)
}

func validateLockedDigest(format string, locked LockedBlob) error {
	decoded, err := hex.DecodeString(locked.SHA256)
	if err != nil || len(decoded) != sha256.Size || locked.SHA256 != strings.ToLower(locked.SHA256) {
		return errors.New("locked blob has invalid SHA-256")
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return err
	}
	if locked.Size < 0 || locked.Size > maximum {
		return fmt.Errorf("blob sha256:%s exceeds format size limit", locked.SHA256)
	}
	return nil
}

func EnsureBlob(ctx context.Context, root, format string, locked LockedBlob, store blob.Store, supplied formats.Identity) (domain.Blob, string, error) {
	if err := validateLockedDigest(format, locked); err != nil {
		return domain.Blob{}, "", err
	}
	loaded, name, localErr := LoadBlob(root, format, locked, supplied)
	if localErr == nil {
		return loaded, name, nil
	}
	if store == nil {
		return domain.Blob{}, "", localErr
	}
	return InstallBlob(root, format, locked, supplied, func(destination io.Writer) error {
		return store.Fetch(ctx, blob.Ref{SHA256: locked.SHA256, Size: locked.Size}, destination)
	})
}

// InstallBlob writes bytes into the workspace CAS and accepts them only if they
// match the locked record, so every source of a blob is admitted through one
// verified path rather than each being trusted on its own terms.
//
// write receives a temporary file inside the CAS. The bytes become the blob only
// after they hash to the locked digest; a mismatch leaves the CAS untouched.
func InstallBlob(root, format string, locked LockedBlob, supplied formats.Identity, write func(io.Writer) error) (domain.Blob, string, error) {
	if err := validateLockedDigest(format, locked); err != nil {
		return domain.Blob{}, "", err
	}
	relativeName := filepath.Join(".snailmail", "cas", "sha256", locked.SHA256[:2], locked.SHA256)
	resolvedRoot, err := ResolveWorkspaceRoot(root)
	if err != nil {
		return domain.Blob{}, "", err
	}
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
	if err := write(temporary); err != nil {
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
	if _, err := validateLockedBlobOpen(verifiedFile, pathInfo, temporaryName, format, locked, supplied); err != nil {
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
	return LoadBlob(root, format, locked, supplied)
}

func validateLockedBlobOpen(file *os.File, pathInfo os.FileInfo, name, format string, locked LockedBlob, supplied formats.Identity) (domain.Blob, error) {
	return validateLockedBlobOpenContext(context.Background(), file, pathInfo, name, format, locked, supplied)
}

func validateLockedBlobOpenContext(ctx context.Context, file *os.File, pathInfo os.FileInfo, name, format string, locked LockedBlob, supplied formats.Identity) (domain.Blob, error) {
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
	sha256Hash := sha256.New()
	legacy := newLegacyDigests(format, locked)
	size, err := io.Copy(legacy.writers(sha256Hash), io.LimitReader(contextReader{ctx: ctx, reader: file}, locked.Size+1))
	if err != nil {
		return domain.Blob{}, fmt.Errorf("%w: read blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
	}
	validated := domain.Blob{
		Filename: locked.Filename,
		Added:    parseLockTime(locked.Added),
		Size:     size,
		MD5:      legacy.md5Hex(),
		SHA1:     legacy.sha1Hex(),
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
	}
	// Establish that these bytes are exactly the locked content before consulting
	// any memo, so a cached parse is only ever reused for content this call has
	// itself just verified.
	// A recorded MD5 or SHA-1 is compared only where one was derived. A lock
	// written before these were computed by need records both for every format;
	// this reads a format that publishes neither, so there is nothing to compare
	// against and an absent value is not a disagreement. The content is still
	// pinned: SHA-256 is checked on the line above, and bytes matching it match
	// every other digest of them.
	if size != info.Size() || validated.Size != locked.Size || validated.SHA256 != locked.SHA256 ||
		legacyDigestConflict(locked, LockedBlob{MD5: validated.MD5, SHA1: validated.SHA1}) {
		return domain.Blob{}, fmt.Errorf("%w: blob sha256:%s disagrees with its lock", blob.ErrCorrupt, locked.SHA256)
	}
	facts, cached := factscache.Lookup(format, validated.SHA256)
	if !cached {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return domain.Blob{}, fmt.Errorf("%w: seek blob sha256:%s: %w", blob.ErrUnavailable, locked.SHA256, err)
		}
		facts, err = inspect(format, locked.Filename, contextReaderAt{ctx: ctx, reader: file}, size, supplied)
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

// parseLockTime reads a recorded timestamp, treating an unreadable one as
// absent: the time is presentation, and a listing that refused to render
// because a date was malformed would be worse than one that omits it.
func parseLockTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

// LockTime formats an instant the way the lock records one. It exists so the
// two commands that add artifacts agree on the format the reader parses back.
func LockTime(at time.Time) string { return at.UTC().Format(time.RFC3339) }

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

func inspect(format, filename string, reader io.ReaderAt, size int64, supplied formats.Identity) (domain.PackageFacts, error) {
	selected, err := formats.For(format)
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("unsupported format %q", format)
	}
	return selected.Inspect(filename, reader, size, supplied)
}

func formatMaximum(format string) (int64, error) {
	selected, err := formats.For(format)
	if err != nil {
		return 0, fmt.Errorf("unsupported format %q", format)
	}
	return selected.MaxArtifactSize(), nil
}

// InspectArtifactFile reads an artifact's facts and digests from a file.
//
// The same work InspectArtifactBytes does, without the artifact being in memory.
// It costs nothing to support: the format inspectors already take an io.ReaderAt,
// which an *os.File satisfies, so only the digesting had to change — and that is a
// streaming operation that was reading from a slice for no reason.
func InspectArtifactFile(format, filename string, file *os.File, size int64, supplied formats.Identity) (domain.Blob, error) {
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, "\x00\r\n/\\") {
		return domain.Blob{}, errors.New("artifact filename is unsafe")
	}
	maximum, err := formatMaximum(format)
	if err != nil {
		return domain.Blob{}, err
	}
	if size > maximum {
		return domain.Blob{}, errors.New("artifact exceeds format size limit")
	}
	facts, err := inspect(format, filename, file, size, supplied)
	if err != nil {
		return domain.Blob{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return domain.Blob{}, err
	}
	// The same rule the other paths use, so an artifact adopted and the same
	// artifact added agree about what the lock records for it.
	legacy := newLegacyDigests(format, LockedBlob{})
	sha256Hash := sha256.New()
	if _, err := io.Copy(legacy.writers(sha256Hash), file); err != nil {
		return domain.Blob{}, err
	}
	return domain.Blob{
		Filename: filename, Size: size, MD5: legacy.md5Hex(), SHA1: legacy.sha1Hex(),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)), Facts: facts,
	}, nil
}
