package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const ManifestFilename = "snailmail.toml"

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func ValidateRepositoryName(name string) error {
	if !identifierPattern.MatchString(name) {
		return fmt.Errorf("repository name %q must use lowercase letters, digits, and hyphens", name)
	}
	return nil
}

func Init(root string, options InitOptions) error {
	if !identifierPattern.MatchString(options.Name) {
		return fmt.Errorf("workspace name %q must use lowercase letters, digits, and hyphens", options.Name)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	manifestPath, err := WorkspacePath(root, ManifestFilename)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(manifestPath); err == nil {
		return fmt.Errorf("workspace already has %s", ManifestFilename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	manifest := Manifest{SchemaVersion: ManifestSchema, Workspace: Workspace{Name: options.Name}, Repositories: map[string]Repository{}}
	if err := WriteManifest(root, manifest); err != nil {
		return err
	}
	if err := makeDirectoriesDurable(filepath.Join(root, ".snailmail", "cas", "sha256"), 0o755); err != nil {
		return fmt.Errorf("create local CAS: %w", err)
	}
	return ensureGitignore(root)
}

func Setup(root string, options SetupOptions) error {
	if err := ValidateRepositoryName(options.Name); err != nil {
		return err
	}
	if options.Format != "pypi" && options.Format != "deb" && options.Format != "helm" {
		return fmt.Errorf("unsupported repository format %q", options.Format)
	}
	if err := validateRelativePath(options.Output); err != nil {
		return fmt.Errorf("invalid repository output: %w", err)
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		return err
	}
	if _, exists := manifest.Repositories[options.Name]; exists {
		return fmt.Errorf("repository %q already exists", options.Name)
	}
	lockPath := filepath.ToSlash(filepath.Join("repos", options.Name+".lock.toml"))
	repository := Repository{Format: options.Format, Lock: lockPath, Output: filepath.ToSlash(options.Output), Gate: "auto"}
	if options.Format == "deb" {
		repository.Suite = options.Suite
		repository.Component = options.Component
		repository.Architectures = append([]string(nil), options.Architectures...)
		if repository.Suite == "" {
			repository.Suite = "stable"
		}
		if repository.Component == "" {
			repository.Component = "main"
		}
		if len(repository.Architectures) == 0 {
			repository.Architectures = []string{"amd64"}
		}
	}
	manifest.Repositories[options.Name] = repository
	resolvedLock, err := WorkspacePath(root, repository.Lock)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(resolvedLock); err == nil {
		return fmt.Errorf("refusing to overwrite existing lock %q", repository.Lock)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := WorkspacePath(root, repository.Output); err != nil {
		return err
	}
	if err := WriteLock(root, repository, RepositoryLock{SchemaVersion: LockSchema, Repository: options.Name}); err != nil {
		return err
	}
	return WriteManifest(root, manifest)
}

func LoadManifest(root string) (Manifest, error) {
	var manifest Manifest
	name, err := WorkspacePath(root, ManifestFilename)
	if err != nil {
		return Manifest{}, err
	}
	if err := decodeTOML(name, &manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.SchemaVersion != ManifestSchema || !identifierPattern.MatchString(manifest.Workspace.Name) {
		return Manifest{}, errors.New("invalid workspace manifest schema or name")
	}
	if manifest.Repositories == nil {
		manifest.Repositories = make(map[string]Repository)
	}
	for name, repository := range manifest.Repositories {
		if !identifierPattern.MatchString(name) {
			return Manifest{}, fmt.Errorf("invalid repository name %q", name)
		}
		if repository.Format != "pypi" && repository.Format != "deb" && repository.Format != "helm" {
			return Manifest{}, fmt.Errorf("repository %q has unsupported format %q", name, repository.Format)
		}
		if err := validateRelativePath(repository.Lock); err != nil {
			return Manifest{}, fmt.Errorf("repository %q lock path: %w", name, err)
		}
		if err := validateRelativePath(repository.Output); err != nil {
			return Manifest{}, fmt.Errorf("repository %q output path: %w", name, err)
		}
	}
	return manifest, nil
}

func WriteManifest(root string, manifest Manifest) error {
	manifest.SchemaVersion = ManifestSchema
	encoded, err := toml.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode workspace manifest: %w", err)
	}
	name, err := WorkspacePath(root, ManifestFilename)
	if err != nil {
		return err
	}
	return atomicWrite(name, encoded, 0o644)
}

func LoadLock(root string, repository Repository) (RepositoryLock, error) {
	var lock RepositoryLock
	name, err := WorkspacePath(root, repository.Lock)
	if err != nil {
		return RepositoryLock{}, err
	}
	if err := decodeTOML(name, &lock); err != nil {
		return RepositoryLock{}, err
	}
	if lock.SchemaVersion != LockSchema || lock.Repository == "" {
		return RepositoryLock{}, errors.New("invalid repository lock schema")
	}
	canonicalizeLock(&lock)
	return lock, nil
}

func WriteLock(root string, repository Repository, lock RepositoryLock) error {
	lock.SchemaVersion = LockSchema
	canonicalizeLock(&lock)
	encoded, err := toml.Marshal(lock)
	if err != nil {
		return fmt.Errorf("encode repository lock: %w", err)
	}
	name, err := WorkspacePath(root, repository.Lock)
	if err != nil {
		return err
	}
	return atomicWrite(name, encoded, 0o644)
}

func AddBlob(lock *RepositoryLock, format, track, distro string, blob LockedBlob, packageName, version string) (bool, error) {
	if track == "" {
		track = "stable"
	}
	if filepath.Base(blob.Filename) != blob.Filename || blob.Filename == "" {
		return false, fmt.Errorf("unsafe artifact filename %q", blob.Filename)
	}
	index := -1
	for i := range lock.PackageVersion {
		if lock.PackageVersion[i].Package == packageName && lock.PackageVersion[i].Version == version {
			index = i
			break
		}
	}
	if index < 0 {
		lock.PackageVersion = append(lock.PackageVersion, PackageVersion{Package: packageName, Version: version, State: "draft"})
		index = len(lock.PackageVersion) - 1
	}
	packageVersion := &lock.PackageVersion[index]
	for _, existing := range packageVersion.Blobs {
		if existing.SHA256 == blob.SHA256 && existing.Filename == blob.Filename {
			return false, nil
		}
		conflicts := existing.Filename == blob.Filename
		if format == "helm" || (format == "deb" && existing.Architecture == blob.Architecture) {
			conflicts = true
		}
		if conflicts {
			return false, fmt.Errorf("package %s@%s is already bound to different bytes", packageName, version)
		}
	}
	packageVersion.Blobs = append(packageVersion.Blobs, blob)
	placementExists := false
	for _, placement := range lock.Placement {
		if placement.Package == packageName && placement.Version == version && placement.Track == track && placement.Distro == distro {
			placementExists = true
			break
		}
	}
	if !placementExists {
		lock.Placement = append(lock.Placement, Placement{Package: packageName, Version: version, Track: track, Distro: distro})
	}
	canonicalizeLock(lock)
	return true, nil
}

func HashFile(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func RepositoryNames(manifest Manifest) []string {
	names := make([]string, 0, len(manifest.Repositories))
	for name := range manifest.Repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func canonicalizeLock(lock *RepositoryLock) {
	for index := range lock.PackageVersion {
		sort.Slice(lock.PackageVersion[index].Blobs, func(i, j int) bool {
			left, right := lock.PackageVersion[index].Blobs[i], lock.PackageVersion[index].Blobs[j]
			if left.Architecture != right.Architecture {
				return left.Architecture < right.Architecture
			}
			if left.Filename != right.Filename {
				return left.Filename < right.Filename
			}
			return left.SHA256 < right.SHA256
		})
	}
	sort.Slice(lock.PackageVersion, func(i, j int) bool {
		if lock.PackageVersion[i].Package != lock.PackageVersion[j].Package {
			return lock.PackageVersion[i].Package < lock.PackageVersion[j].Package
		}
		return lock.PackageVersion[i].Version < lock.PackageVersion[j].Version
	})
	sort.Slice(lock.Placement, func(i, j int) bool {
		left, right := lock.Placement[i], lock.Placement[j]
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		if left.Track != right.Track {
			return left.Track < right.Track
		}
		return left.Distro < right.Distro
	})
}

func validateRelativePath(name string) error {
	if name == "" || filepath.IsAbs(name) {
		return errors.New("path must be non-empty and relative")
	}
	if strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("path contains a control character")
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes the workspace")
	}
	return nil
}

func decodeTOML(name string, target any) error {
	content, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read %q: %w", name, err)
	}
	decoder := toml.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %q: %w", name, err)
	}
	return nil
}

func atomicWrite(name string, content []byte, mode os.FileMode) error {
	if err := makeDirectoriesDurable(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(name), ".snailmail-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(name))
}

func makeDirectoriesDurable(name string, mode os.FileMode) error {
	var created []string
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("path %q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		created = append(created, current)
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("cannot find existing directory ancestor")
		}
	}
	if err := os.MkdirAll(name, mode); err != nil {
		return err
	}
	for _, directory := range created {
		if err := syncStateDirectory(filepath.Dir(directory)); err != nil {
			return err
		}
	}
	return nil
}

func syncStateDirectory(name string) error {
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

func ValidateLock(lock RepositoryLock, expectedRepository, format string) error {
	if lock.SchemaVersion != LockSchema || lock.Repository != expectedRepository {
		return fmt.Errorf("lock repository identity does not match %q", expectedRepository)
	}
	versions := make(map[string]bool)
	for _, packageVersion := range lock.PackageVersion {
		if packageVersion.Package == "" || packageVersion.Version == "" || packageVersion.State != "draft" || len(packageVersion.Blobs) == 0 {
			return fmt.Errorf("invalid package version %s@%s", packageVersion.Package, packageVersion.Version)
		}
		identity := packageVersion.Package + "\x00" + packageVersion.Version
		if versions[identity] {
			return fmt.Errorf("duplicate package version %s@%s", packageVersion.Package, packageVersion.Version)
		}
		versions[identity] = true
		coordinates := make(map[string]bool)
		for _, blob := range packageVersion.Blobs {
			if blob.Filename == "" || filepath.Base(blob.Filename) != blob.Filename || blob.Size < 0 {
				return fmt.Errorf("invalid locked blob filename or size")
			}
			decoded, err := hex.DecodeString(blob.SHA256)
			if err != nil || len(decoded) != sha256.Size || blob.SHA256 != strings.ToLower(blob.SHA256) {
				return fmt.Errorf("invalid locked blob SHA-256")
			}
			coordinate := blob.Filename
			if format == "deb" {
				coordinate = blob.Architecture
			}
			if format == "helm" {
				coordinate = "chart"
			}
			if coordinates[coordinate] {
				return fmt.Errorf("duplicate blob coordinate for %s@%s", packageVersion.Package, packageVersion.Version)
			}
			coordinates[coordinate] = true
		}
	}
	placements := make(map[string]bool)
	for _, placement := range lock.Placement {
		identity := placement.Package + "\x00" + placement.Version
		if !versions[identity] || placement.Track == "" {
			return fmt.Errorf("dangling or invalid placement for %s@%s", placement.Package, placement.Version)
		}
		coordinate := identity + "\x00" + placement.Track + "\x00" + placement.Distro
		if placements[coordinate] {
			return fmt.Errorf("duplicate placement for %s@%s", placement.Package, placement.Version)
		}
		placements[coordinate] = true
	}
	return nil
}

func WorkspacePath(root, relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	existing := candidate
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", errors.New("cannot resolve workspace path")
		}
		existing = parent
	}
	resolvedExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	if !pathWithin(resolvedRoot, resolvedExisting) {
		return "", fmt.Errorf("path %q escapes the workspace through a symlink", relative)
	}
	if _, err := os.Lstat(candidate); err == nil {
		resolvedCandidate, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", err
		}
		if !pathWithin(resolvedRoot, resolvedCandidate) {
			return "", fmt.Errorf("path %q escapes the workspace through a symlink", relative)
		}
	}
	return candidate, nil
}

func pathWithin(root, name string) bool {
	relative, err := filepath.Rel(root, name)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func ensureGitignore(root string) error {
	const block = "# snailmail local state\n.snailmail/\n*.snailmail-plan.json\n"
	name := filepath.Join(root, ".gitignore")
	content, err := os.ReadFile(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if strings.Contains(string(content), ".snailmail/") {
		return nil
	}
	if len(content) != 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	content = append(content, []byte(block)...)
	return atomicWrite(name, content, 0o644)
}
