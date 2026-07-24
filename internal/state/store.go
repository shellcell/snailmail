package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const ManifestFilename = "snailmail.toml"

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func Init(root string, options InitOptions) error {
	if !identifierPattern.MatchString(options.Name) {
		return fmt.Errorf("workspace name %q must use lowercase letters, digits, and hyphens", options.Name)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(root, ManifestFilename)
	if _, err := os.Lstat(manifestPath); err == nil {
		return fmt.Errorf("workspace already has %s", ManifestFilename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	manifest := Manifest{SchemaVersion: ManifestSchema, Workspace: Workspace{Name: options.Name}, Repositories: map[string]Repository{}}
	if err := WriteManifest(root, manifest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, ".snailmail", "cas", "sha256"), 0o755); err != nil {
		return fmt.Errorf("create local CAS: %w", err)
	}
	return ensureGitignore(root)
}

func Setup(root string, options SetupOptions) error {
	if !identifierPattern.MatchString(options.Name) {
		return fmt.Errorf("repository name %q must use lowercase letters, digits, and hyphens", options.Name)
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
	if err := WriteLock(root, repository, RepositoryLock{SchemaVersion: LockSchema, Repository: options.Name}); err != nil {
		return err
	}
	return WriteManifest(root, manifest)
}

func LoadManifest(root string) (Manifest, error) {
	var manifest Manifest
	if err := decodeTOML(filepath.Join(root, ManifestFilename), &manifest); err != nil {
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
	return atomicWrite(filepath.Join(root, ManifestFilename), encoded, 0o644)
}

func LoadLock(root string, repository Repository) (RepositoryLock, error) {
	var lock RepositoryLock
	if err := decodeTOML(filepath.Join(root, filepath.FromSlash(repository.Lock)), &lock); err != nil {
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
	return atomicWrite(filepath.Join(root, filepath.FromSlash(repository.Lock)), encoded, 0o644)
}

func AddBlob(lock *RepositoryLock, format, track, distro string, blob LockedBlob, packageName, version string) (bool, error) {
	if track == "" {
		track = "stable"
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

func GitRevision(root string) string {
	output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
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
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
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
	return os.Rename(temporaryName, name)
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
