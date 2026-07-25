package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/shellcell/snailmail/blob"
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
	if options.ForgeRepository != "" && !validGitHubRepository(options.ForgeRepository) {
		return errors.New("forge repository must use GitHub owner/name syntax")
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
	workspaceID, err := randomWorkspaceID()
	if err != nil {
		return fmt.Errorf("create workspace identity: %w", err)
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchema, Workspace: Workspace{Name: options.Name, ID: workspaceID, ForgeRepository: options.ForgeRepository},
		BlobStore: BlobStoreConfig{Type: "local"}, Repositories: map[string]Repository{},
	}
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
	hostType := options.HostType
	if hostType == "" {
		hostType = "local"
	}
	visibility := options.Visibility
	if visibility == "" {
		visibility = "public"
	}
	gatePolicy := options.Gate
	if gatePolicy == "" {
		gatePolicy = "auto"
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		return err
	}
	if _, exists := manifest.Repositories[options.Name]; exists {
		return fmt.Errorf("repository %q already exists", options.Name)
	}
	lockPath := filepath.ToSlash(filepath.Join("repos", options.Name+".lock.toml"))
	repository := Repository{
		Format: options.Format, Lock: lockPath, Gate: gatePolicy, ApprovalKeys: append([]string(nil), options.ApprovalKeys...), Visibility: visibility,
		Host: HostConfig{
			Type: hostType, Path: filepath.ToSlash(options.Output), Bucket: options.Bucket,
			Prefix: options.Prefix, Region: options.Region, Endpoint: options.Endpoint,
			CanonicalEndpoint: options.CanonicalEndpoint, UsePathStyle: options.UsePathStyle,
			ReadAuth: options.ReadAuth, CredentialBroker: options.CredentialBroker,
			Repository: options.Repository, Branch: options.Branch, PreviewRepository: options.PreviewRepository,
			PreviewBranch: options.PreviewBranch, PreviewEndpoint: options.PreviewEndpoint,
		},
	}
	if hostType == "github-pages" {
		if repository.Host.Branch == "" {
			repository.Host.Branch = "gh-pages"
		}
		if repository.Host.PreviewBranch == "" {
			repository.Host.PreviewBranch = "gh-pages"
		}
	}
	if err := validateRepositoryHost(options.Name, repository); err != nil {
		return err
	}
	if err := validateGateConfiguration(options.Name, repository, manifest.Workspace.ForgeRepository); err != nil {
		return err
	}
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
	if repository.Host.Type == "local" {
		if _, err := WorkspacePath(root, repository.Host.Path); err != nil {
			return err
		}
	}
	if err := WriteLock(root, repository, RepositoryLock{SchemaVersion: LockSchema, Repository: options.Name}); err != nil {
		return err
	}
	if err := writeInstallDocument(root, options.Name, repository); err != nil {
		return err
	}
	return WriteManifest(root, manifest)
}

func writeInstallDocument(root, name string, repository Repository) error {
	if (repository.Host.Type != "s3" && repository.Host.Type != "github-pages") || repository.Format != "pypi" {
		return nil
	}
	content := installDocumentContent(name, repository)
	filename, err := WorkspacePath(root, filepath.ToSlash(filepath.Join("docs", "install-"+name+".md")))
	if err != nil {
		return err
	}
	return atomicWrite(filename, content, 0o644)
}

func ValidateInstallDocument(root, name string, repository Repository) error {
	if (repository.Host.Type != "s3" && repository.Host.Type != "github-pages") || repository.Format != "pypi" {
		return nil
	}
	filename, err := WorkspacePath(root, filepath.ToSlash(filepath.Join("docs", "install-"+name+".md")))
	if err != nil {
		return err
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, installDocumentContent(name, repository)) {
		return fmt.Errorf("install document for repository %q does not match its canonical endpoint", name)
	}
	return nil
}

func installDocumentContent(name string, repository Repository) []byte {
	endpoint := strings.TrimSuffix(repository.Host.CanonicalEndpoint, "/") + "/simple/"
	credentialNote := ""
	if repository.Visibility == "private" {
		parsed, _ := url.Parse(repository.Host.CanonicalEndpoint)
		credentialNote = "Configure a short-lived Basic credential for `" + parsed.Hostname() + "` in your netrc before installing.\n\n"
	}
	return []byte("# Install from " + name + "\n\n" + credentialNote +
		"```sh\npython -m pip install --index-url " + shellQuote(endpoint) + " PACKAGE\n```\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func LoadManifest(root string) (Manifest, error) {
	name, err := WorkspacePath(root, ManifestFilename)
	if err != nil {
		return Manifest{}, err
	}
	content, err := os.ReadFile(name)
	if err != nil {
		return Manifest{}, fmt.Errorf("read %q: %w", name, err)
	}
	var header struct {
		SchemaVersion int `toml:"schema_version"`
	}
	if err := toml.Unmarshal(content, &header); err != nil {
		return Manifest{}, fmt.Errorf("decode %q: %w", name, err)
	}
	var manifest Manifest
	if header.SchemaVersion == 1 {
		var legacy legacyManifest
		decoder := toml.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&legacy); err != nil {
			return Manifest{}, fmt.Errorf("decode %q: %w", name, err)
		}
		manifest = migrateLegacyManifest(legacy)
	} else {
		decoder := toml.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return Manifest{}, fmt.Errorf("decode %q: %w", name, err)
		}
		if header.SchemaVersion == 2 || header.SchemaVersion == 3 {
			manifest.SchemaVersion = ManifestSchema
			if header.SchemaVersion == 2 {
				manifest.Workspace.ID = legacyWorkspaceID(manifest.Workspace.Name)
				manifest.BlobStore = BlobStoreConfig{Type: "local"}
			}
		}
	}
	if manifest.SchemaVersion != ManifestSchema || !identifierPattern.MatchString(manifest.Workspace.Name) || !validSHA256(manifest.Workspace.ID) {
		return Manifest{}, errors.New("invalid workspace manifest schema or name")
	}
	if manifest.Workspace.ForgeRepository != "" && !validGitHubRepository(manifest.Workspace.ForgeRepository) {
		return Manifest{}, errors.New("invalid workspace forge repository")
	}
	if err := ValidateBlobStore(manifest.BlobStore); err != nil {
		return Manifest{}, err
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
		if !validGate(repository.Gate) {
			return Manifest{}, fmt.Errorf("repository %q has invalid gate %q", name, repository.Gate)
		}
		if err := validateGateConfiguration(name, repository, manifest.Workspace.ForgeRepository); err != nil {
			return Manifest{}, err
		}
		if err := validateRelativePath(repository.Lock); err != nil {
			return Manifest{}, fmt.Errorf("repository %q lock path: %w", name, err)
		}
		if err := validateRepositoryHost(name, repository); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

type legacyManifest struct {
	SchemaVersion int                         `toml:"schema_version"`
	Workspace     Workspace                   `toml:"workspace"`
	Repositories  map[string]legacyRepository `toml:"repo"`
}

type legacyRepository struct {
	Format        string   `toml:"format"`
	Lock          string   `toml:"lock"`
	Output        string   `toml:"output"`
	Gate          string   `toml:"gate"`
	Suite         string   `toml:"suite,omitempty"`
	Component     string   `toml:"component,omitempty"`
	Architectures []string `toml:"architectures,omitempty"`
}

func migrateLegacyManifest(legacy legacyManifest) Manifest {
	workspace := legacy.Workspace
	workspace.ID = legacyWorkspaceID(workspace.Name)
	manifest := Manifest{
		SchemaVersion: ManifestSchema, Workspace: workspace, BlobStore: BlobStoreConfig{Type: "local"},
		Repositories: make(map[string]Repository, len(legacy.Repositories)),
	}
	for name, repository := range legacy.Repositories {
		manifest.Repositories[name] = Repository{
			Format: repository.Format, Lock: repository.Lock, Gate: repository.Gate,
			Visibility: "public", Host: HostConfig{Type: "local", Path: repository.Output},
			Suite: repository.Suite, Component: repository.Component,
			Architectures: append([]string(nil), repository.Architectures...),
		}
	}
	return manifest
}

func validateRepositoryHost(name string, repository Repository) error {
	if repository.Visibility != "public" && repository.Visibility != "private" {
		return fmt.Errorf("repository %q has invalid visibility %q", name, repository.Visibility)
	}
	switch repository.Host.Type {
	case "local":
		if err := validateRelativePath(repository.Host.Path); err != nil {
			return fmt.Errorf("repository %q local host path: %w", name, err)
		}
		if repository.Host.Bucket != "" || repository.Host.Prefix != "" || repository.Host.Endpoint != "" || repository.Host.CanonicalEndpoint != "" || repository.Host.ReadAuth != "" || repository.Host.CredentialBroker != "" || repository.Host.Repository != "" || repository.Host.PreviewRepository != "" || repository.Host.PreviewEndpoint != "" || repository.Host.Branch != "" || repository.Host.PreviewBranch != "" {
			return fmt.Errorf("repository %q local host has S3-only configuration", name)
		}
	case "s3":
		if repository.Format != "pypi" {
			return fmt.Errorf("repository %q: the first S3 host slice supports PyPI only", name)
		}
		if repository.Visibility == "private" && (repository.Host.ReadAuth != "basic" || repository.Host.CredentialBroker != "default") {
			return fmt.Errorf("repository %q: private S3 hosting requires Basic read auth and a credential broker", name)
		}
		if repository.Visibility == "public" && (repository.Host.ReadAuth != "" || repository.Host.CredentialBroker != "") {
			return fmt.Errorf("repository %q: public S3 hosting must not configure private read credentials", name)
		}
		if repository.Host.Path != "" || repository.Host.Bucket == "" || repository.Host.CanonicalEndpoint == "" || repository.Host.Repository != "" || repository.Host.PreviewRepository != "" || repository.Host.PreviewEndpoint != "" || repository.Host.Branch != "" || repository.Host.PreviewBranch != "" {
			return fmt.Errorf("repository %q S3 host requires bucket and canonical endpoint, without a local path", name)
		}
		prefix := strings.Trim(repository.Host.Prefix, "/")
		if prefix != repository.Host.Prefix || (prefix != "" && (path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../"))) {
			return fmt.Errorf("repository %q has invalid S3 prefix %q", name, repository.Host.Prefix)
		}
		if err := validateHTTPURL(repository.Host.CanonicalEndpoint); err != nil {
			return fmt.Errorf("repository %q canonical endpoint: %w", name, err)
		}
		parsed, _ := url.Parse(repository.Host.CanonicalEndpoint)
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
			return fmt.Errorf("repository %q client endpoint must use HTTPS", name)
		}
		if repository.Host.Endpoint != "" {
			if err := validateHTTPURL(repository.Host.Endpoint); err != nil {
				return fmt.Errorf("repository %q S3 endpoint: %w", name, err)
			}
			parsed, _ := url.Parse(repository.Host.Endpoint)
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
				return fmt.Errorf("repository %q S3 API endpoint must use HTTPS", name)
			}
		}
	case "github-pages":
		if repository.Format != "pypi" || repository.Visibility != "public" {
			return fmt.Errorf("repository %q: GitHub Pages currently supports public PyPI only", name)
		}
		if repository.Host.Path != "" || repository.Host.Bucket != "" || repository.Host.Prefix != "" || repository.Host.Region != "" || repository.Host.Endpoint != "" || repository.Host.UsePathStyle || repository.Host.ReadAuth != "" || repository.Host.CredentialBroker != "" {
			return fmt.Errorf("repository %q GitHub Pages host has incompatible configuration", name)
		}
		if !validGitHubRepository(repository.Host.Repository) || !validGitHubRepository(repository.Host.PreviewRepository) || strings.EqualFold(repository.Host.Repository, repository.Host.PreviewRepository) {
			return fmt.Errorf("repository %q GitHub Pages host requires distinct production and preview owner/name repositories", name)
		}
		if sameConfiguredEndpoint(repository.Host.CanonicalEndpoint, repository.Host.PreviewEndpoint) {
			return fmt.Errorf("repository %q GitHub Pages production and preview endpoints must be distinct", name)
		}
		if !validGitBranch(repository.Host.Branch) || !validGitBranch(repository.Host.PreviewBranch) {
			return fmt.Errorf("repository %q GitHub Pages host has an invalid branch", name)
		}
		for _, configured := range []struct{ label, endpoint string }{{"canonical", repository.Host.CanonicalEndpoint}, {"preview", repository.Host.PreviewEndpoint}} {
			label, endpoint := configured.label, configured.endpoint
			if err := validateHTTPURL(endpoint); err != nil {
				return fmt.Errorf("repository %q %s endpoint: %w", name, label, err)
			}
			parsed, _ := url.Parse(endpoint)
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
				return fmt.Errorf("repository %q %s endpoint must use HTTPS", name, label)
			}
		}
	default:
		return fmt.Errorf("repository %q has unsupported host type %q", name, repository.Host.Type)
	}
	return nil
}

func validateHTTPURL(value string) error {
	if strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("must not contain control characters")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be an HTTP(S) URL without credentials, query, or fragment")
	}
	return nil
}

func isLoopbackHost(value string) bool {
	return value == "localhost" || value == "127.0.0.1" || value == "::1"
}

func validGitHubRepository(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && validGitHubName(parts[0]) && validGitHubName(parts[1]) && !strings.HasSuffix(strings.ToLower(parts[1]), ".git")
}

func sameConfiguredEndpoint(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) && strings.EqualFold(leftURL.Host, rightURL.Host) &&
		strings.EqualFold(strings.TrimSuffix(leftURL.EscapedPath(), "/"), strings.TrimSuffix(rightURL.EscapedPath(), "/"))
}

func validGitBranch(value string) bool {
	if value == "" || value == "@" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, ".lock") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") {
			return false
		}
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune("~^:?*[\\", character) {
			return false
		}
	}
	return true
}

func validGitHubName(value string) bool {
	if value == "" || len(value) > 100 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validGate(value string) bool {
	return value == "auto" || value == "pr" || value == "approval"
}

func validateGateConfiguration(name string, repository Repository, forgeRepository string) error {
	if err := ValidateGateConfiguration(repository.Gate, repository.ApprovalKeys, forgeRepository); err != nil {
		return fmt.Errorf("repository %q: %w", name, err)
	}
	return nil
}

func ValidateGateConfiguration(policy string, approvalKeys []string, forgeRepository string) error {
	if !validGate(policy) {
		return fmt.Errorf("invalid gate %q", policy)
	}
	if policy == "pr" && forgeRepository == "" {
		return errors.New("PR gate requires workspace forge_repository")
	}
	if policy != "approval" {
		if len(approvalKeys) != 0 {
			return errors.New("approval keys require an approval gate")
		}
		return nil
	}
	if len(approvalKeys) == 0 {
		return errors.New("approval gate requires at least one Ed25519 public key")
	}
	previous := ""
	for _, encoded := range approvalKeys {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize || (previous != "" && previous >= encoded) {
			return errors.New("invalid or unsorted approval keys")
		}
		previous = encoded
	}
	return nil
}

func WriteManifest(root string, manifest Manifest) error {
	manifest.SchemaVersion = ManifestSchema
	if manifest.Workspace.ID == "" {
		manifest.Workspace.ID = legacyWorkspaceID(manifest.Workspace.Name)
	}
	if manifest.BlobStore.Type == "" {
		manifest.BlobStore.Type = "local"
	}
	if !identifierPattern.MatchString(manifest.Workspace.Name) || !validSHA256(manifest.Workspace.ID) {
		return errors.New("invalid workspace name or identity")
	}
	if manifest.Workspace.ForgeRepository != "" && !validGitHubRepository(manifest.Workspace.ForgeRepository) {
		return errors.New("invalid workspace forge repository")
	}
	if err := ValidateBlobStore(manifest.BlobStore); err != nil {
		return err
	}
	for name, repository := range manifest.Repositories {
		if !identifierPattern.MatchString(name) || !validGate(repository.Gate) {
			return fmt.Errorf("repository %q has invalid name or gate", name)
		}
		if err := validateRepositoryHost(name, repository); err != nil {
			return err
		}
		if err := validateGateConfiguration(name, repository, manifest.Workspace.ForgeRepository); err != nil {
			return err
		}
	}
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

func ValidateBlobStore(configuration BlobStoreConfig) error {
	switch configuration.Type {
	case "local":
		if configuration.Bucket != "" || configuration.Prefix != "" || configuration.Region != "" || configuration.Endpoint != "" || configuration.UsePathStyle {
			return errors.New("local blob store has S3-only configuration")
		}
	case "s3":
		if configuration.Bucket == "" || strings.ContainsAny(configuration.Bucket+configuration.Region, "\x00\r\n") {
			return errors.New("S3 blob store requires a valid bucket")
		}
		prefix := strings.Trim(configuration.Prefix, "/")
		if prefix != configuration.Prefix || strings.ContainsRune(prefix, '\\') || (prefix != "" && (path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../"))) {
			return errors.New("S3 blob store prefix is invalid")
		}
		if configuration.Endpoint != "" {
			if err := validateHTTPURL(configuration.Endpoint); err != nil {
				return fmt.Errorf("S3 blob endpoint: %w", err)
			}
			parsed, _ := url.Parse(configuration.Endpoint)
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
				return errors.New("S3 blob endpoint must use HTTPS")
			}
			if parsed.Path != "" && parsed.Path != "/" {
				return errors.New("S3 blob endpoint must not contain a path")
			}
		}
	default:
		return fmt.Errorf("unsupported blob store type %q", configuration.Type)
	}
	return nil
}

func BlobConfiguration(manifest Manifest) blob.Configuration {
	return blob.Configuration{
		Type: manifest.BlobStore.Type, WorkspaceID: manifest.Workspace.ID,
		Bucket: manifest.BlobStore.Bucket, Prefix: manifest.BlobStore.Prefix, Region: manifest.BlobStore.Region,
		Endpoint: manifest.BlobStore.Endpoint, UsePathStyle: manifest.BlobStore.UsePathStyle,
	}
}

func BlobStoreFromOptions(options BlobStoreOptions) BlobStoreConfig {
	storeType := options.Type
	if storeType == "" {
		storeType = "local"
	}
	return BlobStoreConfig{
		Type: storeType, Bucket: options.Bucket, Prefix: options.Prefix, Region: options.Region,
		Endpoint: options.Endpoint, UsePathStyle: options.UsePathStyle,
	}
}

func randomWorkspaceID() (string, error) {
	var value [sha256.Size]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func NewWorkspaceID() (string, error) {
	return randomWorkspaceID()
}

func IsLegacyWorkspaceID(name, identifier string) bool {
	return identifier == legacyWorkspaceID(name)
}

func legacyWorkspaceID(name string) string {
	digest := sha256.Sum256([]byte("snailmail-workspace\x00" + name))
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
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
