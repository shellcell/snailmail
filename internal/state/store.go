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
	"sync"
	"time"
	"unicode"

	"github.com/pelletier/go-toml/v2"
	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/source"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

const ManifestFilename = "snailmail.toml"
const MinimumSigningRefreshSeconds = int64(7 * 24 * 60 * 60)

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var placementCoordinatePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

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
	if err := validateForgeIdentity(Workspace{
		Forge: options.Forge, ForgeRepository: options.ForgeRepository, ForgeHost: options.ForgeHost,
	}); err != nil {
		return err
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
		SchemaVersion: ManifestSchema, Workspace: Workspace{Name: options.Name, ID: workspaceID, Forge: options.Forge,
			ForgeRepository: options.ForgeRepository, ForgeHost: options.ForgeHost},
		BlobStore: BlobStoreConfig{Type: "local"}, Keys: map[string]SigningKey{}, Repositories: map[string]Repository{},
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
	if !formats.Supported(options.Format) {
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
	selectedFormat, err := formats.For(options.Format)
	if err != nil {
		return err
	}
	if selectedFormat.ImplementsSigning() && len(options.SigningKeys) == 0 && !options.AllowUnsigned {
		return fmt.Errorf("a new %s repository requires a signing key or explicit unsigned opt-out", options.Format)
	}
	if _, exists := manifest.Repositories[options.Name]; exists {
		return fmt.Errorf("repository %q already exists", options.Name)
	}
	lockPath := filepath.ToSlash(filepath.Join("repos", options.Name+".lock.toml"))
	repository := Repository{
		Format: options.Format, Lock: lockPath, Gate: gatePolicy, ApprovalKeys: append([]string(nil), options.ApprovalKeys...), SigningKeys: append([]string(nil), options.SigningKeys...), Visibility: visibility,
		Track: options.Track,
		Host: HostConfig{
			Type: hostType, Path: filepath.ToSlash(options.Output), Bucket: options.Bucket,
			Prefix: options.Prefix, Region: options.Region, Endpoint: options.Endpoint,
			CanonicalEndpoint: options.CanonicalEndpoint, UsePathStyle: options.UsePathStyle,
			ReadAuth: options.ReadAuth, CredentialBroker: options.CredentialBroker,
			Repository: options.Repository, Branch: options.Branch, PreviewRepository: options.PreviewRepository,
			PreviewBranch: options.PreviewBranch, PreviewEndpoint: options.PreviewEndpoint,
		},
	}
	if repository.Track == "" {
		repository.Track = "stable"
	}
	if hostType == "github-pages" {
		if repository.Host.Branch == "" {
			repository.Host.Branch = "gh-pages"
		}
		// Only when a preview repository was actually asked for: defaulting the
		// branch unconditionally would leave a half-configured preview behind.
		if repository.Host.PreviewRepository != "" && repository.Host.PreviewBranch == "" {
			repository.Host.PreviewBranch = "gh-pages"
		}
	}
	if err := checkPublicationTargets(manifest, options.Name, repository); err != nil {
		return err
	}
	if err := validateRepositoryHost(options.Name, repository); err != nil {
		return err
	}
	if err := validateGateConfiguration(options.Name, repository, manifest.Workspace.ForgeRepository); err != nil {
		return err
	}
	// An Alpine repository is partitioned by client architecture, and a client
	// fetches only its own index, so which architectures are served is part of
	// the configuration rather than something the packages imply.
	if options.Format == "apk" {
		repository.Architectures = append([]string(nil), options.Architectures...)
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
	// Every signing format publishes the set of keys a client should trust, so
	// the merged keyring is named here rather than per format. What a client
	// installs differs — apt takes the binary keyring, a yum client the armored
	// form — but which keys are in it does not.
	if len(repository.SigningKeys) == 1 {
		repository.SigningKeyring = filepath.ToSlash(filepath.Join("keys", options.Name+"-archive-keyring.gpg"))
	}
	if err := validateRepositorySigning(options.Name, repository, manifest.Keys); err != nil {
		return err
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
	if err := writeInstallDocument(root, options.Name, repository, manifest.Keys); err != nil {
		return err
	}
	return WriteManifest(root, manifest)
}

func writeInstallDocument(root, name string, repository Repository, keys map[string]SigningKey) error {
	if !host.Supports(repository.Host.Type, repository.Format).InstallDocument {
		return nil
	}
	content := installDocumentContent(name, repository, keys)
	filename, err := WorkspacePath(root, filepath.ToSlash(filepath.Join("docs", "install-"+name+".md")))
	if err != nil {
		return err
	}
	return atomicWrite(filename, content, 0o644)
}

func ValidateInstallDocument(root, name string, repository Repository, keys map[string]SigningKey) error {
	if !host.Supports(repository.Host.Type, repository.Format).InstallDocument {
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
	if !bytes.Equal(content, installDocumentContent(name, repository, keys)) {
		return fmt.Errorf("install document for repository %q does not match its canonical endpoint", name)
	}
	return nil
}

// installDocumentContent renders the consumer instructions for a repository.
// ARCHITECTURE §6.5 requires these to be generated rather than hand-written,
// so they cannot advertise a layout the repository does not serve.
// installDocumentContent writes the commands a consumer runs, for whichever
// format this repository serves.
//
// The steps come from formats.InstallSteps, which is what the browsable listing
// publishes too: two generators would drift, and this one had drifted already —
// every format but Debian was handed PyPI's `pip install --index-url`, including
// the rpm, apk and raw repositories the support matrix already declares.
func installDocumentContent(name string, repository Repository, keys map[string]SigningKey) []byte {
	if repository.Format == "deb" {
		// Debian keeps its own generator: a deb822 .sources stanza is a file to
		// write rather than commands to run, and it carries Signed-By.
		return debInstallDocument(name, repository)
	}
	steps := formats.InstallSteps(repository.Format, installRepositoryView(name, repository, keys))
	if len(steps) == 0 {
		return []byte("# Install from " + name + "\n\nThis repository publishes no install instructions.\n")
	}
	var document strings.Builder
	document.WriteString("# Install from " + name + "\n\n")
	if repository.Visibility == "private" {
		parsed, _ := url.Parse(repository.Host.CanonicalEndpoint)
		document.WriteString("Configure a short-lived Basic credential for `" + parsed.Hostname() +
			"` in your netrc before installing.\n\n")
	}
	document.WriteString("```sh\n")
	for _, step := range steps {
		document.WriteString(step + "\n")
	}
	document.WriteString("```\n")
	return []byte(document.String())
}

// installRepositoryView is what a format needs to write instructions against.
//
// The published key is not always the keyring the manifest records: a yum client
// imports an armored export of it, and an apk client holds a bare key under the
// filename its index names. The format is asked which, rather than this guessing.
func installRepositoryView(name string, repository Repository, keys map[string]SigningKey) formats.Repository {
	view := formats.Repository{
		Name: name, Suite: repository.Suite, Component: repository.Component,
		Architectures: repository.Architectures, Signed: len(repository.SigningKeys) != 0,
		Endpoint: repository.Host.CanonicalEndpoint,
	}
	if len(repository.SigningKeys) == 0 {
		return view
	}
	key := keys[repository.SigningKeys[0]]
	keyPath := repository.SigningKeyring
	if signing, err := formats.SignerFor(repository.Format); err == nil {
		keyPath = signing.ClientKeyPath(view, formats.SigningMaterial{
			KeyringPath: repository.SigningKeyring, PublicArmorPath: key.PublicArmorPath,
		})
	}
	view.Signing = &formats.RepositorySigning{
		Fingerprint: key.Fingerprint, Algorithm: key.Algorithm, KeyPath: keyPath,
	}
	return view
}

// debInstallDocument emits a deb822 .sources stanza. The keyring is fetched
// from the repository itself so the instructions carry no key material, and
// Signed-By names the exact keyring the repository publishes rather than
// installing a key into the system-wide trusted set, which would let this
// repository vouch for every other one.
func debInstallDocument(name string, repository Repository) []byte {
	endpoint := strings.TrimSuffix(repository.Host.CanonicalEndpoint, "/")
	keyring := "/usr/share/keyrings/" + name + "-archive-keyring.gpg"
	architectures := strings.Join(repository.Architectures, " ")

	var document strings.Builder
	document.WriteString("# Install from " + name + "\n\n")
	if len(repository.SigningKeys) == 0 {
		document.WriteString("This repository is unsigned. apt will refuse it unless the source is\n" +
			"marked trusted, which disables the integrity check the signature provides.\n\n")
		document.WriteString("```sh\nsudo tee /etc/apt/sources.list.d/" + name + ".sources >/dev/null <<'SOURCES'\n")
		document.WriteString("Types: deb\nURIs: " + endpoint + "\nSuites: " + repository.Suite +
			"\nComponents: " + repository.Component + "\nArchitectures: " + architectures + "\nTrusted: yes\nSOURCES\n")
		document.WriteString("sudo apt-get update\nsudo apt-get install PACKAGE\n```\n")
		return []byte(document.String())
	}
	document.WriteString("```sh\nsudo install -d -m 0755 /usr/share/keyrings\n")
	document.WriteString("sudo curl -fsSL -o " + shellQuote(keyring) + " " +
		shellQuote(endpoint+"/"+filepath.ToSlash(repository.SigningKeyring)) + "\n\n")
	document.WriteString("sudo tee /etc/apt/sources.list.d/" + name + ".sources >/dev/null <<'SOURCES'\n")
	document.WriteString("Types: deb\nURIs: " + endpoint + "\nSuites: " + repository.Suite +
		"\nComponents: " + repository.Component + "\nArchitectures: " + architectures +
		"\nSigned-By: " + keyring + "\nSOURCES\n")
	document.WriteString("sudo apt-get update\nsudo apt-get install PACKAGE\n```\n")
	return []byte(document.String())
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
		if header.SchemaVersion == 2 || header.SchemaVersion == 3 || header.SchemaVersion == 4 || header.SchemaVersion == 5 || header.SchemaVersion == 6 {
			manifest.SchemaVersion = ManifestSchema
			if header.SchemaVersion == 2 {
				manifest.Workspace.ID = legacyWorkspaceID(manifest.Workspace.Name)
				manifest.BlobStore = BlobStoreConfig{Type: "local"}
			}
			if header.SchemaVersion == 5 {
				for name, repository := range manifest.Repositories {
					if len(repository.SigningKeys) == 1 && repository.SigningKeyring == "" {
						repository.SigningKeyring = manifest.Keys[repository.SigningKeys[0]].PublicKeyPath
						manifest.Repositories[name] = repository
					}
				}
			}
		}
	}
	if header.SchemaVersion < ManifestSchema {
		for name, repository := range manifest.Repositories {
			if repository.Track == "" {
				repository.Track = "stable"
				manifest.Repositories[name] = repository
			}
		}
	}
	if manifest.SchemaVersion != ManifestSchema || !identifierPattern.MatchString(manifest.Workspace.Name) || !hexdigest.ValidSHA256(manifest.Workspace.ID) {
		return Manifest{}, errors.New("invalid workspace manifest schema or name")
	}
	if err := validateForgeIdentity(manifest.Workspace); err != nil {
		return Manifest{}, err
	}
	if err := ValidateBlobStore(manifest.BlobStore); err != nil {
		return Manifest{}, err
	}
	if manifest.Repositories == nil {
		manifest.Repositories = make(map[string]Repository)
	}
	if manifest.Keys == nil {
		manifest.Keys = make(map[string]SigningKey)
	}
	if err := validateSigningKeys(manifest); err != nil {
		return Manifest{}, err
	}
	for name, repository := range manifest.Repositories {
		if !identifierPattern.MatchString(name) {
			return Manifest{}, fmt.Errorf("invalid repository name %q", name)
		}
		if !formats.Supported(repository.Format) {
			return Manifest{}, fmt.Errorf("repository %q has unsupported format %q", name, repository.Format)
		}
		if !placementCoordinatePattern.MatchString(repository.Track) {
			return Manifest{}, fmt.Errorf("repository %q has invalid rendered track %q", name, repository.Track)
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
		if err := validateRepositorySigning(name, repository, manifest.Keys); err != nil {
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
		SchemaVersion: ManifestSchema, Workspace: workspace, BlobStore: BlobStoreConfig{Type: "local"}, Keys: map[string]SigningKey{},
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
		if repository.Host.Bucket != "" || repository.Host.Prefix != "" || repository.Host.Endpoint != "" || repository.Host.ReadAuth != "" || repository.Host.CredentialBroker != "" || repository.Host.Repository != "" || repository.Host.PreviewRepository != "" || repository.Host.PreviewEndpoint != "" || repository.Host.Branch != "" || repository.Host.PreviewBranch != "" {
			return fmt.Errorf("repository %q local host has S3-only configuration", name)
		}
		// A local repository is written to a directory that something else
		// serves, so snailmail cannot know its URL — but the operator does, and
		// without it the published listing has no install instructions to show
		// and clients get no address to point at. It is documentation only:
		// nothing publishes to it, so it is validated and otherwise unused.
		if repository.Host.CanonicalEndpoint != "" {
			if err := validateHTTPURL(repository.Host.CanonicalEndpoint); err != nil {
				return fmt.Errorf("repository %q base URL: %w", name, err)
			}
		}
	case "s3":
		if err := requireHostServesFormat(name, repository); err != nil {
			return err
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
		if err := requireHostServesFormat(name, repository); err != nil {
			return err
		}
		if repository.Visibility != "public" {
			return fmt.Errorf("repository %q: GitHub Pages currently supports public repositories only", name)
		}
		if repository.Host.Path != "" || repository.Host.Bucket != "" || repository.Host.Prefix != "" || repository.Host.Region != "" || repository.Host.Endpoint != "" || repository.Host.UsePathStyle || repository.Host.ReadAuth != "" || repository.Host.CredentialBroker != "" {
			return fmt.Errorf("repository %q GitHub Pages host has incompatible configuration", name)
		}
		if !validGitHubRepository(repository.Host.Repository) {
			return fmt.Errorf("repository %q GitHub Pages host requires an owner/name production repository", name)
		}
		if !validGitBranch(repository.Host.Branch) {
			return fmt.Errorf("repository %q GitHub Pages host has an invalid branch", name)
		}
		configuredPreview := repository.Host.PreviewRepository != "" || repository.Host.PreviewBranch != "" || repository.Host.PreviewEndpoint != ""
		// A preview is where a reviewer looks before production changes, so a
		// gate that waits for a human cannot do without one. An auto gate has no
		// reviewer, and the staged tree is still verified — locally rather than
		// over the network. See the apply path for what that costs.
		if !configuredPreview && repository.Gate != "auto" && repository.Gate != "" {
			return fmt.Errorf("repository %q gate %q reviews a preview, so a companion preview repository is required", name, repository.Gate)
		}
		endpoints := []struct{ label, endpoint string }{{"canonical", repository.Host.CanonicalEndpoint}}
		if configuredPreview {
			if !validGitHubRepository(repository.Host.PreviewRepository) || strings.EqualFold(repository.Host.Repository, repository.Host.PreviewRepository) {
				return fmt.Errorf("repository %q GitHub Pages host requires distinct production and preview owner/name repositories", name)
			}
			if sameConfiguredEndpoint(repository.Host.CanonicalEndpoint, repository.Host.PreviewEndpoint) {
				return fmt.Errorf("repository %q GitHub Pages production and preview endpoints must be distinct", name)
			}
			if !validGitBranch(repository.Host.PreviewBranch) {
				return fmt.Errorf("repository %q GitHub Pages host has an invalid branch", name)
			}
			endpoints = append(endpoints, struct{ label, endpoint string }{"preview", repository.Host.PreviewEndpoint})
		}
		for _, configured := range endpoints {
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

// requireHostServesFormat rejects a format the configured host cannot serve,
// naming what it does serve so the operator does not have to read the matrix.
func requireHostServesFormat(name string, repository Repository) error {
	if host.Supports(repository.Host.Type, repository.Format).Supported() {
		return nil
	}
	supported := host.SupportedFormats(repository.Host.Type)
	if len(supported) == 0 {
		return fmt.Errorf("repository %q: host %q serves no repository formats", name, repository.Host.Type)
	}
	return fmt.Errorf("repository %q: host %q does not serve format %q; it serves %s",
		name, repository.Host.Type, repository.Format, strings.Join(supported, ", "))
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

// validateForgeIdentity checks the provider, its repository reference and its
// host together, because they are only meaningful as a set: a reference is valid
// for a provider rather than in general, and a provider that exists only
// self-hosted needs a host to be reachable at all.
func validateForgeIdentity(workspace Workspace) error {
	provider := workspace.Forge
	if provider == "" {
		provider = forge.DefaultProvider
	}
	if !forge.KnownProvider(provider) {
		return fmt.Errorf("workspace forge %q is not one of %s", workspace.Forge,
			strings.Join(forge.Providers(), ", "))
	}
	if workspace.ForgeRepository != "" && !forge.ValidRepositoryReference(provider, workspace.ForgeRepository) {
		return fmt.Errorf("forge repository %q is not how %s addresses a repository",
			workspace.ForgeRepository, provider)
	}
	if workspace.ForgeHost != "" && !forge.ValidHost(workspace.ForgeHost) {
		return fmt.Errorf("forge host %q is not a hostname", workspace.ForgeHost)
	}
	// A provider with no hostname of its own exists only as an instance someone
	// runs, so there is nothing to fall back to. A plain remote is exempt: it is
	// never reached over an API, so it has no host to be reached at.
	if workspace.ForgeHost == "" && workspace.ForgeRepository != "" &&
		provider != forge.ProviderNone && forge.DefaultHost(provider) == "" {
		return fmt.Errorf("forge %q is self-hosted and needs forge_host", provider)
	}
	// A forge is named to be read. Naming one with no repository to read leaves a
	// PR gate configurable and unsatisfiable.
	if workspace.Forge != "" && workspace.Forge != forge.ProviderNone && workspace.ForgeRepository == "" {
		return fmt.Errorf("workspace forge %q has no forge_repository to read", workspace.Forge)
	}
	return nil
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

func validateSigningKeys(manifest Manifest) error {
	fingerprints := make(map[string]string)
	for name, key := range manifest.Keys {
		// An apk key publishes one file, under the name a client will hold it by
		// in /etc/apk/keys; an OpenPGP key publishes a binary keyring and an
		// armored form. The paths are checked against whichever the key is.
		binaryPath := filepath.ToSlash(filepath.Join("keys", name+".gpg"))
		armorPath := filepath.ToSlash(filepath.Join("keys", name+".asc"))
		if key.Algorithm == "apk-rsa4096" {
			binaryPath = filepath.ToSlash(filepath.Join("keys", name+".rsa.pub"))
			armorPath = binaryPath
		}
		if !identifierPattern.MatchString(name) || (key.Algorithm != "openpgp-rsa4096" && key.Algorithm != "apk-rsa4096") ||
			key.Usage != "sign" || !fingerprintPattern.MatchString(key.Fingerprint) ||
			!hexdigest.ValidSHA256(key.PublicKeySHA256) || !hexdigest.ValidSHA256(key.PublicArmorSHA256) || key.PublicKeyPath != binaryPath ||
			key.PublicArmorPath != armorPath || key.Ref.Backend != "file" || key.Ref.ID != manifest.Workspace.ID+"/"+name {
			return fmt.Errorf("signing key %q has invalid identity or public forms", name)
		}
		createdAt, createdErr := time.Parse(time.RFC3339, key.CreatedAt)
		expiresAt, expiresErr := time.Parse(time.RFC3339, key.ExpiresAt)
		if createdErr != nil || expiresErr != nil || !expiresAt.After(createdAt) {
			return fmt.Errorf("signing key %q has invalid validity", name)
		}
		if previous, exists := fingerprints[key.Fingerprint]; exists {
			return fmt.Errorf("signing keys %q and %q have the same fingerprint", previous, name)
		}
		fingerprints[key.Fingerprint] = name
	}
	return nil
}

func validateRepositorySigning(name string, repository Repository, keys map[string]SigningKey) error {
	if len(repository.SigningKeys) == 0 {
		if repository.SigningKeyring != "" || repository.SigningRotation != nil {
			return fmt.Errorf("repository %q has signing trust without an active key", name)
		}
		return nil
	}
	selected, err := formats.For(repository.Format)
	if err != nil {
		return fmt.Errorf("repository %q: %w", name, err)
	}
	if !selected.ImplementsSigning() {
		return fmt.Errorf("repository %q: snailmail does not produce repository signatures for format %q", name, repository.Format)
	}
	if len(repository.SigningKeys) != 1 {
		return fmt.Errorf("repository %q must have exactly one active signing key", name)
	}
	previous := ""
	for _, signingKey := range repository.SigningKeys {
		configured, exists := keys[signingKey]
		if !exists {
			return fmt.Errorf("repository %q references unknown signing key %q", name, signingKey)
		}
		if configured.Algorithm != selected.SigningAlgorithm() {
			return fmt.Errorf("repository %q is %s and its clients verify %s keys, but %q is %s",
				name, repository.Format, selected.SigningAlgorithm(), signingKey, configured.Algorithm)
		}
		if signingKey <= previous {
			return fmt.Errorf("repository %q signing keys must be unique and sorted", name)
		}
		previous = signingKey
	}
	if err := validateRelativePath(repository.SigningKeyring); err != nil || !strings.HasPrefix(repository.SigningKeyring, "keys/") || !strings.HasSuffix(repository.SigningKeyring, ".gpg") {
		return fmt.Errorf("repository %q has invalid signing keyring path", name)
	}
	if rotation := repository.SigningRotation; rotation != nil {
		if rotation.SuccessorKey == repository.SigningKeys[0] || (rotation.Phase != "introducing" && rotation.Phase != "activated") || rotation.MinimumRefreshSeconds < MinimumSigningRefreshSeconds {
			return fmt.Errorf("repository %q has invalid signing rotation", name)
		}
		if _, exists := keys[rotation.SuccessorKey]; !exists {
			return fmt.Errorf("repository %q rotation references unknown successor key %q", name, rotation.SuccessorKey)
		}
	}
	return nil
}

func LoadSigningPublic(root string, key SigningKey) ([]byte, []byte, error) {
	binary, err := loadSigningPublicFile(root, key.PublicKeyPath, key.PublicKeySHA256)
	if err != nil {
		return nil, nil, err
	}
	armored, err := loadSigningPublicFile(root, key.PublicArmorPath, key.PublicArmorSHA256)
	if err != nil {
		return nil, nil, err
	}
	return binary, armored, nil
}

func WriteSigningPublic(root string, key SigningKey, binary, armored []byte) error {
	forms := []struct {
		path, digest string
		content      []byte
	}{{key.PublicKeyPath, key.PublicKeySHA256, binary}, {key.PublicArmorPath, key.PublicArmorSHA256, armored}}
	// A key with one published form names it twice. Writing the second over the
	// first would look like an overwrite with different bytes, so the armored
	// form — the one a client installs — is the one kept.
	if key.PublicKeyPath == key.PublicArmorPath {
		forms = forms[1:]
	}
	for _, file := range forms {
		digest := sha256.Sum256(file.content)
		if hex.EncodeToString(digest[:]) != file.digest {
			return errors.New("public signing key bytes do not match configured digest")
		}
		name, err := WorkspacePath(root, file.path)
		if err != nil {
			return err
		}
		if existing, err := os.ReadFile(name); err == nil {
			if !bytes.Equal(existing, file.content) {
				return fmt.Errorf("refusing to overwrite public signing key %q", file.path)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := atomicWrite(name, file.content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func loadSigningPublicFile(root, relative, expectedSHA256 string) ([]byte, error) {
	name, err := WorkspacePath(root, relative)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("public signing key %q is not a bounded regular file", relative)
	}
	content, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, fmt.Errorf("public signing key %q differs from its manifest digest", relative)
	}
	return content, nil
}

func WriteManifest(root string, manifest Manifest) error {
	manifest.SchemaVersion = ManifestSchema
	if manifest.Workspace.ID == "" {
		manifest.Workspace.ID = legacyWorkspaceID(manifest.Workspace.Name)
	}
	if manifest.BlobStore.Type == "" {
		manifest.BlobStore.Type = "local"
	}
	if !identifierPattern.MatchString(manifest.Workspace.Name) || !hexdigest.ValidSHA256(manifest.Workspace.ID) {
		return errors.New("invalid workspace name or identity")
	}
	if err := validateForgeIdentity(manifest.Workspace); err != nil {
		return err
	}
	if err := ValidateBlobStore(manifest.BlobStore); err != nil {
		return err
	}
	if manifest.Keys == nil {
		manifest.Keys = make(map[string]SigningKey)
	}
	if err := validateSigningKeys(manifest); err != nil {
		return err
	}
	for name, repository := range manifest.Repositories {
		if !identifierPattern.MatchString(name) || !validGate(repository.Gate) || !placementCoordinatePattern.MatchString(repository.Track) {
			return fmt.Errorf("repository %q has invalid name or gate", name)
		}
		if err := validateRepositoryHost(name, repository); err != nil {
			return err
		}
		if err := validateGateConfiguration(name, repository, manifest.Workspace.ForgeRepository); err != nil {
			return err
		}
		if err := validateRepositorySigning(name, repository, manifest.Keys); err != nil {
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

func LoadLock(root string, repository Repository) (RepositoryLock, error) {
	var lock RepositoryLock
	name, err := WorkspacePath(root, repository.Lock)
	if err != nil {
		return RepositoryLock{}, err
	}
	// Before parsing, not after: reading an oversized lock to discover it is
	// oversized has already spent the memory the limit exists to protect.
	if info, statErr := os.Stat(name); statErr == nil {
		if err := requireLockWithinLimit(repository.Lock, info.Size()); err != nil {
			return RepositoryLock{}, err
		}
	}
	if err := decodeTOML(name, &lock); err != nil {
		return RepositoryLock{}, err
	}
	if lock.SchemaVersion == 1 {
		for _, packageVersion := range lock.PackageVersion {
			for _, locked := range packageVersion.Blobs {
				if locked.Origin != nil {
					return RepositoryLock{}, errors.New("lock schema 1 cannot contain artifact origins")
				}
			}
		}
		lock.SchemaVersion = LockSchema
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
	selectedFormat, err := formats.For(format)
	if err != nil {
		return false, err
	}
	if track == "" {
		track = "stable"
	}
	if err := validatePlacementCoordinates(format, track, distro); err != nil {
		return false, err
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
	blobExists := false
	for _, existing := range packageVersion.Blobs {
		if existing.SHA256 == blob.SHA256 && existing.Filename == blob.Filename {
			// A digest is compared only where both sides have one. A lock
			// written before these were computed by need records MD5 and SHA-1
			// for every format; an artifact re-added to such a lock now derives
			// neither, and an absent value is not a disagreement — it is a
			// question that was not asked. Treating it as one refused to
			// re-adopt anything already published.
			if existing.Size != blob.Size || legacyDigestConflict(existing, blob) || existing.Architecture != blob.Architecture {
				return false, fmt.Errorf("package %s@%s has inconsistent metadata for existing bytes", packageName, version)
			}
			blobExists = true
			break
		}
		existingCoordinate := selectedFormat.ArtifactCoordinate(formats.Artifact{
			Filename: existing.Filename, Architecture: existing.Architecture,
		})
		addedCoordinate := selectedFormat.ArtifactCoordinate(formats.Artifact{
			Filename: blob.Filename, Architecture: blob.Architecture,
		})
		if existing.Filename == blob.Filename || existingCoordinate == addedCoordinate {
			return false, fmt.Errorf("package %s@%s is already bound to different bytes", packageName, version)
		}
	}
	if !blobExists {
		packageVersion.Blobs = append(packageVersion.Blobs, blob)
	}
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
	// Canonical order is a property of the written file, and WriteLock
	// establishes it. Sorting here instead re-sorted the whole lock once per
	// added artifact, which made `snailmail add` quadratic in an existing lock.
	return !blobExists || !placementExists, nil
}

func SetBlobOrigin(lock *RepositoryLock, packageName, version, filename, digest string, origin ArtifactOrigin) (bool, error) {
	for packageIndex := range lock.PackageVersion {
		packageVersion := &lock.PackageVersion[packageIndex]
		if packageVersion.Package != packageName || packageVersion.Version != version {
			continue
		}
		for blobIndex := range packageVersion.Blobs {
			locked := &packageVersion.Blobs[blobIndex]
			if locked.Filename != filename || locked.SHA256 != digest {
				continue
			}
			if locked.Origin != nil {
				if *locked.Origin == origin {
					return false, nil
				}
				return false, errors.New("artifact already records a different origin")
			}
			locked.Origin = &origin
			return true, nil
		}
	}
	return false, errors.New("artifact is not recorded in the lock")
}

func PromotePlacement(lock *RepositoryLock, format, packageName, version, track, distro string) (bool, error) {
	if err := validatePlacementCoordinates(format, track, distro); err != nil {
		return false, err
	}
	if !packageVersionExists(*lock, packageName, version) {
		return false, fmt.Errorf("package version %s@%s is not recorded", packageName, version)
	}
	for _, placement := range lock.Placement {
		if placement.Package == packageName && placement.Version == version && placement.Track == track && placement.Distro == distro {
			return false, nil
		}
	}
	lock.Placement = append(lock.Placement, Placement{Package: packageName, Version: version, Track: track, Distro: distro})
	canonicalizeLock(lock)
	return true, nil
}

func YankPlacements(lock *RepositoryLock, format, packageName, version, track, distro string, all bool) (int, error) {
	if !packageVersionExists(*lock, packageName, version) {
		return 0, fmt.Errorf("package version %s@%s is not recorded", packageName, version)
	}
	if all {
		if track != "" || distro != "" {
			return 0, errors.New("all-placement yank cannot select a track or distro")
		}
	} else if err := validatePlacementCoordinates(format, track, distro); err != nil {
		return 0, err
	}
	kept := lock.Placement[:0]
	removed := 0
	for _, placement := range lock.Placement {
		matches := placement.Package == packageName && placement.Version == version
		if !all {
			matches = matches && placement.Track == track && placement.Distro == distro
		}
		if matches {
			removed++
			continue
		}
		kept = append(kept, placement)
	}
	lock.Placement = kept
	canonicalizeLock(lock)
	return removed, nil
}

func packageVersionExists(lock RepositoryLock, packageName, version string) bool {
	for _, packageVersion := range lock.PackageVersion {
		if packageVersion.Package == packageName && packageVersion.Version == version {
			return true
		}
	}
	return false
}

func validatePlacementCoordinates(format, track, distro string) error {
	if !placementCoordinatePattern.MatchString(track) {
		return fmt.Errorf("invalid placement track %q", track)
	}
	selected, err := formats.For(format)
	if err != nil {
		return err
	}
	if selected.SupportsDistros() {
		if !placementCoordinatePattern.MatchString(distro) {
			return fmt.Errorf("invalid Debian placement distro %q", distro)
		}
	} else if distro != "" {
		return fmt.Errorf("format %q does not support placement distros", format)
	}
	return nil
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
	selectedFormat, err := formats.For(format)
	if err != nil {
		return err
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
			if blob.Filename == "" || filepath.Base(blob.Filename) != blob.Filename || strings.IndexFunc(blob.Filename, unicode.IsControl) >= 0 || blob.Size < 0 {
				return fmt.Errorf("invalid locked blob filename or size")
			}
			decoded, err := hex.DecodeString(blob.SHA256)
			if err != nil || len(decoded) != sha256.Size || blob.SHA256 != strings.ToLower(blob.SHA256) {
				return fmt.Errorf("invalid locked blob SHA-256")
			}
			if blob.Origin != nil {
				if ValidateArtifactOrigin(*blob.Origin) != nil {
					return errors.New("invalid locked blob origin")
				}
			}
			coordinate := selectedFormat.ArtifactCoordinate(formats.Artifact{
				Filename: blob.Filename, Architecture: blob.Architecture,
			})
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

func ValidateArtifactOrigin(origin ArtifactOrigin) error {
	parsed, err := url.Parse(origin.URL)
	if origin.Kind != "https" || err != nil || source.ValidatePublicURL(parsed) != nil {
		return errors.New("invalid artifact origin")
	}
	return nil
}

// resolvedRoots caches the symlink resolution of a workspace root. A root
// cannot change while an operation holds the workspace lock, and resolving it
// is otherwise repeated for every path, including once per blob in a build.
var resolvedRoots struct {
	sync.Mutex
	byRoot map[string]string
}

// ResolveWorkspaceRoot returns the workspace root with symlinks resolved.
func ResolveWorkspaceRoot(root string) (string, error) {
	resolvedRoots.Lock()
	cached, found := resolvedRoots.byRoot[root]
	resolvedRoots.Unlock()
	if found {
		return cached, nil
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolvedRoots.Lock()
	if resolvedRoots.byRoot == nil {
		resolvedRoots.byRoot = make(map[string]string)
	}
	resolvedRoots.byRoot[root] = resolved
	resolvedRoots.Unlock()
	return resolved, nil
}

func WorkspacePath(root, relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	resolvedRoot, err := ResolveWorkspaceRoot(root)
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
	if hasIgnoreRule(content, ".snailmail/") {
		return nil
	}
	if len(content) != 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	content = append(content, []byte(block)...)
	return atomicWrite(name, content, 0o644)
}

// hasIgnoreRule reports whether rule is present as its own directive. A
// substring search also matched the rule inside a comment or, worse, inside a
// "!.snailmail/" negation that re-includes exactly what must stay ignored.
func hasIgnoreRule(content []byte, rule string) bool {
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == rule || line == "/"+rule {
			return true
		}
	}
	return false
}

// publicationTargets returns the places a repository writes to.
//
// A repository owns what it publishes: a local host replaces a managed release
// directory, and a Pages host force-updates a branch to an orphan commit of the
// whole tree. Two repositories aimed at one target therefore do not merge, they
// take turns destroying each other, and the loser looks published right up until
// someone fetches it.
func publicationTargets(repository Repository) []string {
	switch repository.Host.Type {
	case "s3":
		return []string{"s3 bucket " + repository.Host.Bucket + " under prefix /" + strings.Trim(repository.Host.Prefix, "/")}
	case "github-pages":
		targets := []string{"GitHub Pages branch " + repository.Host.Branch + " of " + repository.Host.Repository}
		if repository.Host.PreviewRepository != "" {
			targets = append(targets, "GitHub Pages branch "+repository.Host.PreviewBranch+" of "+repository.Host.PreviewRepository)
		}
		return targets
	default:
		return []string{"directory " + path.Clean(repository.Host.Path)}
	}
}

// checkPublicationTargets refuses a repository that would publish where another
// already does. Nested directories and prefixes count: publishing into a parent
// replaces everything below it.
func checkPublicationTargets(manifest Manifest, name string, candidate Repository) error {
	for _, existingName := range sortedRepositoryNames(manifest.Repositories) {
		if existingName == name {
			continue
		}
		existing := manifest.Repositories[existingName]
		for _, target := range publicationTargets(candidate) {
			for _, occupied := range publicationTargets(existing) {
				if !targetsOverlap(target, occupied) {
					continue
				}
				return fmt.Errorf("repository %q would publish to %s, which repository %q already owns",
					name, target, existingName)
			}
		}
	}
	return nil
}

// targetsOverlap reports whether writing to one target disturbs the other. Two
// targets of the same kind whose paths nest are an overlap, because a managed
// release replaces a whole directory rather than merging into it.
func targetsOverlap(left, right string) bool {
	if left == right {
		return true
	}
	return strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func sortedRepositoryNames(repositories map[string]Repository) []string {
	names := make([]string, 0, len(repositories))
	for name := range repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// legacyDigestConflict reports whether a recorded MD5 or SHA-1 contradicts a
// freshly derived one. Either being absent means there is nothing to contradict.
func legacyDigestConflict(existing, derived LockedBlob) bool {
	if existing.MD5 != "" && derived.MD5 != "" && existing.MD5 != derived.MD5 {
		return true
	}
	return existing.SHA1 != "" && derived.SHA1 != "" && existing.SHA1 != derived.SHA1
}
