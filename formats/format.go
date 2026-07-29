// Package formats is the boundary between the rest of snailmail and a
// packaging ecosystem's rules.
//
// A Format owns everything that differs between ecosystems: how bytes are
// inspected, how versions order, what makes two artifacts of one package
// version distinct, whether placements carry a distribution, whether the
// repository can be signed, and how an index is rendered. Code outside this
// package asks the registry for a Format rather than switching on a name, so
// adding an ecosystem is implementing this interface rather than editing
// engine, state and app.
//
// The interface is satisfied structurally, so no format subpackage imports
// this one and there is no dependency cycle.
package formats

import (
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"time"

	"github.com/shellcell/snailmail/formats/apk"
	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/formats/raw"
	"github.com/shellcell/snailmail/formats/rpm"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/signer"
)

// Identity is operator-supplied package identity, used only where an artifact
// carries none of its own. It is empty for every format that reads identity
// from bytes.
type Identity struct {
	Name    string
	Version string
}

// Supplied reports whether any identity was given.
func (identity Identity) Supplied() bool {
	return identity.Name != "" || identity.Version != ""
}

// IdentityFor returns the identity to hand a format when re-deriving facts for
// a package version already recorded in a lock.
//
// It is empty for formats that name themselves, which reject anything supplied.
// For the rest it replays what was reviewed, so validation checks that the
// bytes are unchanged rather than re-deciding an identity the operator already
// chose and committed.
func IdentityFor(selected Format, name, version string) Identity {
	if selected == nil || selected.DerivesIdentityFromBytes() {
		return Identity{}
	}
	return Identity{Name: name, Version: version}
}

// Artifact identifies one artifact within a package version, which is what a
// format needs to decide whether two artifacts collide.
type Artifact struct {
	Filename     string
	Architecture string
}

// Repository is the format-relevant part of a configured repository.
type Repository struct {
	Name          string
	Suite         string
	Component     string
	Architectures []string
	Signed        bool
	// Endpoint is the public URL a client fetches from, used to write install
	// instructions into the browsable listing. Empty for a repository published
	// to a directory, where no URL is known and instructions are omitted rather
	// than invented.
	Endpoint string
	// Signing describes what verifies the repository, for the listing to state.
	// It is known before the build because it comes from configuration; the
	// signature itself is applied afterwards.
	Signing *RepositorySigning
}

// RepositorySigning is the signing state a listing reports.
type RepositorySigning struct {
	Fingerprint string
	Algorithm   string
	// KeyPath is the file a client installs, relative to the repository root.
	KeyPath string
}

// BuildOptions carries every input an index render may need. A format uses
// only the fields its ecosystem has; PyPI has no suite, Helm has no
// architecture matrix. Making the set explicit is what keeps a build a pure
// function of declared inputs rather than of ambient state.
type BuildOptions struct {
	Repository  Repository
	GeneratedAt time.Time
}

// Format is a packaging ecosystem's rules as code.
type Format interface {
	// Name is the token used in manifests, locks and the CLI, such as "pypi".
	Name() string
	// ID is the versioned identity recorded in a generated repository
	// manifest, such as "pypi/v1". It changes when output would change.
	ID() string

	// MaxArtifactSize bounds a single artifact of this ecosystem.
	MaxArtifactSize() int64
	// IsArtifactFilename reports whether a filename is one this format serves.
	IsArtifactFilename(name string) bool
	// NormalizeName folds a package name to its canonical form. Formats
	// without a folding rule return the name unchanged.
	NormalizeName(name string) string
	// DerivesIdentityFromBytes reports whether the artifact names itself.
	// Where it does, supplied identity is refused, so a caller can never
	// relabel a wheel or a .deb into something a client would not agree with.
	DerivesIdentityFromBytes() bool
	// Inspect derives package facts from the artifact.
	//
	// Supplied identity is a last resort for formats whose artifacts carry no
	// metadata. A format that reads identity out of the bytes must reject it:
	// letting a caller relabel a wheel or a .deb would make the lock disagree
	// with what any client sees, and it is the one thing this boundary exists
	// to prevent.
	Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error)
	// CompareVersions orders two native version strings.
	CompareVersions(left, right string) (int, error)
	// RequiresLegacyDigests reports whether this format's index publishes MD5
	// and SHA-1 beside SHA-256.
	//
	// apt reads MD5sum and SHA1 out of a Packages file, so a Debian repository
	// has to carry them. No other format here does, and computing them anyway
	// costs about five times what SHA-256 alone does over the same bytes —
	// which is paid on every plan and every apply, for every artifact.
	RequiresLegacyDigests() bool

	// ArtifactCoordinate is the key that must be unique among the artifacts of
	// one package version: a Debian package version holds one artifact per
	// architecture, a Helm chart version holds exactly one, and a PyPI release
	// holds one per distribution filename.
	ArtifactCoordinate(artifact Artifact) string
	// SupportsDistros reports whether placements in this format carry a
	// distribution coordinate.
	SupportsDistros() bool
	// SigningAlgorithm is the kind of key this format's clients can verify, or
	// empty where the format is not signed. A client that trusts one kind of key
	// cannot check a signature made with another, so this is not a preference:
	// attaching the wrong kind produces a repository nothing can read.
	SigningAlgorithm() string
	// ImplementsSigning reports whether snailmail can produce repository
	// signatures for this format. This is narrower than what the ecosystem
	// permits: the knowledge bundle records that Helm defines .prov signing,
	// while this implementation does not yet produce it.
	ImplementsSigning() bool
	// CommitPaths are the files whose switch makes a new revision live, which
	// a host must publish last and together.
	CommitPaths(repository Repository) []string

	// Build renders a deterministic file tree from the given artifacts.
	Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error)
}

var registry = map[string]Format{
	"pypi": pypiFormat{},
	"deb":  debFormat{},
	"helm": helmFormat{},
	"raw":  rawFormat{},
	"rpm":  rpmFormat{},
	"apk":  apkFormat{},
}

// For returns the format registered under name.
func For(name string) (Format, error) {
	format, known := registry[name]
	if !known {
		return nil, fmt.Errorf("unsupported repository format %q", name)
	}
	return format, nil
}

// Supported reports whether a format name is registered.
func Supported(name string) bool {
	_, known := registry[name]
	return known
}

// Names lists every registered format in a stable order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns every registered format in the order Names reports.
func All() []Format {
	all := make([]Format, 0, len(registry))
	for _, name := range Names() {
		all = append(all, registry[name])
	}
	return all
}

type pypiFormat struct{}

func (pypiFormat) Name() string                     { return "pypi" }
func (pypiFormat) ID() string                       { return pypi.FormatID }
func (pypiFormat) MaxArtifactSize() int64           { return pypi.MaxArtifactSize }
func (pypiFormat) IsArtifactFilename(n string) bool { return pypi.IsDistributionFilename(n) }
func (pypiFormat) NormalizeName(n string) string    { return pypi.NormalizeName(n) }
func (pypiFormat) CompareVersions(l, r string) (int, error) {
	return pypi.CompareVersions(l, r)
}
func (pypiFormat) DerivesIdentityFromBytes() bool { return true }
func (pypiFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if supplied.Supplied() {
		return domain.PackageFacts{}, errors.New("PyPI identity comes from wheel or source-distribution metadata and cannot be supplied")
	}
	return pypi.Inspect(filename, reader, size)
}

// A PyPI release holds one artifact per distribution filename: an sdist and
// any number of wheels differing by platform tag.
func (pypiFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Filename }
func (pypiFormat) SupportsDistros() bool                       { return false }

// PyPI dropped GPG signatures in 2023, so there is no repository signature to
// carry.
// PyPI dropped repository signing in 2023.
func (pypiFormat) RequiresLegacyDigests() bool { return false }

func (pypiFormat) SigningAlgorithm() string { return "" }

func (pypiFormat) ImplementsSigning() bool         { return false }
func (pypiFormat) CommitPaths(Repository) []string { return []string{"simple/index.html"} }
func (pypiFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := pypi.Build(blobs)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "pypi", options, blobs)
}

type debFormat struct{}

func (debFormat) Name() string                     { return "deb" }
func (debFormat) ID() string                       { return deb.FormatID }
func (debFormat) MaxArtifactSize() int64           { return deb.MaxArtifactSize }
func (debFormat) IsArtifactFilename(n string) bool { return deb.IsPackageFilename(n) }

// Debian package names are already canonical; there is no folding rule.
func (debFormat) NormalizeName(n string) string { return n }
func (debFormat) CompareVersions(l, r string) (int, error) {
	return deb.CompareVersions(l, r)
}
func (debFormat) DerivesIdentityFromBytes() bool { return true }
func (debFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if supplied.Supplied() {
		return domain.PackageFacts{}, errors.New("Debian identity comes from its control file and cannot be supplied")
	}
	return deb.Inspect(filename, reader, size)
}

// A Debian package version holds one artifact per architecture.
func (debFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Architecture }
func (debFormat) SupportsDistros() bool                       { return true }

// apt verifies OpenPGP over the Release document.
// apt reads MD5sum and SHA1 from a Packages file, so a Debian repository is
// the one place these still have to be computed.
func (debFormat) RequiresLegacyDigests() bool { return true }

func (debFormat) SigningAlgorithm() string { return signer.AlgorithmOpenPGPRSA4096 }

func (debFormat) ImplementsSigning() bool { return true }

// A signed suite additionally switches InRelease and Release.gpg, which must
// become live together with the Release they authenticate.
func (debFormat) CommitPaths(repository Repository) []string {
	// path.Join also cleans, which is what kept a surprising suite from
	// producing a traversing commit path.
	release := path.Join("dists", repository.Suite, "Release")
	if repository.Signed {
		return []string{
			path.Join("dists", repository.Suite, "InRelease"),
			release,
			path.Join("dists", repository.Suite, "Release.gpg"),
		}
	}
	return []string{release}
}

func (debFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := deb.Build(blobs, deb.BuildOptions{
		Suite:         options.Repository.Suite,
		Component:     options.Repository.Component,
		Architectures: options.Repository.Architectures,
		GeneratedAt:   options.GeneratedAt,
	})
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "deb", options, blobs)
}

type helmFormat struct{}

func (helmFormat) Name() string                     { return "helm" }
func (helmFormat) ID() string                       { return helm.FormatID }
func (helmFormat) MaxArtifactSize() int64           { return helm.MaxArtifactSize }
func (helmFormat) IsArtifactFilename(n string) bool { return helm.IsChartFilename(n) }
func (helmFormat) NormalizeName(n string) string    { return n }
func (helmFormat) CompareVersions(l, r string) (int, error) {
	return helm.CompareVersions(l, r)
}
func (helmFormat) DerivesIdentityFromBytes() bool { return true }
func (helmFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if supplied.Supplied() {
		return domain.PackageFacts{}, errors.New("Helm identity comes from its Chart.yaml and cannot be supplied")
	}
	return helm.Inspect(filename, reader, size)
}

// A chart version is exactly one archive, so every artifact of a version
// collides with every other.
func (helmFormat) ArtifactCoordinate(Artifact) string { return "chart" }
func (helmFormat) SupportsDistros() bool              { return false }

// Helm signs with a per-chart .prov file, which is not yet implemented.
// Helm defines .prov signing, which is not produced here.
func (helmFormat) RequiresLegacyDigests() bool { return false }

func (helmFormat) SigningAlgorithm() string { return signer.AlgorithmOpenPGPRSA4096 }

func (helmFormat) ImplementsSigning() bool { return true }

// A Helm signature is a provenance file beside the chart it covers, at a
// content-addressed path nothing else ever writes. Only index.yaml is replaced
// on a publication, so it remains the one path whose switch has to be atomic.
func (helmFormat) CommitPaths(Repository) []string { return []string{"index.yaml"} }
func (helmFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := helm.Build(blobs, helm.BuildOptions{GeneratedAt: options.GeneratedAt})
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "helm", options, blobs)
}

// Compile-time proof that every registered value satisfies the interface.
var (
	_ Format = rawFormat{}
	_ Format = rpmFormat{}
	_ Format = apkFormat{}
	_ Format = pypiFormat{}
	_ Format = debFormat{}
	_ Format = helmFormat{}
)

// rawFormat serves artifacts with no ecosystem metadata: release tarballs,
// static binaries, installers.
type rawFormat struct{}

func (rawFormat) Name() string                     { return "raw" }
func (rawFormat) ID() string                       { return raw.FormatID }
func (rawFormat) MaxArtifactSize() int64           { return raw.MaxArtifactSize }
func (rawFormat) IsArtifactFilename(n string) bool { return raw.IsArtifactFilename(n) }

// Raw names are already the operator's chosen identity; there is no ecosystem
// folding rule to apply.
func (rawFormat) NormalizeName(n string) string { return n }
func (rawFormat) CompareVersions(l, r string) (int, error) {
	return raw.CompareVersions(l, r)
}

// Raw artifacts carry no metadata, so identity comes from the filename
// convention or from the operator.
func (rawFormat) DerivesIdentityFromBytes() bool { return false }
func (rawFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	return raw.Inspect(filename, reader, size, raw.Identity{Name: supplied.Name, Version: supplied.Version})
}

// A raw version holds one artifact per filename, so a release can carry a
// binary per platform alongside its checksums.
func (rawFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Filename }
func (rawFormat) SupportsDistros() bool                       { return false }

// Detached signatures over the listing are the documented raw scheme; they are
// not implemented yet.
// Loose files are not an ecosystem and define no signing.
func (rawFormat) RequiresLegacyDigests() bool { return false }

func (rawFormat) SigningAlgorithm() string { return "" }

func (rawFormat) ImplementsSigning() bool         { return false }
func (rawFormat) CommitPaths(Repository) []string { return []string{"index.html", "SHA256SUMS"} }
func (rawFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := raw.Build(blobs, raw.BuildOptions{GeneratedAt: options.GeneratedAt})
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "raw", options, blobs)
}

// rpmFormat serves RPM packages through a yum/dnf repository.
type rpmFormat struct{}

func (rpmFormat) Name() string                     { return "rpm" }
func (rpmFormat) ID() string                       { return rpm.FormatID }
func (rpmFormat) MaxArtifactSize() int64           { return rpm.MaxArtifactSize }
func (rpmFormat) IsArtifactFilename(n string) bool { return rpm.IsArtifactFilename(n) }

// RPM names are case-sensitive and used verbatim by every client.
func (rpmFormat) NormalizeName(n string) string { return n }
func (rpmFormat) CompareVersions(l, r string) (int, error) {
	return rpm.CompareVersions(l, r)
}

// An RPM names itself in its header; the filename is only a convention.
func (rpmFormat) DerivesIdentityFromBytes() bool { return true }
func (rpmFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if supplied.Supplied() {
		return domain.PackageFacts{}, errors.New("RPM identity comes from the package header and cannot be supplied")
	}
	return rpm.Inspect(filename, reader, size)
}

// One RPM version holds one package per architecture, the same shape Debian has.
func (rpmFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Architecture }

// A yum repository is addressed by its own URL rather than by a distribution
// coordinate inside it, so releases do not carry one.
func (rpmFormat) SupportsDistros() bool { return false }

// Detached OpenPGP over repomd.xml is what repo_gpgcheck verifies, and it is
// produced. Per-package signing is not: that signature lives in the package
// header and is made by whoever built the package, not by the repository.
// repo_gpgcheck verifies OpenPGP over repomd.xml.
func (rpmFormat) RequiresLegacyDigests() bool { return false }

func (rpmFormat) SigningAlgorithm() string { return signer.AlgorithmOpenPGPRSA4096 }

func (rpmFormat) ImplementsSigning() bool         { return true }
func (rpmFormat) CommitPaths(Repository) []string { return []string{"repodata/repomd.xml"} }
func (rpmFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := rpm.Build(blobs, rpm.BuildOptions{GeneratedAt: options.GeneratedAt})
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "rpm", options, blobs)
}

// apkFormat serves Alpine packages through an APKINDEX repository.
type apkFormat struct{}

func (apkFormat) Name() string                     { return "apk" }
func (apkFormat) ID() string                       { return apk.FormatID }
func (apkFormat) MaxArtifactSize() int64           { return apk.MaxArtifactSize }
func (apkFormat) IsArtifactFilename(n string) bool { return apk.IsArtifactFilename(n) }

// Alpine package names are used verbatim by apk.
func (apkFormat) NormalizeName(n string) string { return n }
func (apkFormat) CompareVersions(l, r string) (int, error) {
	return apk.CompareVersions(l, r)
}

// An .apk names itself in .PKGINFO; the filename is only a convention.
func (apkFormat) DerivesIdentityFromBytes() bool { return true }
func (apkFormat) Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if supplied.Supplied() {
		return domain.PackageFacts{}, errors.New("Alpine identity comes from .PKGINFO and cannot be supplied")
	}
	return apk.Inspect(filename, reader, size)
}

// One Alpine version holds one package per architecture.
func (apkFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Architecture }

// An Alpine repository is addressed by its own URL, and the architecture
// directory is part of that URL rather than a coordinate inside the index.
func (apkFormat) SupportsDistros() bool { return false }

// apk signs an index by prepending a signature stream to it, with the signing
// key's filename identifying which key to check. That is not produced yet.
// apk verifies a bare RSA signature against a key held by filename.
func (apkFormat) RequiresLegacyDigests() bool { return false }

func (apkFormat) SigningAlgorithm() string { return signer.AlgorithmAPKRSA4096 }

func (apkFormat) ImplementsSigning() bool { return true }
func (apkFormat) CommitPaths(repository Repository) []string {
	paths := make([]string, 0, len(repository.Architectures))
	for _, architecture := range repository.Architectures {
		paths = append(paths, path.Join(architecture, apk.IndexFilename))
	}
	return paths
}
func (apkFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	artifact, err := apk.Build(blobs, apk.BuildOptions{
		GeneratedAt: options.GeneratedAt, Architectures: options.Repository.Architectures,
	})
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return AppendListing(artifact, "apk", options, blobs)
}
