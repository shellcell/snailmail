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
	"fmt"
	"io"
	"path"
	"sort"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/domain"
)

// Artifact identifies one artifact within a package version, which is what a
// format needs to decide whether two artifacts collide.
type Artifact struct {
	Filename     string
	Architecture string
}

// Repository is the format-relevant part of a configured repository.
type Repository struct {
	Suite         string
	Component     string
	Architectures []string
	Signed        bool
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
	// Inspect derives package facts from the artifact bytes themselves.
	Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error)
	// CompareVersions orders two native version strings.
	CompareVersions(left, right string) (int, error)

	// ArtifactCoordinate is the key that must be unique among the artifacts of
	// one package version: a Debian package version holds one artifact per
	// architecture, a Helm chart version holds exactly one, and a PyPI release
	// holds one per distribution filename.
	ArtifactCoordinate(artifact Artifact) string
	// SupportsDistros reports whether placements in this format carry a
	// distribution coordinate.
	SupportsDistros() bool
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
func (pypiFormat) Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	return pypi.Inspect(filename, reader, size)
}

// A PyPI release holds one artifact per distribution filename: an sdist and
// any number of wheels differing by platform tag.
func (pypiFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Filename }
func (pypiFormat) SupportsDistros() bool                       { return false }

// PyPI dropped GPG signatures in 2023, so there is no repository signature to
// carry.
func (pypiFormat) ImplementsSigning() bool         { return false }
func (pypiFormat) CommitPaths(Repository) []string { return []string{"simple/index.html"} }
func (pypiFormat) Build(blobs []domain.Blob, _ BuildOptions) (domain.RepositoryArtifact, error) {
	return pypi.Build(blobs)
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
func (debFormat) Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	return deb.Inspect(filename, reader, size)
}

// A Debian package version holds one artifact per architecture.
func (debFormat) ArtifactCoordinate(artifact Artifact) string { return artifact.Architecture }
func (debFormat) SupportsDistros() bool                       { return true }
func (debFormat) ImplementsSigning() bool                     { return true }

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
	return deb.Build(blobs, deb.BuildOptions{
		Suite:         options.Repository.Suite,
		Component:     options.Repository.Component,
		Architectures: options.Repository.Architectures,
		GeneratedAt:   options.GeneratedAt,
	})
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
func (helmFormat) Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	return helm.Inspect(filename, reader, size)
}

// A chart version is exactly one archive, so every artifact of a version
// collides with every other.
func (helmFormat) ArtifactCoordinate(Artifact) string { return "chart" }
func (helmFormat) SupportsDistros() bool              { return false }

// Helm signs with a per-chart .prov file, which is not yet implemented.
func (helmFormat) ImplementsSigning() bool         { return false }
func (helmFormat) CommitPaths(Repository) []string { return []string{"index.yaml"} }
func (helmFormat) Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	return helm.Build(blobs, helm.BuildOptions{GeneratedAt: options.GeneratedAt})
}

// Compile-time proof that every registered value satisfies the interface.
var (
	_ Format = pypiFormat{}
	_ Format = debFormat{}
	_ Format = helmFormat{}
)
