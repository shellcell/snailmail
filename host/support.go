package host

import "sort"

// The format-by-host support matrix.
//
// PLAN.md §15 names scope explosion as the first risk: formats times hosts
// times gates is a matrix nobody can test, and tiering is the defence. That
// defence only works if the sparseness is declared in one place. Scattering it
// across configuration validators and apply-time branches is how a pair becomes
// unsupported in one check and half-supported in another, and how adding a
// format means editing a host's code.
//
// Declaring it here also moves the failure earlier: an unsupported pair is
// rejected when a repository is configured rather than midway through an apply
// that has already staged bytes.

// FormatSupport is what one host type can do with one repository format.
type FormatSupport struct {
	// Publish reports whether the host can serve this format's tree at all.
	Publish bool
	// RemoteClientVerification reports whether the endpoint-served client probe
	// — staged preview and canonical — is implemented for this pair. A local
	// host verifies its own directory instead and does not use this.
	RemoteClientVerification bool
	// InstallDocument reports whether a consumer instruction document is
	// generated and digest-bound for this pair. It needs a stable public
	// endpoint, so it accompanies remote hosting rather than a local directory.
	InstallDocument bool
}

// Supported reports whether the host can publish the format at all.
func (support FormatSupport) Supported() bool { return support.Publish }

var formatSupport = map[string]map[string]FormatSupport{
	// A local directory is the format-neutral case: it serves any tree the
	// build produces, and verification runs against the directory rather than
	// an endpoint.
	"local": {
		"pypi": {Publish: true},
		"deb":  {Publish: true},
		"helm": {Publish: true},
		"raw":  {Publish: true},
		"rpm":  {Publish: true},
		"apk":  {Publish: true},
	},
	// The first remote slice is PyPI. Extending a host to another format means
	// its commit paths, install document, and endpoint client probe, so the two
	// flags move together per pair rather than per host.
	"s3": {
		"pypi": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
	},
	// Pages commits by moving a publish ref to an orphan commit of the whole
	// tree, which is atomic and format-neutral, so a suite's Release and its
	// Packages and pool become live together. That is what Debian needs and
	// what an object store cannot offer without an ordered multi-object commit.
	"github-pages": {
		"pypi": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
		"deb":  {Publish: true, RemoteClientVerification: true, InstallDocument: true},
		// A chart repository switches one file, index.yaml; a provenance file
		// sits at a content-addressed path nothing ever replaces. So the atomic
		// commit Pages offers is more than Helm needs.
		"helm": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
		// Raw has no client to run: a consumer fetches a URL and checks it
		// against SHA256SUMS, which host-served byte verification already does.
		"raw": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
		"rpm": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
		"apk": {Publish: true, RemoteClientVerification: true, InstallDocument: true},
	},
}

// Supports reports what hostType can do with format. An unknown host type or
// format supports nothing, so a new one is unsupported until declared rather
// than accidentally permitted.
func Supports(hostType, format string) FormatSupport {
	return formatSupport[hostType][format]
}

// SupportedFormats lists the formats a host type can publish, in a stable
// order, for error messages that tell an operator what would work.
func SupportedFormats(hostType string) []string {
	byFormat := formatSupport[hostType]
	formats := make([]string, 0, len(byFormat))
	for format, support := range byFormat {
		if support.Publish {
			formats = append(formats, format)
		}
	}
	sort.Strings(formats)
	return formats
}

// KnownHostTypes lists every host type the matrix declares.
func KnownHostTypes() []string {
	types := make([]string, 0, len(formatSupport))
	for hostType := range formatSupport {
		types = append(types, hostType)
	}
	sort.Strings(types)
	return types
}
