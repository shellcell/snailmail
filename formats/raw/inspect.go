// Package raw serves artifacts that carry no ecosystem metadata of their own:
// release tarballs, static binaries, checksums, installers.
//
// Every other format derives identity from inside the artifact and treats the
// filename as a claim to cross-check. Raw bytes say nothing, so identity comes
// from the filename by convention, or from the operator when the convention
// does not apply. That is a real weakening, and it is why the published layout
// puts identity in the path: once an artifact is in the tree, its identity is
// recomputed from where it sits rather than from a name that may have been
// overridden at ingest.
package raw

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "raw/v1"

// MaxArtifactSize bounds one artifact. Raw carries installers and disk images,
// so the limit is higher than a package format needs, but still bounded.
const MaxArtifactSize = 2 << 30

// namePattern and versionPattern keep a parsed identity usable as a path
// segment and as a listing entry.
var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~-]{0,127}$`)
	// knownArchitectures recognises the trailing platform fields that release
	// tooling emits, so they are not mistaken for part of the version.
	knownOperatingSystems = map[string]bool{
		"linux": true, "darwin": true, "windows": true, "freebsd": true,
		"openbsd": true, "netbsd": true, "solaris": true, "aix": true, "js": true,
	}
	knownArchitectures = map[string]bool{
		"amd64": true, "arm64": true, "386": true, "arm": true, "armv6": true,
		"armv7": true, "ppc64": true, "ppc64le": true, "s390x": true,
		"mips": true, "mipsle": true, "mips64": true, "mips64le": true,
		"riscv64": true, "loong64": true, "wasm": true, "universal": true,
		"x86_64": true, "aarch64": true, "i386": true,
	}
)

// Identity is operator-supplied package identity. Formats that read identity
// from the artifact reject it; raw uses it when the filename cannot supply one.
type Identity struct {
	Name    string
	Version string
}

// IsArtifactFilename accepts any filename that is safe to publish. Raw does not
// restrict extensions, because restricting them is the job it exists to avoid.
func IsArtifactFilename(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return false
	}
	// Reserved by the generated tree.
	return name != "SHA256SUMS" && name != "index.html"
}

// Inspect derives identity from the filename convention, or accepts identity
// the operator supplied when the convention does not parse.
//
// The reader is required and read in full so the artifact's size is confirmed
// against what the caller declared: raw performs no structural parse, so this
// is the only check that the bytes are the bytes.
func Inspect(filename string, reader io.ReaderAt, size int64, supplied Identity) (domain.PackageFacts, error) {
	if !IsArtifactFilename(filename) {
		return domain.PackageFacts{}, fmt.Errorf("raw artifact filename %q is unusable", filename)
	}
	if size < 0 || size > MaxArtifactSize {
		return domain.PackageFacts{}, errors.New("raw artifact exceeds the format size limit")
	}
	if reader == nil {
		return domain.PackageFacts{}, errors.New("raw artifact bytes are required")
	}
	// A section reader stops at the underlying EOF without reporting one, so the
	// count is what catches an artifact shorter than its declared size.
	read, err := io.Copy(io.Discard, io.NewSectionReader(reader, 0, size))
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("read raw artifact: %w", err)
	}
	if read != size {
		return domain.PackageFacts{}, fmt.Errorf("raw artifact %q is %d bytes, not the declared %d", filename, read, size)
	}

	name, version, architecture := parseFilename(filename)
	if supplied.Name != "" {
		name = supplied.Name
	}
	if supplied.Version != "" {
		version = supplied.Version
	}
	if name == "" || version == "" {
		return domain.PackageFacts{}, fmt.Errorf(
			"raw artifact %q does not follow <name>_<version>_<os>_<arch>.<ext>; supply --name and --version", filename)
	}
	if !namePattern.MatchString(name) {
		return domain.PackageFacts{}, fmt.Errorf("raw package name %q is unusable as a path segment", name)
	}
	if !versionPattern.MatchString(version) {
		return domain.PackageFacts{}, fmt.Errorf("raw version %q must begin with a digit and be usable as a path segment", version)
	}
	return domain.PackageFacts{Name: name, Version: version, Architecture: architecture}, nil
}

// FactsFor builds facts for an artifact whose identity is already known, such
// as one read back from a published tree where the path records it. There are
// no bytes to consult: raw identity never came from them.
func FactsFor(name, version, filename string) (domain.PackageFacts, error) {
	if !IsArtifactFilename(filename) {
		return domain.PackageFacts{}, fmt.Errorf("raw artifact filename %q is unusable", filename)
	}
	if !namePattern.MatchString(name) {
		return domain.PackageFacts{}, fmt.Errorf("raw package name %q is unusable as a path segment", name)
	}
	if !versionPattern.MatchString(version) {
		return domain.PackageFacts{}, fmt.Errorf("raw version %q is unusable as a path segment", version)
	}
	_, _, architecture := parseFilename(filename)
	return domain.PackageFacts{Name: name, Version: version, Architecture: architecture}, nil
}

// parseFilename reads <name>_<version>[_<os>][_<arch>].<ext>. Anything it
// cannot split confidently returns empty, so the operator is asked rather than
// guessed at.
func parseFilename(filename string) (name, version, architecture string) {
	stem := strings.TrimSuffix(filename, compoundExtension(filename))
	// Trailing platform fields are stripped as whole tokens rather than by
	// splitting first, because an architecture may itself contain an underscore
	// — x86_64 would otherwise be read as the two fields "x86" and "64".
	for {
		token, remainder, ok := trailingToken(stem)
		if !ok {
			break
		}
		lowered := strings.ToLower(token)
		if knownArchitectures[lowered] {
			if architecture == "" {
				architecture = lowered
			}
			stem = remainder
			continue
		}
		if knownOperatingSystems[lowered] {
			stem = remainder
			continue
		}
		break
	}
	fields := strings.Split(stem, "_")
	if len(fields) != 2 {
		// A name containing underscores is indistinguishable from extra fields,
		// so the operator decides rather than the parser.
		return "", "", ""
	}
	name, version = fields[0], fields[1]
	if !namePattern.MatchString(name) || !versionPattern.MatchString(version) {
		return "", "", ""
	}
	return name, version, architecture
}

// trailingToken splits the longest recognised platform token off the end,
// preferring a two-part token such as x86_64 over its final segment.
func trailingToken(stem string) (token, remainder string, ok bool) {
	fields := strings.Split(stem, "_")
	if len(fields) < 3 {
		return "", "", false
	}
	if len(fields) >= 4 {
		joined := strings.ToLower(fields[len(fields)-2] + "_" + fields[len(fields)-1])
		if knownArchitectures[joined] || knownOperatingSystems[joined] {
			return joined, strings.Join(fields[:len(fields)-2], "_"), true
		}
	}
	return fields[len(fields)-1], strings.Join(fields[:len(fields)-1], "_"), true
}

// compoundExtension returns the extension to strip, keeping two-part archive
// suffixes together so a version is never truncated at the wrong dot.
func compoundExtension(filename string) string {
	lower := strings.ToLower(filename)
	for _, suffix := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"} {
		if strings.HasSuffix(lower, suffix) {
			return filename[len(filename)-len(suffix):]
		}
	}
	if index := strings.LastIndex(filename, "."); index > 0 {
		return filename[index:]
	}
	return ""
}
