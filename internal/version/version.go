// Package version reports what a snailmail binary is.
//
// The release version comes from the Git tag the binary was built from, stamped
// in at link time. Nothing is committed to a source file, so a release is
// created by tagging rather than by editing code and remembering to tag.
//
// A tag and a package version are deliberately separate strings. Tags are
// conventionally v-prefixed; a published package version must begin with a
// digit. Conflating them would fail at publish time rather than here, so the
// v-stripped form is what Version carries and what callers publish.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// stamped is set at link time:
//
//	STAMP=$(git describe --tags --dirty 2>/dev/null || true)
//	go build -ldflags "-X github.com/shellcell/snailmail/internal/version.stamped=$STAMP"
//
// It is empty for an ordinary `go build`, and empty when no tag is reachable,
// which falls back to the VCS information the Go toolchain embeds on its own.
//
// Do not add --always. It makes describe emit a bare commit hash when no tag is
// reachable, and a hash beginning with a digit is shaped exactly like a version;
// stamping one would publish a commit hash as a release. hashLike guards against
// it, but the guard cannot be exact, so the command is the real fix.
var stamped string

// releaseTag is a tag that names a release: a leading digit, then the
// characters a package version may contain. It matches what the raw format
// accepts as a version, which is asserted by test rather than assumed.
var releaseTag = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~-]{0,127}$`)

// snapshot matches what `git describe` appends past an exact tag: the number of
// commits and the abbreviated hash. Its presence means the build is not a
// release even though a tag is reachable from it.
var snapshot = regexp.MustCompile(`-[0-9]+-g[0-9a-f]{7,}$`)

// hashLike matches an abbreviated commit hash: only hex digits, no separator,
// and at least as long as Git abbreviates to. A release tag reaches this code
// only if someone stamped `describe --always` output, and rejecting it costs a
// separator-free all-hex tag such as "20240115" — which a date-based scheme
// should write as "2024.01.15" anyway.
var hashLike = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// pseudoVersion matches the timestamp-and-hash form the Go toolchain synthesises
// for a commit with no tag. It is shaped like a version and is not one.
var pseudoVersion = regexp.MustCompile(`-[0-9]{14}-[0-9a-f]{12}`)

// Build is what a binary can say about its own provenance.
type Build struct {
	// Version is the publishable release version, v-stripped, and is empty
	// unless the binary was built from an exact and clean release tag. Callers
	// that publish must treat empty as a refusal: a snapshot published under a
	// release version is indistinguishable from the release afterwards.
	Version string `json:"version"`
	// Describe is what the build was stamped with, kept verbatim so a snapshot
	// can still identify itself precisely.
	Describe string `json:"describe,omitempty"`
	// Revision is the commit, when the toolchain or the stamp recorded one.
	Revision string `json:"revision,omitempty"`
	// Modified reports that the working tree had uncommitted changes.
	Modified bool `json:"modified,omitempty"`
}

// IsRelease reports whether this binary may be published as a release.
func (build Build) IsRelease() bool { return build.Version != "" }

// String renders the build for a human.
func (build Build) String() string {
	switch {
	case build.IsRelease():
		return build.Version
	case build.Describe != "":
		return build.Describe
	case build.Revision != "":
		revision := build.Revision
		if len(revision) > 12 {
			revision = revision[:12]
		}
		if build.Modified {
			return revision + "-dirty"
		}
		return revision
	default:
		return "unknown"
	}
}

// Current reports what this binary is.
func Current() Build {
	build := Build{Describe: stamped}
	if stamped != "" {
		build.Modified = strings.HasSuffix(stamped, "-dirty")
		build.Version = releaseVersion(stamped)
	}
	readBuildInfo(&build)
	return build
}

// readBuildInfo fills in what the Go toolchain embedded. It never overrides the
// stamp: an explicit link-time value is the more specific statement.
func readBuildInfo(build *Build) {
	info, available := debug.ReadBuildInfo()
	if !available {
		return
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if build.Revision == "" {
				build.Revision = setting.Value
			}
		case "vcs.modified":
			if stamped == "" && setting.Value == "true" {
				build.Modified = true
			}
		}
	}
	// A stamp is the authoritative answer to whether this is a release,
	// including when the answer is no. Consulting the module version after a
	// stamp has already declined would let a snapshot build be republished as a
	// release under a synthesised version.
	if stamped != "" {
		return
	}
	// `go install module@v1.2.3` records a real tagged version even with no
	// stamp, and that is a release by construction.
	if resolved := moduleReleaseVersion(info.Main.Version); resolved != "" && !build.Modified {
		build.Version = resolved
		build.Describe = info.Main.Version
	}
}

// moduleReleaseVersion accepts only a genuinely tagged module version. A
// pseudo-version names an untagged commit, and Go appends "+dirty" or
// "+incompatible" as markers rather than as part of any tag; none of those is a
// release however much it is shaped like one.
func moduleReleaseVersion(moduleVersion string) string {
	if moduleVersion == "" || moduleVersion == "(devel)" {
		return ""
	}
	if strings.Contains(moduleVersion, "+") || pseudoVersion.MatchString(moduleVersion) {
		return ""
	}
	return releaseVersion(moduleVersion)
}

// releaseVersion converts a Git describe string into a publishable version, or
// returns empty when the build is not an exact, clean release.
func releaseVersion(describe string) string {
	if describe == "" || strings.HasSuffix(describe, "-dirty") {
		return ""
	}
	if snapshot.MatchString(describe) {
		return ""
	}
	candidate := strings.TrimPrefix(describe, "v")
	if !releaseTag.MatchString(candidate) || hashLike.MatchString(candidate) {
		return ""
	}
	return candidate
}

// PackageVersion converts a Git tag into the version a repository publishes,
// reporting whether the tag names a release at all. It is the same rule Current
// applies, exposed for tooling that has a tag in hand rather than a binary.
func PackageVersion(tag string) (string, bool) {
	resolved := releaseVersion(strings.TrimSpace(tag))
	return resolved, resolved != ""
}
