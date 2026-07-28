package version

import (
	"testing"

	"github.com/shellcell/snailmail/formats/raw"
)

func TestReleaseTagsBecomePublishableVersions(t *testing.T) {
	for tag, want := range map[string]string{
		"v0.1.2":       "0.1.2",
		"0.1.2":        "0.1.2",
		"v1.0.0-rc1":   "1.0.0-rc1",
		"v2024.1":      "2024.1",
		"v1.2.3.4":     "1.2.3.4",
		"  v0.1.2  \n": "0.1.2",
	} {
		got, ok := PackageVersion(tag)
		if !ok || got != want {
			t.Errorf("PackageVersion(%q) = %q, %v; want %q, true", tag, got, ok, want)
		}
	}
}

// Publishing a snapshot under a release version is unrecoverable: afterwards
// nothing distinguishes it from the release it claims to be.
func TestSnapshotsAndDirtyTreesAreNotReleases(t *testing.T) {
	for _, describe := range []string{
		"v0.1.2-3-gabc1234",
		"v0.1.2-3-gabc1234-dirty",
		"v0.1.2-dirty",
		"abc1234", // --always with no tag reachable
		"5957ba6", // the same, but digit-led: shaped exactly like a version
		"5957ba66781db296d66a1e575c819325fe57772e", // an unabbreviated hash
		"vsomance", // not a version at all
		"v",
		"",
	} {
		if got, ok := PackageVersion(describe); ok {
			t.Errorf("PackageVersion(%q) = %q, true; want a refusal", describe, got)
		}
	}
}

// The version this package produces has to be one the raw format will accept,
// or a release would be built and then refused at publish time. Asserting it
// here keeps the two patterns honest rather than merely similar.
func TestPublishableVersionsAreAcceptedByRaw(t *testing.T) {
	for _, tag := range []string{"v0.1.2", "v1.0.0-rc1", "v2024.1", "v1.2.3.4"} {
		resolved, ok := PackageVersion(tag)
		if !ok {
			t.Fatalf("%s is not publishable", tag)
		}
		if _, err := raw.FactsFor("snailmail", resolved, "snailmail_"+resolved+"_linux_amd64.tar.gz"); err != nil {
			t.Errorf("raw rejected version %q derived from %q: %v", resolved, tag, err)
		}
	}
}

func TestCurrentDescribesAnUnstampedBuild(t *testing.T) {
	// The test binary carries no stamp, so this exercises the fallback path.
	build := Current()
	if build.IsRelease() {
		t.Errorf("an unstamped test binary claims to be release %q", build.Version)
	}
	if build.String() == "" {
		t.Error("String() is empty; a build must always describe itself")
	}
}

func TestStringPrefersTheMostSpecificDescription(t *testing.T) {
	for name, testCase := range map[string]struct {
		build Build
		want  string
	}{
		"release":        {Build{Version: "0.1.2", Describe: "v0.1.2"}, "0.1.2"},
		"snapshot":       {Build{Describe: "v0.1.2-3-gabc1234"}, "v0.1.2-3-gabc1234"},
		"revision":       {Build{Revision: "abc1234def5678901"}, "abc1234def56"},
		"dirty revision": {Build{Revision: "abc1234def5678901", Modified: true}, "abc1234def56-dirty"},
		"nothing":        {Build{}, "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := testCase.build.String(); got != testCase.want {
				t.Errorf("String() = %q, want %q", got, testCase.want)
			}
		})
	}
}

// A module version is only a release when it names a real tag. The Go
// toolchain synthesises version-shaped strings for untagged and dirty builds,
// and accepting one would let a snapshot publish itself as a release.
func TestSynthesisedModuleVersionsAreNotReleases(t *testing.T) {
	for _, moduleVersion := range []string{
		"(devel)",
		"",
		"v0.0.0-20260728185423-5957ba66781d",
		"v0.0.0-20260728185423-5957ba66781d+dirty",
		"v1.2.3+incompatible",
		"v0.1.2+dirty",
	} {
		if got := moduleReleaseVersion(moduleVersion); got != "" {
			t.Errorf("moduleReleaseVersion(%q) = %q; want a refusal", moduleVersion, got)
		}
	}
	if got := moduleReleaseVersion("v1.2.3"); got != "1.2.3" {
		t.Errorf("moduleReleaseVersion(\"v1.2.3\") = %q, want \"1.2.3\"", got)
	}
}
