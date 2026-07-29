package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/domain"
)

func versions(cases []domain.VerificationCase) []string {
	out := make([]string, 0, len(cases))
	for _, verification := range cases {
		out = append(out, verification.Package+"/"+verification.Architecture+"@"+verification.Version)
	}
	return out
}

func debianCases(architecture string, list ...string) []domain.VerificationCase {
	cases := make([]domain.VerificationCase, 0, len(list))
	for _, version := range list {
		cases = append(cases, domain.VerificationCase{Package: "snailmail", Architecture: architecture, Version: version})
	}
	return cases
}

// The newest is what people install; the oldest is what would break first if a
// regenerated index stopped serving anything but the latest.
func TestSampleKeepsNewestAndOldest(t *testing.T) {
	cases := debianCases("amd64", "0.0.3-1", "0.1.0-1", "0.0.9-1")
	got := SampleVerificationCases(cases, formatCompare("deb"))
	want := []string{"snailmail/amd64@0.0.3-1", "snailmail/amd64@0.1.0-1"}
	if !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("sampled %v, want %v", versions(got), want)
	}
}

// Ordering is by the format's own rules, not by text: 0.10 is newer than 0.9
// everywhere except in a string sort.
func TestSampleOrdersByFormatRules(t *testing.T) {
	cases := debianCases("amd64", "0.9.0-1", "0.10.0-1", "0.2.0-1")
	got := SampleVerificationCases(cases, formatCompare("deb"))
	want := []string{"snailmail/amd64@0.10.0-1", "snailmail/amd64@0.2.0-1"}
	if !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("sampled %v, want %v — 0.2.0 is oldest and 0.10.0 newest", versions(got), want)
	}
}

// Each architecture is a separate client and a separate index entry, so the
// sample is per architecture rather than per package.
func TestSampleIsPerArchitecture(t *testing.T) {
	cases := append(debianCases("amd64", "1.0-1", "2.0-1", "3.0-1"), debianCases("arm64", "1.0-1", "2.0-1", "3.0-1")...)
	got := SampleVerificationCases(cases, formatCompare("deb"))
	if len(got) != 4 {
		t.Fatalf("sampled %d cases, want 2 per architecture: %v", len(got), versions(got))
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		seen := 0
		for _, verification := range got {
			if verification.Architecture == architecture {
				seen++
			}
		}
		if seen != 2 {
			t.Errorf("architecture %s got %d cases, want 2", architecture, seen)
		}
	}
}

// A version the format cannot order is one nothing can choose between, so the
// whole group is verified rather than an arbitrary pair of it.
func TestSampleVerifiesEverythingItCannotOrder(t *testing.T) {
	cases := debianCases("amd64", "1.0-1", "2.0-1", "3.0-1")
	got := SampleVerificationCases(cases, func(string, string) (int, error) {
		return 0, errors.New("unorderable")
	})
	if len(got) != len(cases) {
		t.Fatalf("sampled %d of %d cases; an unorderable group must not be narrowed", len(got), len(cases))
	}
}

// A failure should name the same case whether or not sampling was in play.
func TestSampleKeepsManifestOrder(t *testing.T) {
	cases := append(debianCases("amd64", "3.0-1", "1.0-1", "2.0-1"), debianCases("arm64", "9.0-1")...)
	got := SampleVerificationCases(cases, formatCompare("deb"))
	want := []string{"snailmail/amd64@3.0-1", "snailmail/amd64@1.0-1", "snailmail/arm64@9.0-1"}
	if !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("sampled %v, want the manifest's order %v", versions(got), want)
	}
}

// Asking for everything must get everything, and an unrecognised policy must
// not quietly check less than it was told to.
func TestScopeSelection(t *testing.T) {
	cases := debianCases("amd64", "1.0-1", "2.0-1", "3.0-1")
	if got := AllVersions.selection(cases, formatCompare("deb")); len(got) != 3 {
		t.Errorf("AllVersions narrowed to %d cases", len(got))
	}
	if got := VersionScope("nonsense").selection(cases, formatCompare("deb")); len(got) != 3 {
		t.Errorf("an unrecognised scope narrowed to %d cases", len(got))
	}
	if got := SampledVersions.selection(cases, formatCompare("deb")); len(got) != 2 {
		t.Errorf("SampledVersions kept %d cases, want 2", len(got))
	}
}

// Every format whose client verification samples must be able to order its own
// versions, or the sample silently falls back to verifying everything.
func TestSamplingComparatorsResolve(t *testing.T) {
	for name, compare := range map[string]func(string, string) (int, error){
		"deb": debCompare, "rpm": rpmCompare, "apk": apkCompare,
	} {
		if _, err := formats.For(name); err != nil {
			t.Fatalf("format %q is not registered: %v", name, err)
		}
		if _, err := compare("1.0", "1.0"); err != nil {
			t.Errorf("format %q cannot order its own versions: %v", name, err)
		}
	}
}
