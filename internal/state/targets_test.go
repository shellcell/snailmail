package state

import (
	"strings"
	"testing"
)

// A repository owns what it publishes: a local host replaces a managed release
// directory, and a Pages host force-updates a branch to an orphan commit of the
// whole tree. Two repositories aimed at one target take turns destroying each
// other, and the loser looks published until someone fetches it.
func TestOverlappingPublicationTargetsAreRefused(t *testing.T) {
	manifest := Manifest{Repositories: map[string]Repository{
		"releases": {Format: "raw", Host: HostConfig{Type: "local", Path: "docs/releases"}},
		"apt": {Format: "deb", Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/apt", Branch: "gh-pages",
			PreviewRepository: "shellcell/apt-preview", PreviewBranch: "gh-pages",
		}},
		"python": {Format: "pypi", Host: HostConfig{Type: "s3", Bucket: "packages", Prefix: "python"}},
	}}

	for name, candidate := range map[string]Repository{
		"same directory":   {Host: HostConfig{Type: "local", Path: "docs/releases"}},
		"nested directory": {Host: HostConfig{Type: "local", Path: "docs/releases/sub"}},
		// Publishing into a parent replaces everything below it.
		"parent directory": {Host: HostConfig{Type: "local", Path: "docs"}},
		"same Pages branch": {Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/apt", Branch: "gh-pages",
			PreviewRepository: "shellcell/other-preview", PreviewBranch: "gh-pages",
		}},
		// A shared preview clobbers just as thoroughly as a shared production.
		"shared preview repository": {Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/raw", Branch: "gh-pages",
			PreviewRepository: "shellcell/apt-preview", PreviewBranch: "gh-pages",
		}},
		"production over another preview": {Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/apt-preview", Branch: "gh-pages",
			PreviewRepository: "shellcell/x-preview", PreviewBranch: "gh-pages",
		}},
		"same bucket and prefix": {Host: HostConfig{Type: "s3", Bucket: "packages", Prefix: "python"}},
		"nested bucket prefix":   {Host: HostConfig{Type: "s3", Bucket: "packages", Prefix: "python/wheels"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkPublicationTargets(manifest, "candidate", candidate); err == nil {
				t.Fatal("an overlapping target was accepted")
			}
		})
	}
}

func TestDistinctPublicationTargetsAreAllowed(t *testing.T) {
	manifest := Manifest{Repositories: map[string]Repository{
		"releases": {Format: "raw", Host: HostConfig{Type: "local", Path: "docs/releases"}},
		"apt": {Format: "deb", Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/apt", Branch: "gh-pages",
			PreviewRepository: "shellcell/apt-preview", PreviewBranch: "gh-pages",
		}},
		"python": {Format: "pypi", Host: HostConfig{Type: "s3", Bucket: "packages", Prefix: "python"}},
	}}

	for name, candidate := range map[string]Repository{
		"sibling directory": {Host: HostConfig{Type: "local", Path: "docs/charts"}},
		// A shared prefix that is not a path boundary is a different directory.
		"similarly named directory": {Host: HostConfig{Type: "local", Path: "docs/releases-old"}},
		"another branch of one repository": {Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/apt", Branch: "other-pages",
			PreviewRepository: "shellcell/o-preview", PreviewBranch: "gh-pages",
		}},
		"another Pages repository": {Host: HostConfig{
			Type: "github-pages", Repository: "shellcell/charts", Branch: "gh-pages",
			PreviewRepository: "shellcell/charts-preview", PreviewBranch: "gh-pages",
		}},
		"another prefix in one bucket": {Host: HostConfig{Type: "s3", Bucket: "packages", Prefix: "debian"}},
		"another bucket":               {Host: HostConfig{Type: "s3", Bucket: "other", Prefix: "python"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkPublicationTargets(manifest, "candidate", candidate); err != nil {
				t.Fatalf("a distinct target was refused: %v", err)
			}
		})
	}
}

// Reconfiguring a repository compares it against the others, not against the
// entry it is replacing.
func TestPublicationTargetsIgnoreTheRepositoryBeingConfigured(t *testing.T) {
	manifest := Manifest{Repositories: map[string]Repository{
		"releases": {Format: "raw", Host: HostConfig{Type: "local", Path: "docs/releases"}},
	}}
	candidate := Repository{Host: HostConfig{Type: "local", Path: "docs/releases"}}
	if err := checkPublicationTargets(manifest, "releases", candidate); err != nil {
		t.Fatalf("a repository collided with itself: %v", err)
	}
}

// The error has to name both repositories and the target, or an operator cannot
// tell which of several configured repositories is in the way.
func TestPublicationTargetErrorNamesBothRepositories(t *testing.T) {
	manifest := Manifest{Repositories: map[string]Repository{
		"releases": {Format: "raw", Host: HostConfig{Type: "local", Path: "docs/releases"}},
	}}
	err := checkPublicationTargets(manifest, "other", Repository{Host: HostConfig{Type: "local", Path: "docs/releases"}})
	if err == nil {
		t.Fatal("expected a collision")
	}
	for _, want := range []string{"other", "releases", "docs/releases"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
