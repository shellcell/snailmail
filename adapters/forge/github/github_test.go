package githubforge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/forge/forgetest"
)

// The adapter shells out to gh, so it is tested against a gh on PATH that
// answers from fixtures. This exercises the real argument construction, the real
// process boundary and the real JSON decoding — the parts that would otherwise
// only ever run against github.com, where a wrong translation is not something a
// test suite would notice.
//
// Each endpoint gets its own fixture file. An absent file means the endpoint was
// not expected, and the script fails, so an adapter that asks a different
// question than the test arranged for is a failure rather than a pass.
const fakeGH = `#!/bin/sh
set -e
endpoint=""
for argument in "$@"; do endpoint="$argument"; done
if [ -f "$SNAILMAIL_FAKE_GH_DIR/unavailable" ]; then
  echo "gh: could not reach the API" >&2
  exit 1
fi
printf '%s\n' "$*" >> "$SNAILMAIL_FAKE_GH_DIR/calls"
case "$endpoint" in
  */pulls)   file=pulls.json ;;
  */compare/*) file=compare.json ;;
  repos/*)   file=repo.json ;;
  *) echo "gh: unexpected endpoint $endpoint" >&2; exit 1 ;;
esac
if [ ! -f "$SNAILMAIL_FAKE_GH_DIR/$file" ]; then
  echo "gh: no fixture for $endpoint" >&2
  exit 1
fi
cat "$SNAILMAIL_FAKE_GH_DIR/$file"
`

// installFakeGH puts a scripted gh first on PATH and returns its fixture
// directory, so a test can rewrite what the provider answers between cases.
func installFakeGH(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	script := filepath.Join(directory, "gh")
	if err := os.WriteFile(script, []byte(fakeGH), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join(directory, "fixtures")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNAILMAIL_FAKE_GH_DIR", fixtures)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	return fixtures
}

func writeFixture(t *testing.T, fixtures, name string, content any) {
	t.Helper()
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, name), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

// arrangeGH renders a conformance scenario as the responses gh would print.
func arrangeGH(fixtures string) func(*testing.T, forgetest.Scenario) {
	return func(t *testing.T, scenario forgetest.Scenario) {
		t.Helper()
		for _, name := range []string{"repo.json", "pulls.json", "compare.json", "unavailable", "calls"} {
			if err := os.Remove(filepath.Join(fixtures, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		if scenario.Unavailable {
			if err := os.WriteFile(filepath.Join(fixtures, "unavailable"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
		writeFixture(t, fixtures, "repo.json", map[string]any{
			"full_name":      scenario.Repository.Name,
			"default_branch": scenario.Repository.DefaultBranch,
		})
		pulls := make([]map[string]any, 0, len(scenario.PullRequests))
		for _, pullRequest := range scenario.PullRequests {
			var mergedAt any
			if pullRequest.Merged {
				mergedAt = "2026-01-01T00:00:00Z"
			}
			pulls = append(pulls, map[string]any{
				"number":    pullRequest.Number,
				"merged_at": mergedAt,
				"base":      map[string]any{"ref": pullRequest.BaseBranch},
			})
		}
		writeFixture(t, fixtures, "pulls.json", pulls)
		// GitHub reports the comparison relative to the base, which the adapter
		// asks for as revision...branch: the branch being ahead of the revision is
		// what puts the revision on it.
		status := "diverged"
		if scenario.Ancestry.Contains {
			status = "ahead"
		}
		writeFixture(t, fixtures, "compare.json", map[string]any{
			"status":            status,
			"merge_base_commit": map[string]any{"sha": scenario.Ancestry.MergeBase},
		})
	}
}

func TestGitHubConformsToTheForgePort(t *testing.T) {
	fixtures := installFakeGH(t)
	forgetest.Conformance(t, New(), arrangeGH(fixtures))
}

// The compare status is the whole of the containment answer, and only two of the
// four values put the revision on the branch. "behind" means the branch is
// behind the revision — the revision is not on it — and reading that as
// contained would authorize a revision that was never merged.
func TestGitHubMapsEveryCompareStatus(t *testing.T) {
	fixtures := installFakeGH(t)
	adapter := New()
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for status, contained := range map[string]bool{
		"ahead":     true,
		"identical": true,
		"behind":    false,
		"diverged":  false,
	} {
		t.Run(status, func(t *testing.T) {
			writeFixture(t, fixtures, "compare.json", map[string]any{
				"status":            status,
				"merge_base_commit": map[string]any{"sha": forgetest.Revision},
			})
			ancestry, err := adapter.RevisionAncestry(context.Background(), target, forgetest.Revision, "main")
			if err != nil {
				t.Fatal(err)
			}
			if ancestry.Contains != contained {
				t.Errorf("status %q read as contained=%v, want %v", status, ancestry.Contains, contained)
			}
		})
	}
}

// An empty merged_at is as absent as a null one. GitHub sends null, but a
// proxy or a Enterprise version that sends "" must not read as merged.
func TestGitHubTreatsAnEmptyMergeTimeAsUnmerged(t *testing.T) {
	fixtures := installFakeGH(t)
	for name, mergedAt := range map[string]any{"null": nil, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			writeFixture(t, fixtures, "pulls.json", []map[string]any{
				{"number": 12, "merged_at": mergedAt, "base": map[string]any{"ref": "main"}},
			})
			pullRequests, err := New().PullRequestsForRevision(context.Background(),
				forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}, forgetest.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if len(pullRequests) != 1 || pullRequests[0].Merged {
				t.Errorf("merged_at %v read as %+v, want unmerged", mergedAt, pullRequests)
			}
		})
	}
}

// A repository with no default branch cannot be compared against, so it is
// unknown rather than a repository that reviews nothing.
func TestGitHubRefusesARepositoryWithNoDefaultBranch(t *testing.T) {
	fixtures := installFakeGH(t)
	writeFixture(t, fixtures, "repo.json", map[string]any{"full_name": forgetest.Repository, "default_branch": ""})
	_, err := New().Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()})
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

// A response the adapter cannot fully account for is unknown. Trailing data
// means something other than the API answered, or answered twice, and picking
// the first document would be reading review evidence from an unidentified
// source.
func TestGitHubRefusesAResponseItCannotAccountFor(t *testing.T) {
	fixtures := installFakeGH(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for name, body := range map[string]string{
		"trailing document": `{"full_name":"shellcell/state","default_branch":"main"}{"full_name":"other"}`,
		"not json":          `<html>proxy error</html>`,
		"truncated":         `{"full_name":"shellcell/state",`,
		"oversized":         `{"default_branch":"` + strings.Repeat("x", maxResponseSize+1) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(fixtures, "repo.json"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := New().Repository(context.Background(), target); !errors.Is(err, forge.ErrUnavailable) {
				t.Errorf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// Enterprise instances are reached by hostname, and the hostname reaches gh as
// an argument. A hostname carrying a space or a slash would become a second
// argument or a path, so it is rejected rather than passed through.
func TestGitHubHostnameIsCheckedBeforeItReachesTheCLI(t *testing.T) {
	for _, hostname := range []string{"", " ", "github.example.com/api", "a b", "host\nname", "host\tname"} {
		if _, err := NewForHost(hostname); err == nil {
			t.Errorf("hostname %q was accepted", hostname)
		}
	}
	adapter, err := NewForHost("github.example.com")
	if err != nil {
		t.Fatalf("a valid Enterprise hostname was refused: %v", err)
	}
	fixtures := installFakeGH(t)
	arrangeGH(fixtures)(t, forgetest.Reviewed())
	if _, err := adapter.Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(fixtures, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "--hostname github.example.com") {
		t.Errorf("gh was called as %q, want the configured hostname", strings.TrimSpace(string(calls)))
	}
}

// The resolver exists so the gate does not have to know which provider it is
// talking to. It must hand back an adapter rather than nil, whatever it is asked
// about, because a nil provider would be a panic during authorization.
func TestGitHubResolverAlwaysReturnsAnAdapter(t *testing.T) {
	for _, name := range []string{forgetest.Repository, "", "not/a/github/name"} {
		selected, err := NewResolver().Resolve(context.Background(), forge.Repository{Name: name})
		if err != nil || selected == nil {
			t.Fatalf("resolving %q gave (%v, %v)", name, selected, err)
		}
		if selected.Name() != "github" {
			t.Errorf("resolving %q selected %q", name, selected.Name())
		}
	}
}

func TestFakeGHRefusesAnUnexpectedEndpoint(t *testing.T) {
	// The harness itself has to fail closed, or every case above could be
	// passing against a fixture the adapter never asked for.
	fixtures := installFakeGH(t)
	arrangeGH(fixtures)(t, forgetest.Reviewed())
	if err := os.Remove(filepath.Join(fixtures, "repo.json")); err != nil {
		t.Fatal(err)
	}
	_, err := New().Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()})
	if err == nil {
		t.Fatal("a missing fixture was reported as a successful read")
	}
}
