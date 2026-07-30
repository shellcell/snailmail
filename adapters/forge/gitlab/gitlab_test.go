package gitlabforge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/adapters/forge/forgeio"
	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/forge/forgetest"
)

// glab is scripted the same way gh is in the GitHub adapter's tests, so the real
// argument construction, process boundary and JSON decoding all run. The endpoint
// is recorded rather than only matched, because how GitLab addresses a nested
// project is a thing this adapter has to get right and a fixture match would hide
// it.
const fakeGlab = `#!/bin/sh
set -e
endpoint=""
for argument in "$@"; do endpoint="$argument"; done
printf '%s\n' "$*" >> "$SNAILMAIL_FAKE_GLAB_DIR/calls"
if [ -f "$SNAILMAIL_FAKE_GLAB_DIR/unavailable" ]; then
  echo "glab: could not reach the API" >&2
  exit 1
fi
case "$endpoint" in
  *merge_base*)     file=merge_base.json ;;
  *merge_requests)  file=merge_requests.json ;;
  projects/*)       file=project.json ;;
  *) echo "glab: unexpected endpoint $endpoint" >&2; exit 1 ;;
esac
if [ ! -f "$SNAILMAIL_FAKE_GLAB_DIR/$file" ]; then
  echo "glab: no fixture for $endpoint" >&2
  exit 1
fi
cat "$SNAILMAIL_FAKE_GLAB_DIR/$file"
`

func installFakeGlab(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "glab"), []byte(fakeGlab), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join(directory, "fixtures")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNAILMAIL_FAKE_GLAB_DIR", fixtures)
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

// arrangeGlab renders a conformance scenario as the responses glab would print.
func arrangeGlab(fixtures string) func(*testing.T, forgetest.Scenario) {
	return func(t *testing.T, scenario forgetest.Scenario) {
		t.Helper()
		for _, name := range []string{"project.json", "merge_requests.json", "merge_base.json", "unavailable", "calls"} {
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
		writeFixture(t, fixtures, "project.json", map[string]any{
			"path_with_namespace": scenario.Repository.Name,
			"default_branch":      scenario.Repository.DefaultBranch,
		})
		requests := make([]map[string]any, 0, len(scenario.PullRequests))
		for _, pullRequest := range scenario.PullRequests {
			state := "closed"
			if pullRequest.Merged {
				state = "merged"
			}
			requests = append(requests, map[string]any{
				"iid": pullRequest.Number, "state": state, "target_branch": pullRequest.BaseBranch,
				// The global id is deliberately different from the iid, so an adapter
				// reading the wrong one fails rather than coincidentally passes.
				"id": pullRequest.Number + 10000,
			})
		}
		writeFixture(t, fixtures, "merge_requests.json", requests)
		writeFixture(t, fixtures, "merge_base.json", map[string]any{"id": scenario.Ancestry.MergeBase})
	}
}

func TestGitLabConformsToTheForgePort(t *testing.T) {
	fixtures := installFakeGlab(t)
	forgetest.Conformance(t, New(nil), arrangeGlab(fixtures))
}

// A merge request is known by its per-project iid. The global id is a different
// number that means nothing to anyone reading the project, and reporting it would
// name a review nobody can find.
func TestGitLabReportsThePerProjectNumber(t *testing.T) {
	fixtures := installFakeGlab(t)
	writeFixture(t, fixtures, "merge_requests.json", []map[string]any{
		{"iid": 12, "id": 98765, "state": "merged", "target_branch": "main"},
	})
	pullRequests, err := New(nil).PullRequestsForRevision(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}, forgetest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(pullRequests) != 1 || pullRequests[0].Number != 12 {
		t.Errorf("got %+v, want the iid 12", pullRequests)
	}
}

// Only "merged" is review that landed. "closed" is review that was rejected, and
// reading it as merged would authorize exactly what the gate exists to stop.
func TestGitLabMapsEveryMergeRequestState(t *testing.T) {
	fixtures := installFakeGlab(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for state, merged := range map[string]bool{
		"merged": true, "closed": false, "opened": false, "locked": false, "": false,
	} {
		t.Run(state, func(t *testing.T) {
			writeFixture(t, fixtures, "merge_requests.json", []map[string]any{
				{"iid": 12, "state": state, "target_branch": "main"},
			})
			pullRequests, err := New(nil).PullRequestsForRevision(context.Background(), target, forgetest.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if len(pullRequests) != 1 || pullRequests[0].Merged != merged {
				t.Errorf("state %q read as %+v, want merged=%v", state, pullRequests, merged)
			}
		})
	}
}

// Containment is derived from the merge base rather than from a status, so the
// two cases are exactly: the base is the revision, or it is not.
func TestGitLabDerivesContainmentFromTheMergeBase(t *testing.T) {
	fixtures := installFakeGlab(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	ancestor := strings.Repeat("c", 40)
	for name, base := range map[string]string{"the revision": forgetest.Revision, "an ancestor": ancestor} {
		t.Run(name, func(t *testing.T) {
			writeFixture(t, fixtures, "merge_base.json", map[string]any{"id": base})
			ancestry, err := New(nil).RevisionAncestry(context.Background(), target, forgetest.Revision, "main")
			if err != nil {
				t.Fatal(err)
			}
			if ancestry.Contains != (base == forgetest.Revision) || ancestry.MergeBase != base {
				t.Errorf("merge base %q read as %+v", base, ancestry)
			}
		})
	}
	// Two branches with no common history have no merge base. That is not "not
	// contained" — it is a question the answer does not fit, so it is unknown.
	writeFixture(t, fixtures, "merge_base.json", map[string]any{"id": ""})
	if _, err := New(nil).RevisionAncestry(context.Background(), target, forgetest.Revision, "main"); !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("an absent merge base gave %v, want ErrUnavailable", err)
	}
}

// Groups nest, so a project is addressed by its whole path with the separators
// encoded. An unencoded path would address a different endpoint entirely.
func TestGitLabAddressesANestedProjectByItsEncodedPath(t *testing.T) {
	fixtures := installFakeGlab(t)
	nested := "acme/platform/tools/state"
	writeFixture(t, fixtures, "project.json", map[string]any{
		"path_with_namespace": nested, "default_branch": "main",
	})
	info, err := New(nil).Repository(context.Background(),
		forge.Repository{Name: nested, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatalf("a nested project was refused: %v", err)
	}
	if info.Name != nested {
		t.Errorf("got %q, want %q", info.Name, nested)
	}
	calls, err := os.ReadFile(filepath.Join(fixtures, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "projects/acme%2Fplatform%2Ftools%2Fstate") {
		t.Errorf("glab was called as %q, want the path encoded", strings.TrimSpace(string(calls)))
	}
}

// A project that has moved answers about its new path. Following that would read
// review evidence from a repository nobody configured.
func TestGitLabRefusesAProjectThatAnsweredAboutAnotherPath(t *testing.T) {
	fixtures := installFakeGlab(t)
	writeFixture(t, fixtures, "project.json", map[string]any{
		"path_with_namespace": "acme/state-renamed", "default_branch": "main",
	})
	_, err := New(nil).Repository(context.Background(),
		forge.Repository{Name: "acme/state", WorkingDirectory: t.TempDir()})
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

// A value that is not a revision must not reach an endpoint. The gate supplies a
// git revision, but this is the boundary where that stops being an assumption.
func TestGitLabRefusesSomethingThatIsNotARevision(t *testing.T) {
	installFakeGlab(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for _, revision := range []string{"", "main", "../../projects", "a", strings.Repeat("a", 65), "HEAD~1"} {
		if _, err := New(nil).PullRequestsForRevision(context.Background(), target, revision); err == nil {
			t.Errorf("revision %q reached the API", revision)
		}
		if _, err := New(nil).RevisionAncestry(context.Background(), target, revision, "main"); err == nil {
			t.Errorf("revision %q reached the API", revision)
		}
	}
	// And a branch has to be sayable as one argument.
	for _, branch := range []string{"", "ma in", "main\n"} {
		if _, err := New(nil).RevisionAncestry(context.Background(), target, forgetest.Revision, branch); err == nil {
			t.Errorf("branch %q reached the API", branch)
		}
	}
}

func TestGitLabRefusesAResponseItCannotAccountFor(t *testing.T) {
	fixtures := installFakeGlab(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for name, body := range map[string]string{
		"trailing document": `{"path_with_namespace":"shellcell/state","default_branch":"main"}{"x":1}`,
		"not json":          `<html>502</html>`,
		"truncated":         `{"path_with_namespace":`,
		"oversized":         `{"default_branch":"` + strings.Repeat("x", forgeio.MaxResponseSize+1) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(fixtures, "project.json"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := New(nil).Repository(context.Background(), target); !errors.Is(err, forge.ErrUnavailable) {
				t.Errorf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestGitLabHostnameIsCheckedBeforeItReachesTheCLI(t *testing.T) {
	for _, hostname := range []string{"", " ", "git.acme.example/api", "a b", "host\nname"} {
		if _, err := NewForHost(hostname, nil); err == nil {
			t.Errorf("hostname %q was accepted", hostname)
		}
	}
	// The fake goes on PATH first: the transport is chosen at construction, so an
	// adapter built before it would pick HTTP on a machine with no real glab.
	fixtures := installFakeGlab(t)
	adapter, err := NewForHost("git.acme.example", nil)
	if err != nil {
		t.Fatalf("a valid self-hosted hostname was refused: %v", err)
	}
	arrangeGlab(fixtures)(t, forgetest.Reviewed())
	if _, err := adapter.Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(fixtures, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "--hostname git.acme.example") {
		t.Errorf("glab was called as %q, want the configured hostname", strings.TrimSpace(string(calls)))
	}
}

func TestGitLabResolverAlwaysReturnsAnAdapter(t *testing.T) {
	selected, err := NewResolver().Resolve(context.Background(), forge.Repository{Name: forgetest.Repository})
	if err != nil || selected == nil {
		t.Fatalf("resolving gave (%v, %v)", selected, err)
	}
	if selected.Name() != forge.ProviderGitLab {
		t.Errorf("selected %q", selected.Name())
	}
}
