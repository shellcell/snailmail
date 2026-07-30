package forgejoforge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/forge/forgetest"
)

// The adapter speaks HTTP, so it is tested against a server that answers the way
// a Forgejo instance does. The shapes here are the ones observed on codeberg.org:
// merged as a boolean beside state "closed", a singular per-commit endpoint that
// 404s when nothing reviewed a commit, and a comparison that reports only a count.
type instance struct {
	mutex        sync.Mutex
	scenario     forgetest.Scenario
	requested    []string
	compareCount int
}

func (server *instance) handler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.requested = append(server.requested, request.URL.Path)
		scenario := server.scenario
		if scenario.Unavailable {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		path := strings.TrimPrefix(request.URL.Path, "/api/v1/")
		switch {
		case strings.Contains(path, "/compare/"):
			// Empty exactly when the branch already contains the revision.
			count := server.compareCount
			if !scenario.Ancestry.Contains && count == 0 {
				count = 1
			}
			writeJSON(writer, map[string]any{"total_commits": count, "commits": []any{}, "files": []any{}})
		case strings.HasSuffix(path, "/pull"):
			if len(scenario.PullRequests) == 0 {
				// No review is a 404 here, not an empty list.
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			pullRequest := scenario.PullRequests[0]
			state := "open"
			if pullRequest.Merged {
				state = "closed"
			}
			writeJSON(writer, map[string]any{
				"number": pullRequest.Number, "merged": pullRequest.Merged, "state": state,
				"base": map[string]any{"ref": pullRequest.BaseBranch},
			})
		case strings.HasPrefix(path, "repos/"):
			writeJSON(writer, map[string]any{
				"full_name": scenario.Repository.Name, "default_branch": scenario.Repository.DefaultBranch,
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

func writeJSON(writer http.ResponseWriter, body any) {
	encoded, _ := json.Marshal(body)
	_, _ = writer.Write(encoded)
}

// adapterFor points the adapter at a local server. The scheme is http on
// loopback, which forgeio permits precisely so a test server and a local instance
// can be reached.
func adapterFor(t *testing.T) (*Adapter, *instance) {
	t.Helper()
	server := &instance{}
	httpServer := httptest.NewServer(server.handler())
	t.Cleanup(httpServer.Close)
	adapter, err := NewForHost(forge.ProviderForgejo, "git.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter.baseURL = httpServer.URL + "/api/v1"
	return adapter, server
}

func TestForgejoConformsToTheForgePort(t *testing.T) {
	adapter, server := adapterFor(t)
	forgetest.Conformance(t, adapter, func(t *testing.T, scenario forgetest.Scenario) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.scenario = scenario
		server.compareCount = 0
	})
}

// Gitea speaks the same API, and the only thing that differs is the name in the
// manifest and in an error.
func TestGiteaIsTheSameAdapterUnderItsOwnName(t *testing.T) {
	adapter, err := NewForHost(forge.ProviderGitea, "git.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Name() != forge.ProviderGitea {
		t.Errorf("Name() = %q", adapter.Name())
	}
	if _, err := NewForHost("github", "git.example", nil); err == nil {
		t.Error("a provider this adapter does not speak for was accepted")
	}
}

// This is the trap. A merged pull request reports merged=true and state "closed",
// so GitLab's rule — state == "merged" — would read every merged review as
// unmerged and refuse every publication.
func TestForgejoReadsMergedRatherThanState(t *testing.T) {
	adapter, server := adapterFor(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for _, merged := range []bool{true, false} {
		server.mutex.Lock()
		scenario := forgetest.Reviewed()
		scenario.PullRequests[0].Merged = merged
		server.scenario = scenario
		server.mutex.Unlock()
		pullRequests, err := adapter.PullRequestsForRevision(context.Background(), target, forgetest.Revision)
		if err != nil {
			t.Fatal(err)
		}
		if len(pullRequests) != 1 || pullRequests[0].Merged != merged {
			t.Errorf("merged=%v read as %+v", merged, pullRequests)
		}
	}
}

// A commit with no pull request is a 404, and that is an answer rather than a
// failure. Reporting it as unavailable would send an operator to check
// credentials for a revision that simply was not reviewed.
func TestNoReviewIsNoneRatherThanUnavailable(t *testing.T) {
	adapter, server := adapterFor(t)
	server.mutex.Lock()
	scenario := forgetest.Reviewed()
	scenario.PullRequests = nil
	server.scenario = scenario
	server.mutex.Unlock()
	pullRequests, err := adapter.PullRequestsForRevision(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}, forgetest.Revision)
	if err != nil {
		t.Fatalf("a revision with no review read as %v", err)
	}
	if len(pullRequests) != 0 {
		t.Errorf("got %+v, want none", pullRequests)
	}
}

// A 404 anywhere else is unknown. A repository the token cannot see answers the
// same way as one that does not exist, and neither is evidence about review.
func TestNotFoundElsewhereIsUnavailable(t *testing.T) {
	adapter, server := adapterFor(t)
	server.mutex.Lock()
	server.scenario = forgetest.Scenario{}
	server.mutex.Unlock()
	// An empty scenario answers the repository endpoint with an empty name, which
	// cannot match the request.
	_, err := adapter.Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()})
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

// Containment comes from a count, so the two outcomes are exactly: nothing is
// reachable from the revision that the branch lacks, or something is.
func TestContainmentComesFromTheReverseComparison(t *testing.T) {
	adapter, server := adapterFor(t)
	target := forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}
	for count, contained := range map[int]bool{0: true, 1: false, 42: false} {
		server.mutex.Lock()
		server.scenario = forgetest.Reviewed()
		server.compareCount = count
		server.mutex.Unlock()
		ancestry, err := adapter.RevisionAncestry(context.Background(), target, forgetest.Revision, "main")
		if err != nil {
			t.Fatal(err)
		}
		if ancestry.Contains != contained {
			t.Errorf("total_commits=%d read as contained=%v", count, ancestry.Contains)
		}
		// The merge base is reported only when it is known to be the revision, and
		// left empty otherwise so it cannot satisfy the gate's check by accident.
		if contained && ancestry.MergeBase != forgetest.Revision {
			t.Errorf("total_commits=0 gave merge base %q", ancestry.MergeBase)
		}
		if !contained && ancestry.MergeBase != "" {
			t.Errorf("total_commits=%d invented merge base %q", count, ancestry.MergeBase)
		}
	}
}

// The comparison is asked base-first, branch then revision. Reversed it would be
// empty whenever the revision is merely an ancestor's descendant, which would
// report an unmerged revision as being on the branch.
func TestTheComparisonAsksTheBranchFirst(t *testing.T) {
	adapter, server := adapterFor(t)
	if _, err := adapter.RevisionAncestry(context.Background(),
		forge.Repository{Name: forgetest.Repository}, forgetest.Revision, "release/2.0"); err != nil {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		t.Fatalf("err=%v paths=%v", err, server.requested)
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	want := "/compare/release/2.0..." + forgetest.Revision
	var found bool
	for _, path := range server.requested {
		if strings.HasSuffix(path, want) {
			found = true
		}
	}
	if !found {
		t.Errorf("requested %v, want a path ending %q", server.requested, want)
	}
}

// Groups do not nest here, so a reference with more than two segments is a
// misconfiguration rather than something to pass through — and a value that is
// not a revision must not reach an endpoint at all.
func TestForgejoRefusesReferencesAndRevisionsItCannotAddress(t *testing.T) {
	adapter, _ := adapterFor(t)
	ctx := context.Background()
	for _, reference := range []string{"acme/team/state", "state", "", "acme/state.git"} {
		if _, err := adapter.Repository(ctx, forge.Repository{Name: reference}); err == nil {
			t.Errorf("reference %q was accepted", reference)
		}
	}
	target := forge.Repository{Name: forgetest.Repository}
	for _, revision := range []string{"", "main", "../../admin", "HEAD~1", strings.Repeat("a", 65)} {
		if _, err := adapter.PullRequestsForRevision(ctx, target, revision); err == nil {
			t.Errorf("revision %q reached the API", revision)
		}
		if _, err := adapter.RevisionAncestry(ctx, target, revision, "main"); err == nil {
			t.Errorf("revision %q reached the API", revision)
		}
	}
	for _, branch := range []string{"", "ma in", "a..b", "main#x", "main?x"} {
		if _, err := adapter.RevisionAncestry(ctx, target, forgetest.Revision, branch); err == nil {
			t.Errorf("branch %q reached the API", branch)
		}
	}
}

// Neither provider has a hostname of its own, so an instance is always named, and
// a hostname that could not be sent is refused before it reaches a request.
func TestForgejoRequiresAUsableHost(t *testing.T) {
	for _, hostname := range []string{"", " ", "git.example/api", "a b", "host\nname"} {
		if _, err := NewForHost(forge.ProviderForgejo, hostname, nil); err == nil {
			t.Errorf("hostname %q was accepted", hostname)
		}
	}
	adapter, err := NewForHost(forge.ProviderForgejo, "git.acme.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.host() != "git.acme.example" {
		t.Errorf("host() = %q", adapter.host())
	}
	// https, so a token is never sent in the clear.
	if !strings.HasPrefix(adapter.baseURL, "https://") {
		t.Errorf("baseURL = %q", adapter.baseURL)
	}
}
