package githubforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/forge/forgetest"
)

// The HTTP path exists so a runner without gh can still run a gate. It reads the
// same endpoints and must reach the same answers, so it is held to the same
// conformance suite: a second route to the same authorization must not be a
// weaker one.
type apiServer struct {
	mutex     sync.Mutex
	scenario  forgetest.Scenario
	requested []string
	accept    string
}

func (server *apiServer) handler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.requested = append(server.requested, request.URL.Path)
		server.accept = request.Header.Get("Accept")
		scenario := server.scenario
		if scenario.Unavailable {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		path := request.URL.Path
		switch {
		case strings.HasSuffix(path, "/pulls"):
			pulls := make([]map[string]any, 0, len(scenario.PullRequests))
			for _, pullRequest := range scenario.PullRequests {
				var mergedAt any
				if pullRequest.Merged {
					mergedAt = "2026-01-01T00:00:00Z"
				}
				pulls = append(pulls, map[string]any{
					"number": pullRequest.Number, "merged_at": mergedAt,
					"base": map[string]any{"ref": pullRequest.BaseBranch},
				})
			}
			writeJSON(writer, pulls)
		case strings.Contains(path, "/compare/"):
			status := "diverged"
			if scenario.Ancestry.Contains {
				status = "ahead"
			}
			writeJSON(writer, map[string]any{
				"status": status, "merge_base_commit": map[string]any{"sha": scenario.Ancestry.MergeBase},
			})
		case strings.HasPrefix(path, "/repos/"):
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

// httpAdapter builds an adapter that cannot find gh, so it takes the HTTP path,
// and points it at a local server.
func httpAdapter(t *testing.T) (*Adapter, *apiServer) {
	t.Helper()
	// An empty PATH is how a runner with no gh installed looks. The transport is
	// chosen at construction, so this has to be set first.
	t.Setenv("PATH", t.TempDir())
	adapter := New(nil)
	if adapter.UsesCLI() {
		t.Fatal("gh was found on an empty PATH")
	}
	server := &apiServer{}
	httpServer := httptest.NewServer(server.handler())
	t.Cleanup(httpServer.Close)
	adapter.baseURL = httpServer.URL
	return adapter, server
}

func TestGitHubOverHTTPConformsToTheForgePort(t *testing.T) {
	adapter, server := httpAdapter(t)
	forgetest.Conformance(t, adapter, func(t *testing.T, scenario forgetest.Scenario) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.scenario = scenario
	})
}

// A runner with gh installed keeps using it: the vendor tool owns authentication,
// and snailmail holding a token is the weaker arrangement.
func TestTheCLIIsPreferredWhenInstalled(t *testing.T) {
	installFakeGH(t)
	if !New(nil).UsesCLI() {
		t.Error("gh is on PATH but the HTTP transport was chosen")
	}
	t.Setenv("PATH", t.TempDir())
	if New(nil).UsesCLI() {
		t.Error("gh is absent but the CLI transport was chosen")
	}
}

// github.com serves its API from its own host; an Enterprise instance serves it
// under the instance. Sending Enterprise requests to api.github.com would ask a
// different organisation about a repository with the same name.
func TestTheAPIBaseFollowsTheHost(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if base := New(nil).apiBase(); base != "https://api.github.com" {
		t.Errorf("github.com base = %q", base)
	}
	enterprise, err := NewForHost("github.acme.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if base := enterprise.apiBase(); base != "https://github.acme.example/api/v3" {
		t.Errorf("Enterprise base = %q", base)
	}
}

// gh sends this for every call, so the HTTP path asks the same question rather
// than relying on whatever the API happens to default to.
func TestTheHTTPPathDeclaresTheGitHubMediaType(t *testing.T) {
	adapter, server := httpAdapter(t)
	server.mutex.Lock()
	server.scenario = forgetest.Reviewed()
	server.mutex.Unlock()
	if _, err := adapter.Repository(context.Background(),
		forge.Repository{Name: forgetest.Repository, WorkingDirectory: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	if server.accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", server.accept)
	}
}

// A reference is interpolated into a path on the HTTP transport, where gh would
// have rejected it. Without a shape check a crafted name could address a
// different endpoint entirely.
func TestAReferenceCannotReshapeTheRequest(t *testing.T) {
	adapter, server := httpAdapter(t)
	server.mutex.Lock()
	server.scenario = forgetest.Reviewed()
	server.mutex.Unlock()
	for _, reference := range []string{"a/b/../../admin", "../admin", "a/b/c"} {
		if _, err := adapter.Repository(context.Background(),
			forge.Repository{Name: reference, WorkingDirectory: t.TempDir()}); err == nil {
			t.Errorf("reference %q was accepted", reference)
		}
	}
}

func TestUsesCLIIsStableForTheLifeOfAnAdapter(t *testing.T) {
	installFakeGH(t)
	adapter := New(nil)
	if !adapter.UsesCLI() {
		t.Fatal("gh was not found")
	}
	// gh disappearing mid-operation must not move the adapter onto another
	// transport partway through a gate's three reads.
	t.Setenv("PATH", t.TempDir())
	if !adapter.UsesCLI() {
		t.Error("the transport changed after construction")
	}
}
