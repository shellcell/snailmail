package gitlabforge

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

// The HTTP path exists so a runner without glab can still run a gate. It reads the
// same endpoints and must reach the same answers, so it is held to the same
// conformance suite: a second route to the same authorization must not be a
// weaker one.
type apiServer struct {
	mutex     sync.Mutex
	scenario  forgetest.Scenario
	requested []string
}

func (server *apiServer) handler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.requested = append(server.requested, request.URL.RequestURI())
		scenario := server.scenario
		if scenario.Unavailable {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		path := request.URL.Path
		switch {
		case strings.Contains(path, "/merge_base"):
			writeAPIJSON(writer, map[string]any{"id": scenario.Ancestry.MergeBase})
		case strings.HasSuffix(path, "/merge_requests"):
			requests := make([]map[string]any, 0, len(scenario.PullRequests))
			for _, pullRequest := range scenario.PullRequests {
				state := "closed"
				if pullRequest.Merged {
					state = "merged"
				}
				requests = append(requests, map[string]any{
					"iid": pullRequest.Number, "id": pullRequest.Number + 10000,
					"state": state, "target_branch": pullRequest.BaseBranch,
				})
			}
			writeAPIJSON(writer, requests)
		case strings.HasPrefix(path, "/api/v4/projects/"):
			writeAPIJSON(writer, map[string]any{
				"path_with_namespace": scenario.Repository.Name,
				"default_branch":      scenario.Repository.DefaultBranch,
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

func writeAPIJSON(writer http.ResponseWriter, body any) {
	encoded, _ := json.Marshal(body)
	_, _ = writer.Write(encoded)
}

// httpAdapter builds an adapter that cannot find glab, so it takes the HTTP path,
// and points it at a local server.
func httpAdapter(t *testing.T) (*Adapter, *apiServer) {
	t.Helper()
	// An empty PATH is how a runner with no glab installed looks. The transport is
	// chosen at construction, so this has to be set first.
	t.Setenv("PATH", t.TempDir())
	adapter := New(nil)
	if adapter.UsesCLI() {
		t.Fatal("glab was found on an empty PATH")
	}
	server := &apiServer{}
	httpServer := httptest.NewServer(server.handler())
	t.Cleanup(httpServer.Close)
	adapter.baseURL = httpServer.URL + "/api/v4"
	return adapter, server
}

func TestGitLabOverHTTPConformsToTheForgePort(t *testing.T) {
	adapter, server := httpAdapter(t)
	forgetest.Conformance(t, adapter, func(t *testing.T, scenario forgetest.Scenario) {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		server.scenario = scenario
	})
}

// A runner with glab installed keeps using it: the vendor tool owns
// authentication, and snailmail holding a token is the weaker arrangement.
func TestTheCLIIsPreferredWhenInstalled(t *testing.T) {
	installFakeGlab(t)
	if !New(nil).UsesCLI() {
		t.Error("glab is on PATH but the HTTP transport was chosen")
	}
	t.Setenv("PATH", t.TempDir())
	if New(nil).UsesCLI() {
		t.Error("glab is absent but the CLI transport was chosen")
	}
}

// Every instance serves v4 under itself, so a self-hosted one is reached by its
// own hostname rather than through gitlab.com.
func TestTheAPIBaseFollowsTheHost(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if base := New(nil).baseURL; base != "https://gitlab.com/api/v4" {
		t.Errorf("gitlab.com base = %q", base)
	}
	selfHosted, err := NewForHost("git.acme.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if base := selfHosted.baseURL; base != "https://git.acme.example/api/v4" {
		t.Errorf("self-hosted base = %q", base)
	}
}

// A nested group is one URL-encoded path segment, and the encoding has to survive
// the HTTP transport as well as the CLI one — an unencoded path addresses a
// different endpoint entirely.
func TestTheHTTPPathEncodesANestedProject(t *testing.T) {
	adapter, server := httpAdapter(t)
	nested := "acme/platform/tools/state"
	server.mutex.Lock()
	scenario := forgetest.Reviewed()
	scenario.Repository.Name = nested
	server.scenario = scenario
	server.mutex.Unlock()
	if _, err := adapter.Repository(context.Background(),
		forge.Repository{Name: nested, WorkingDirectory: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	var found bool
	for _, uri := range server.requested {
		if strings.Contains(uri, "projects/acme%2Fplatform%2Ftools%2Fstate") {
			found = true
		}
	}
	if !found {
		t.Errorf("requested %v, want the project path encoded", server.requested)
	}
}

// The merge_base query carries two refs. They have to arrive as two values, not
// one, or the API answers about something else.
func TestTheHTTPPathSendsBothRefs(t *testing.T) {
	adapter, server := httpAdapter(t)
	server.mutex.Lock()
	server.scenario = forgetest.Reviewed()
	server.mutex.Unlock()
	if _, err := adapter.RevisionAncestry(context.Background(),
		forge.Repository{Name: forgetest.Repository}, forgetest.Revision, "main"); err != nil {
		t.Fatal(err)
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	var seen string
	for _, uri := range server.requested {
		if strings.Contains(uri, "merge_base") {
			seen = uri
		}
	}
	if !strings.Contains(seen, forgetest.Revision) || !strings.Contains(seen, "main") {
		t.Errorf("merge_base requested as %q, want both refs", seen)
	}
	if strings.Count(seen, "refs") != 2 {
		t.Errorf("merge_base requested as %q, want two refs parameters", seen)
	}
}
