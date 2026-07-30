// Package gitlabforge reads review evidence from GitLab.
//
// Through the glab CLI where it is installed, because then the vendor tool owns
// authentication and host resolution and snailmail never handles a token. Where it
// is not, the same endpoints are read over HTTP with a token from a broker, so a
// runner without glab can still run a PR gate. The transport is chosen once, at
// construction.
//
// GitLab answers the port's three questions more directly than GitHub does. The
// merge_base endpoint returns the common ancestor itself, so containment and
// merge base come from one read rather than from a comparison status that has to
// be interpreted — there is no equivalent of deciding what "ahead" means.
//
// Two differences from GitHub shape this adapter. A project is addressed by its
// full path, URL-encoded, because groups nest; and a merge request reports a
// state rather than a merge timestamp, so "closed" and "merged" are distinct
// values of one field rather than the presence or absence of another.
package gitlabforge

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	"github.com/shellcell/snailmail/adapters/forge/forgeio"
	"github.com/shellcell/snailmail/forge"
)

// Adapter reads GitLab review evidence.
type Adapter struct {
	hostname string
	cli      bool
	broker   forge.TokenBroker
	// baseURL is where the REST API lives, resolved once alongside the transport.
	baseURL string
}

// New returns an adapter for gitlab.com.
//
// broker supplies a token for the HTTP path and is unused when glab is installed.
// Nil is legitimate: a public project is readable without one.
func New(broker forge.TokenBroker) *Adapter {
	host := forge.DefaultHost(forge.ProviderGitLab)
	return &Adapter{hostname: host, cli: haveCLI(), broker: broker, baseURL: apiBaseFor(host)}
}

// NewForHost returns an adapter for a self-hosted GitLab instance.
func NewForHost(hostname string, broker forge.TokenBroker) (*Adapter, error) {
	if !forge.ValidHost(hostname) {
		return nil, fmt.Errorf("GitLab hostname %q is invalid", hostname)
	}
	return &Adapter{hostname: hostname, cli: haveCLI(), broker: broker, baseURL: apiBaseFor(hostname)}, nil
}

// haveCLI is resolved once per adapter rather than per request, so a glab that
// appears or disappears mid-operation cannot change transport halfway through.
func haveCLI() bool {
	_, err := exec.LookPath("glab")
	return err == nil
}

func (adapter *Adapter) Name() string { return forge.ProviderGitLab }

func (adapter *Adapter) Repository(ctx context.Context, repository forge.Repository) (forge.RepositoryInfo, error) {
	var response struct {
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
	}
	if err := adapter.api(ctx, repository, &response, "projects/"+projectID(repository.Name)); err != nil {
		return forge.RepositoryInfo{}, err
	}
	// Compared against the requested path rather than trusted: a project that has
	// been moved answers about its new location, and following that would read
	// review evidence from a repository nobody configured.
	if response.PathWithNamespace != repository.Name || response.DefaultBranch == "" {
		return forge.RepositoryInfo{}, fmt.Errorf("%w: could not identify project %q", forge.ErrUnavailable, repository.Name)
	}
	return forge.RepositoryInfo{Name: response.PathWithNamespace, DefaultBranch: response.DefaultBranch}, nil
}

func (adapter *Adapter) PullRequestsForRevision(ctx context.Context, repository forge.Repository, revision string) ([]forge.PullRequest, error) {
	if !validRevision(revision) {
		return nil, fmt.Errorf("%w: %q is not a revision", forge.ErrUnavailable, revision)
	}
	var response []struct {
		// IID is the per-project number a merge request is known by. ID is a
		// global counter that means nothing to anyone reading a project.
		IID          int    `json:"iid"`
		State        string `json:"state"`
		TargetBranch string `json:"target_branch"`
	}
	endpoint := "projects/" + projectID(repository.Name) + "/repository/commits/" + url.PathEscape(revision) + "/merge_requests"
	if err := adapter.api(ctx, repository, &response, endpoint); err != nil {
		return nil, err
	}
	pullRequests := make([]forge.PullRequest, 0, len(response))
	for _, item := range response {
		// A merge request is "opened", "closed", "merged" or "locked". Only one of
		// those is review that landed, and "closed" is review that was rejected.
		pullRequests = append(pullRequests, forge.PullRequest{
			Number:     item.IID,
			Merged:     item.State == "merged",
			BaseBranch: item.TargetBranch,
		})
	}
	return pullRequests, nil
}

func (adapter *Adapter) RevisionAncestry(ctx context.Context, repository forge.Repository, revision, branch string) (forge.Ancestry, error) {
	if !validRevision(revision) || branch == "" || strings.ContainsAny(branch, " \t\r\n") {
		return forge.Ancestry{}, fmt.Errorf("%w: cannot compare %q against %q", forge.ErrUnavailable, revision, branch)
	}
	var response struct {
		ID string `json:"id"`
	}
	endpoint := "projects/" + projectID(repository.Name) + "/repository/merge_base" +
		"?refs[]=" + url.QueryEscape(revision) + "&refs[]=" + url.QueryEscape(branch)
	if err := adapter.api(ctx, repository, &response, endpoint); err != nil {
		return forge.Ancestry{}, err
	}
	if response.ID == "" {
		return forge.Ancestry{}, fmt.Errorf("%w: no merge base for %s and %s", forge.ErrUnavailable, revision, branch)
	}
	// The merge base of a revision and a branch is the revision exactly when the
	// branch contains it. Both fields the gate checks come from this one value, so
	// there is no comparison status to interpret and no direction to get backwards.
	return forge.Ancestry{Contains: response.ID == revision, MergeBase: response.ID}, nil
}

// projectID is how the API addresses a project: its full path, URL-encoded,
// because a group can nest and the path therefore contains slashes.
func projectID(name string) string {
	return url.PathEscape(name)
}

// validRevision keeps a value that is not a revision from being interpolated
// into an endpoint. The gate supplies a git revision, but this is the boundary
// where that stops being an assumption.
func validRevision(revision string) bool {
	if len(revision) < 7 || len(revision) > 64 {
		return false
	}
	for _, character := range revision {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func (adapter *Adapter) api(ctx context.Context, repository forge.Repository, target any, endpoint string) error {
	if adapter.cli {
		return forgeio.ReadJSON(ctx, forgeio.Request{
			Binary:           "glab",
			Arguments:        []string{"api", "--hostname", adapter.hostname, endpoint},
			WorkingDirectory: repository.WorkingDirectory,
			Endpoint:         endpoint,
		}, target)
	}
	return forgeio.HTTPClient{
		BaseURL: adapter.baseURL,
		Broker:  adapter.broker,
		Scope: forge.TokenScope{
			Provider: forge.ProviderGitLab, Host: adapter.hostname, Repository: repository.Name,
		},
	}.Get(ctx, endpoint, target)
}

// apiBaseFor resolves the API root. Every instance serves v4 under itself; there
// is no separate API host the way github.com has one.
func apiBaseFor(hostname string) string { return "https://" + hostname + "/api/v4" }

// UsesCLI reports which transport was chosen, for tests and for a diagnostic that
// can tell a missing glab from an unreachable GitLab.
func (adapter *Adapter) UsesCLI() bool { return adapter.cli }

// Resolver selects this adapter for every repository.
type Resolver struct{ adapter *Adapter }

// NewResolver returns a resolver bound to gitlab.com.
func NewResolver() *Resolver { return &Resolver{adapter: New(nil)} }

func (resolver *Resolver) Resolve(context.Context, forge.Repository) (forge.Forge, error) {
	return resolver.adapter, nil
}

// The port is satisfied at compile time, not at wiring time.
var _ forge.Forge = (*Adapter)(nil)
