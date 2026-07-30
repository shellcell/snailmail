// Package githubforge reads review evidence from GitHub.
//
// Through the gh CLI where it is installed, because then the vendor tool owns
// authentication and host resolution and snailmail never handles a token. Where
// it is not, the same endpoints are read over HTTP with a token from a broker —
// otherwise a runner without gh could not run a PR gate at all, and would fail as
// though GitHub were unreachable.
//
// The transport is chosen once, at construction, so a gate cannot read one
// question through one path and the next through another.
package githubforge

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/shellcell/snailmail/adapters/forge/forgeio"
	"github.com/shellcell/snailmail/forge"
)

// Adapter reads GitHub review evidence.
type Adapter struct {
	hostname string
	// cli is whether gh was found when this adapter was built.
	cli    bool
	broker forge.TokenBroker
	// baseURL is where the REST API lives, resolved once alongside the transport.
	baseURL string
}

// New returns an adapter for github.com.
//
// broker supplies a token for the HTTP path and is unused when gh is installed.
// Nil is legitimate: a public state repository is readable without one.
func New(broker forge.TokenBroker) *Adapter {
	return &Adapter{hostname: "github.com", cli: haveCLI(), broker: broker, baseURL: apiBaseFor("github.com")}
}

// NewForHost returns an adapter for a GitHub Enterprise hostname.
func NewForHost(hostname string, broker forge.TokenBroker) (*Adapter, error) {
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n/") {
		return nil, errors.New("GitHub hostname is invalid")
	}
	return &Adapter{hostname: hostname, cli: haveCLI(), broker: broker, baseURL: apiBaseFor(hostname)}, nil
}

// haveCLI is resolved once per adapter rather than per request, so a gh that
// appears or disappears mid-operation cannot change transport halfway through.
func haveCLI() bool {
	_, err := exec.LookPath("gh")
	return err == nil
}

func (adapter *Adapter) Name() string { return "github" }

func (adapter *Adapter) Repository(ctx context.Context, repository forge.Repository) (forge.RepositoryInfo, error) {
	if err := checkReference(repository.Name); err != nil {
		return forge.RepositoryInfo{}, err
	}
	var response struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := adapter.api(ctx, repository, &response, "repos/"+repository.Name); err != nil {
		return forge.RepositoryInfo{}, err
	}
	if response.FullName != repository.Name || response.DefaultBranch == "" {
		return forge.RepositoryInfo{}, fmt.Errorf("%w: could not identify repository %q", forge.ErrUnavailable, repository.Name)
	}
	return forge.RepositoryInfo{Name: response.FullName, DefaultBranch: response.DefaultBranch}, nil
}

func (adapter *Adapter) PullRequestsForRevision(ctx context.Context, repository forge.Repository, revision string) ([]forge.PullRequest, error) {
	if err := checkReference(repository.Name); err != nil {
		return nil, err
	}
	var response []struct {
		Number   int     `json:"number"`
		MergedAt *string `json:"merged_at"`
		Base     struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := adapter.api(ctx, repository, &response,
		"repos/"+repository.Name+"/commits/"+revision+"/pulls", "-H", "Accept: application/vnd.github+json"); err != nil {
		return nil, err
	}
	pullRequests := make([]forge.PullRequest, 0, len(response))
	for _, item := range response {
		pullRequests = append(pullRequests, forge.PullRequest{
			Number:     item.Number,
			Merged:     item.MergedAt != nil && *item.MergedAt != "",
			BaseBranch: item.Base.Ref,
		})
	}
	return pullRequests, nil
}

func (adapter *Adapter) RevisionAncestry(ctx context.Context, repository forge.Repository, revision, branch string) (forge.Ancestry, error) {
	if err := checkReference(repository.Name); err != nil {
		return forge.Ancestry{}, err
	}
	var response struct {
		Status          string `json:"status"`
		MergeBaseCommit struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	if err := adapter.api(ctx, repository, &response,
		"repos/"+repository.Name+"/compare/"+revision+"..."+branch); err != nil {
		return forge.Ancestry{}, err
	}
	// "ahead" means the branch has moved on from the revision and "identical"
	// means it is exactly there; both put the revision on the branch.
	return forge.Ancestry{
		Contains:  response.Status == "ahead" || response.Status == "identical",
		MergeBase: response.MergeBaseCommit.SHA,
	}, nil
}

func (adapter *Adapter) api(ctx context.Context, repository forge.Repository, target any, endpoint string, extra ...string) error {
	if adapter.cli {
		arguments := append([]string{"api", "--hostname", adapter.hostname}, extra...)
		return forgeio.ReadJSON(ctx, forgeio.Request{
			Binary:           "gh",
			Arguments:        append(arguments, endpoint),
			WorkingDirectory: repository.WorkingDirectory,
			Endpoint:         endpoint,
		}, target)
	}
	return forgeio.HTTPClient{
		BaseURL: adapter.apiBase(),
		Broker:  adapter.broker,
		Scope: forge.TokenScope{
			Provider: forge.ProviderGitHub, Host: adapter.hostname, Repository: repository.Name,
		},
		// What gh sends for every call, so the HTTP path asks the same question
		// rather than relying on whatever the API defaults to this year.
		Headers: map[string]string{"Accept": "application/vnd.github+json"},
	}.Get(ctx, endpoint, target)
}

// apiBase is where this adapter's REST API lives.
func (adapter *Adapter) apiBase() string { return adapter.baseURL }

// apiBaseFor resolves the API root. github.com serves it from its own host; an
// Enterprise instance serves it under the instance, and sending Enterprise
// requests to api.github.com would ask a different organisation about a
// repository with the same name.
func apiBaseFor(hostname string) string {
	if hostname == "github.com" {
		return "https://api.github.com"
	}
	return "https://" + hostname + "/api/v3"
}

// UsesCLI reports which transport was chosen, for tests and for a diagnostic that
// can tell a missing gh from an unreachable GitHub.
func (adapter *Adapter) UsesCLI() bool { return adapter.cli }

// Resolver selects this adapter for every repository.
type Resolver struct{ adapter *Adapter }

// NewResolver returns a resolver bound to github.com.
func NewResolver() *Resolver { return &Resolver{adapter: New(nil)} }

func (resolver *Resolver) Resolve(context.Context, forge.Repository) (forge.Forge, error) {
	return resolver.adapter, nil
}

// checkReference refuses a name that is not how GitHub addresses a repository.
//
// It matters more on the HTTP transport, where the name is interpolated into a
// URL path and a crafted one could address a different endpoint; gh would have
// rejected it. Checked on both paths so the two cannot disagree about what is
// acceptable.
func checkReference(name string) error {
	if !forge.ValidRepositoryReference(forge.ProviderGitHub, name) {
		return fmt.Errorf("%w: %q is not an owner/name repository", forge.ErrUnavailable, name)
	}
	return nil
}
