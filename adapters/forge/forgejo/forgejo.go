// Package forgejoforge reads review evidence from Forgejo and Gitea.
//
// One adapter for two providers: Forgejo is a fork of Gitea and its API is the
// same, so the difference is the name an operator writes in the manifest and the
// name that appears in an error, not the requests.
//
// Unlike the GitHub and GitLab adapters, this one speaks HTTP rather than
// delegating to a vendor CLI. There is no `tea api` passthrough to delegate to,
// and going through a CLI would be wrong here anyway: the per-commit endpoint
// answers 404 for a commit with no pull request, and a wrapper that renders every
// failure alike cannot tell that from a network fault — one means the revision was
// not reviewed, the other that review state is unknown, and the gate owes an
// operator the difference.
//
// Two departures from the other adapters, both established against a live
// instance rather than assumed:
//
//   - A merged pull request reports merged=true with state "closed". Reading
//     state, the way GitLab requires, would call every merged review unmerged.
//   - There is no merge-base endpoint and compare returns no status, so
//     containment comes from the reverse comparison being empty. That is the same
//     proposition as merge_base(revision, branch) == revision.
package forgejoforge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/shellcell/snailmail/adapters/forge/forgeio"
	"github.com/shellcell/snailmail/forge"
)

// Adapter reads Forgejo or Gitea review evidence.
type Adapter struct {
	provider string
	baseURL  string
	broker   forge.TokenBroker
}

// NewForHost returns an adapter for one instance.
//
// There is no host-less constructor: neither provider has a hostname of its own,
// so an instance is always something an operator runs and the manifest always has
// to say which one.
//
// broker may be nil, which reads without authenticating. That is enough for a
// public state repository and is the only configuration that needs no secret at
// all; a private one needs a broker, and says so when it gets a 404 for a
// repository it cannot see.
func NewForHost(provider, hostname string, broker forge.TokenBroker) (*Adapter, error) {
	if provider != forge.ProviderForgejo && provider != forge.ProviderGitea {
		return nil, fmt.Errorf("%q is not Forgejo or Gitea", provider)
	}
	if !forge.ValidHost(hostname) {
		return nil, fmt.Errorf("%s hostname %q is invalid", provider, hostname)
	}
	return &Adapter{provider: provider, baseURL: "https://" + hostname + "/api/v1", broker: broker}, nil
}

func (adapter *Adapter) Name() string { return adapter.provider }

func (adapter *Adapter) Repository(ctx context.Context, repository forge.Repository) (forge.RepositoryInfo, error) {
	owner, name, err := adapter.split(repository.Name)
	if err != nil {
		return forge.RepositoryInfo{}, err
	}
	var response struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := adapter.get(ctx, repository, "repos/"+owner+"/"+name, &response); err != nil {
		return forge.RepositoryInfo{}, adapter.unavailable(err)
	}
	// Compared against the request rather than trusted: a renamed repository
	// answers about its new name, and following that would read review evidence
	// from a repository nobody configured.
	if response.FullName != repository.Name || response.DefaultBranch == "" {
		return forge.RepositoryInfo{}, fmt.Errorf("%w: could not identify repository %q", forge.ErrUnavailable, repository.Name)
	}
	return forge.RepositoryInfo{Name: response.FullName, DefaultBranch: response.DefaultBranch}, nil
}

func (adapter *Adapter) PullRequestsForRevision(ctx context.Context, repository forge.Repository, revision string) ([]forge.PullRequest, error) {
	owner, name, err := adapter.split(repository.Name)
	if err != nil {
		return nil, err
	}
	if !validRevision(revision) {
		return nil, fmt.Errorf("%w: %q is not a revision", forge.ErrUnavailable, revision)
	}
	// Singular: the endpoint answers with the one pull request a commit arrived
	// through, not a list.
	var response struct {
		Number int    `json:"number"`
		Merged bool   `json:"merged"`
		State  string `json:"state"`
		Base   struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	err = adapter.get(ctx, repository, "repos/"+owner+"/"+name+"/commits/"+url.PathEscape(revision)+"/pull", &response)
	if errors.Is(err, forgeio.ErrNotFound) {
		// A commit with no pull request. That is an answer — nothing reviewed this
		// revision — and reporting it as unavailable would tell an operator to
		// check their credentials for a revision that simply was not reviewed.
		return nil, nil
	}
	if err != nil {
		return nil, adapter.unavailable(err)
	}
	if response.Number <= 0 {
		return nil, fmt.Errorf("%w: review for %s has no number", forge.ErrUnavailable, revision)
	}
	// merged is the field, not state. A merged pull request here reports
	// merged=true and state "closed", so reading state would call every merged
	// review unmerged and refuse every publication.
	return []forge.PullRequest{{
		Number: response.Number, Merged: response.Merged, BaseBranch: response.Base.Ref,
	}}, nil
}

func (adapter *Adapter) RevisionAncestry(ctx context.Context, repository forge.Repository, revision, branch string) (forge.Ancestry, error) {
	owner, name, err := adapter.split(repository.Name)
	if err != nil {
		return forge.Ancestry{}, err
	}
	if !validRevision(revision) || !validBranch(branch) {
		return forge.Ancestry{}, fmt.Errorf("%w: cannot compare %q against %q", forge.ErrUnavailable, revision, branch)
	}
	// compare/{base}...{head} lists what is reachable from head and not from base.
	// Asking it the other way round — base the branch, head the revision — is
	// empty exactly when the branch already contains the revision. A slash in a
	// branch name passes through, because the route takes the whole remainder of
	// the path.
	var response struct {
		TotalCommits int `json:"total_commits"`
	}
	endpoint := "repos/" + owner + "/" + name + "/compare/" + branch + "..." + url.PathEscape(revision)
	if err := adapter.get(ctx, repository, endpoint, &response); err != nil {
		return forge.Ancestry{}, adapter.unavailable(err)
	}
	if response.TotalCommits < 0 {
		return forge.Ancestry{}, fmt.Errorf("%w: comparison of %s against %s is not a count", forge.ErrUnavailable, revision, branch)
	}
	if response.TotalCommits != 0 {
		// Reachable from the revision but not from the branch, so the revision is
		// not on it. There is no merge base to report: the API does not give one,
		// and inventing one the gate might compare against would be worse than
		// leaving it empty, which cannot pass its check by accident.
		return forge.Ancestry{Contains: false}, nil
	}
	// Nothing is reachable from the revision that the branch does not already
	// have, which is what merge_base(revision, branch) == revision means. Derived
	// rather than read, because there is no endpoint that reports it.
	return forge.Ancestry{Contains: true, MergeBase: revision}, nil
}

func (adapter *Adapter) get(ctx context.Context, repository forge.Repository, endpoint string, target any) error {
	client := forgeio.HTTPClient{
		BaseURL: adapter.baseURL,
		Broker:  adapter.broker,
		Scope: forge.TokenScope{
			Provider: adapter.provider, Host: adapter.host(), Repository: repository.Name,
		},
	}
	return client.Get(ctx, endpoint, target)
}

func (adapter *Adapter) host() string {
	trimmed := strings.TrimPrefix(adapter.baseURL, "https://")
	host, _, _ := strings.Cut(trimmed, "/")
	return host
}

// split separates owner from name. Both providers address a repository as exactly
// two path segments — unlike GitLab, groups do not nest — so a reference with
// more is a misconfiguration rather than something to pass through.
func (adapter *Adapter) split(reference string) (string, string, error) {
	if !forge.ValidRepositoryReference(adapter.provider, reference) {
		return "", "", fmt.Errorf("%w: %q is not how %s addresses a repository",
			forge.ErrUnavailable, reference, adapter.provider)
	}
	owner, name, _ := strings.Cut(reference, "/")
	return url.PathEscape(owner), url.PathEscape(name), nil
}

// unavailable keeps a not-found from escaping as itself. Only a caller that knows
// what a 404 means for the endpoint it asked about may act on one, and every
// endpoint here except the per-commit one treats it as unknown.
func (adapter *Adapter) unavailable(err error) error {
	if errors.Is(err, forgeio.ErrNotFound) {
		return fmt.Errorf("%w: %s", forge.ErrUnavailable, err.Error())
	}
	return err
}

// validRevision keeps a value that is not a revision from being interpolated into
// an endpoint. The gate supplies a git revision, but the adapter boundary is
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

// validBranch admits a slash, which the compare route accepts, and refuses what
// would change the shape of the request.
func validBranch(branch string) bool {
	return branch != "" && len(branch) <= 255 &&
		!strings.ContainsAny(branch, " \t\r\n?#%") && !strings.Contains(branch, "..")
}

// The port is satisfied at compile time, not at wiring time.
var _ forge.Forge = (*Adapter)(nil)
