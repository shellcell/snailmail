// Package githubforge reads review evidence from GitHub through the gh CLI,
// which owns authentication and host resolution.
package githubforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/shellcell/snailmail/forge"
)

// maxResponseSize bounds a provider response. Review metadata is small, and an
// unbounded read would let a compromised or misconfigured endpoint exhaust
// memory during the one step that authorizes publication.
const maxResponseSize = 4 << 20

// Adapter reads GitHub review evidence.
type Adapter struct {
	hostname string
}

// New returns an adapter for github.com.
func New() *Adapter { return &Adapter{hostname: "github.com"} }

// NewForHost returns an adapter for a GitHub Enterprise hostname.
func NewForHost(hostname string) (*Adapter, error) {
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n/") {
		return nil, errors.New("GitHub hostname is invalid")
	}
	return &Adapter{hostname: hostname}, nil
}

func (adapter *Adapter) Name() string { return "github" }

func (adapter *Adapter) Repository(ctx context.Context, repository forge.Repository) (forge.RepositoryInfo, error) {
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
	arguments := append([]string{"api", "--hostname", adapter.hostname}, extra...)
	command := exec.CommandContext(ctx, "gh", append(arguments, endpoint)...)
	command.Dir = repository.WorkingDirectory
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("%w: gh api %s", forge.ErrUnavailable, endpoint)
	}
	if len(output) > maxResponseSize {
		return fmt.Errorf("%w: response from %s exceeds the read limit", forge.ErrUnavailable, endpoint)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid response from %s", forge.ErrUnavailable, endpoint)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data in response from %s", forge.ErrUnavailable, endpoint)
	}
	return nil
}

// Resolver selects this adapter for every repository.
type Resolver struct{ adapter *Adapter }

// NewResolver returns a resolver bound to github.com.
func NewResolver() *Resolver { return &Resolver{adapter: New()} }

func (resolver *Resolver) Resolve(context.Context, forge.Repository) (forge.Forge, error) {
	return resolver.adapter, nil
}
