// Package plainforge is the adapter for a workspace whose Git remote is not a
// forge with a review API — a bare repository, a self-hosted mirror, a local
// path.
//
// It answers every question with ErrUnavailable rather than a permissive
// default. A PR gate configured against a plain remote therefore refuses to
// authorize, which is the required outcome: review evidence that cannot be read
// is unknown, and ARCHITECTURE §18 forbids collapsing unknown into success.
package plainforge

import (
	"context"
	"fmt"

	"github.com/shellcell/snailmail/forge"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (*Adapter) Name() string { return "plain" }

func (*Adapter) Repository(_ context.Context, repository forge.Repository) (forge.RepositoryInfo, error) {
	return forge.RepositoryInfo{}, unsupported(repository)
}

func (*Adapter) PullRequestsForRevision(_ context.Context, repository forge.Repository, _ string) ([]forge.PullRequest, error) {
	return nil, unsupported(repository)
}

func (*Adapter) RevisionAncestry(_ context.Context, repository forge.Repository, _, _ string) (forge.Ancestry, error) {
	return forge.Ancestry{}, unsupported(repository)
}

func unsupported(repository forge.Repository) error {
	return fmt.Errorf("%w: %q has no forge review API, so merged-PR evidence cannot be read",
		forge.ErrUnavailable, repository.Name)
}

// Resolver selects this adapter for every repository.
type Resolver struct{ adapter *Adapter }

func NewResolver() *Resolver { return &Resolver{adapter: New()} }

func (resolver *Resolver) Resolve(context.Context, forge.Repository) (forge.Forge, error) {
	return resolver.adapter, nil
}
