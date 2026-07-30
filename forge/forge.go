// Package forge is the port through which snailmail reads review evidence
// from a code-hosting provider.
//
// The PR gate asks exactly three questions: what is this repository's default
// branch, which pull requests contain a revision, and is that revision an
// ancestor of the default branch. Nothing here writes, because review evidence
// is observed rather than produced.
//
// An adapter that cannot answer must say so. ARCHITECTURE §18 requires that an
// unavailable provider API render unknown and never silently authorize a
// mutation, so every failure here is an error and none is a permissive default.
package forge

import (
	"context"
	"errors"
)

// ErrUnavailable reports that the provider could not be reached or did not
// answer. It never means the revision failed review, only that review state is
// unknown, and a gate must refuse either way.
var ErrUnavailable = errors.New("forge is unavailable")

// Repository identifies a repository on a provider.
type Repository struct {
	// Name is the provider-native identity, such as "owner/name".
	Name string
	// Provider names the service, as recorded in the manifest. Empty means
	// DefaultProvider — a workspace written before the field existed.
	Provider string
	// Host is the instance to ask, for a self-hosted or Enterprise deployment.
	// Empty means the provider's own, which is what DefaultHost reports.
	Host string
	// WorkingDirectory is the local checkout a provider CLI may need for
	// credential and host resolution.
	WorkingDirectory string
}

// RepositoryInfo is what the gate needs to know about the repository itself.
type RepositoryInfo struct {
	// Name must equal the requested name; a provider answering about a
	// different repository is a redirect the gate must not follow.
	Name string
	// DefaultBranch is the branch review must land on.
	DefaultBranch string
}

// PullRequest is one review of a revision.
type PullRequest struct {
	Number int
	// Merged reports whether the pull request landed.
	Merged bool
	// BaseBranch is the branch it merged into.
	BaseBranch string
}

// Ancestry describes how a revision relates to a branch.
type Ancestry struct {
	// Contains reports whether the branch contains the revision.
	Contains bool
	// MergeBase is the common ancestor, which must be the revision itself for
	// the revision to be part of the branch rather than merely comparable.
	MergeBase string
}

// Forge reads review evidence for one provider.
type Forge interface {
	// Name identifies the provider, for error messages and configuration.
	Name() string
	// Repository resolves a repository's review-relevant metadata.
	Repository(ctx context.Context, repository Repository) (RepositoryInfo, error)
	// PullRequestsForRevision lists the pull requests containing a revision.
	PullRequestsForRevision(ctx context.Context, repository Repository, revision string) ([]PullRequest, error)
	// RevisionAncestry reports how a revision relates to a branch.
	RevisionAncestry(ctx context.Context, repository Repository, revision, branch string) (Ancestry, error)
}

// Resolver selects the provider for a repository.
type Resolver interface {
	Resolve(ctx context.Context, repository Repository) (Forge, error)
}
