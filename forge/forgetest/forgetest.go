// Package forgetest is the conformance suite every forge adapter must pass.
//
// The forge port is the PR gate's only source of review evidence, so an adapter
// that translates a provider response wrongly does not fail loudly — it reports
// that an unreviewed revision was reviewed, or refuses one that was. The gate's
// own reasoning is tested against a stub in package gate; what is tested here is
// the translation, which is the part each provider gets to be different about.
//
// The suite lives outside package forge so that an adapter can import it without
// the port importing its adapters. It asserts port semantics only. How a
// provider misbehaves — a truncated body, a rename redirect, an oversized
// response — is adapter-specific and belongs in the adapter's own tests.
package forgetest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
)

// Repository is the repository every conformance case asks about.
const Repository = "shellcell/state"

// Revision is the revision every conformance case asks about.
var Revision = strings.Repeat("a", 40)

// Scenario is what a provider is made to answer for one case.
type Scenario struct {
	// Repository is the identity and default branch the provider reports. A Name
	// other than Repository stands for a provider answering about a different
	// repository, which an adapter must refuse rather than follow.
	Repository forge.RepositoryInfo
	// PullRequests are the reviews the provider reports for Revision.
	PullRequests []forge.PullRequest
	// Ancestry is how the provider relates Revision to the default branch.
	Ancestry forge.Ancestry
	// Unavailable makes every provider read fail, which must render unknown
	// rather than either answer.
	Unavailable bool
}

// Reviewed is the scenario where the revision was merged through a review and is
// still reachable from the default branch — the one case that authorizes.
func Reviewed() Scenario {
	return Scenario{
		Repository:   forge.RepositoryInfo{Name: Repository, DefaultBranch: "main"},
		PullRequests: []forge.PullRequest{{Number: 12, Merged: true, BaseBranch: "main"}},
		Ancestry:     forge.Ancestry{Contains: true, MergeBase: Revision},
	}
}

// Conformance asserts the port's required behaviour against one adapter.
//
// arrange must make the provider answer the given scenario. It is called before
// each case, and may use t for cleanup.
func Conformance(t *testing.T, adapter forge.Forge, arrange func(*testing.T, Scenario)) {
	t.Helper()
	ctx := context.Background()
	target := forge.Repository{Name: Repository, WorkingDirectory: t.TempDir()}

	t.Run("names itself", func(t *testing.T) {
		if adapter.Name() == "" {
			t.Error("an adapter with no name cannot be named in a configuration or an error")
		}
	})

	t.Run("reads the default branch", func(t *testing.T) {
		arrange(t, Reviewed())
		info, err := adapter.Repository(ctx, target)
		if err != nil {
			t.Fatalf("reading a repository failed: %v", err)
		}
		if info.Name != Repository || info.DefaultBranch != "main" {
			t.Errorf("got %+v, want %q on main", info, Repository)
		}
	})

	// A provider that answers about a different repository is a redirect — a
	// rename, a fork, a case-folded near-miss. Following it would read review
	// evidence from a repository nobody configured.
	t.Run("refuses a different repository", func(t *testing.T) {
		scenario := Reviewed()
		scenario.Repository.Name = "someone-else/state"
		arrange(t, scenario)
		if _, err := adapter.Repository(ctx, target); err == nil {
			t.Error("a provider answering about another repository was accepted")
		}
	})

	t.Run("reads a merged review", func(t *testing.T) {
		arrange(t, Reviewed())
		pullRequests, err := adapter.PullRequestsForRevision(ctx, target, Revision)
		if err != nil {
			t.Fatalf("reading reviews failed: %v", err)
		}
		if len(pullRequests) != 1 {
			t.Fatalf("got %d reviews, want 1: %+v", len(pullRequests), pullRequests)
		}
		if got := pullRequests[0]; got.Number != 12 || !got.Merged || got.BaseBranch != "main" {
			t.Errorf("got %+v, want review 12 merged into main", got)
		}
	})

	// Closed and merged are different outcomes, and only one of them is review
	// that landed. An adapter reading a provider's "closed" as merged would
	// authorize a revision whose review was rejected.
	t.Run("distinguishes closed from merged", func(t *testing.T) {
		scenario := Reviewed()
		scenario.PullRequests = []forge.PullRequest{{Number: 12, Merged: false, BaseBranch: "main"}}
		arrange(t, scenario)
		pullRequests, err := adapter.PullRequestsForRevision(ctx, target, Revision)
		if err != nil {
			t.Fatalf("reading reviews failed: %v", err)
		}
		if len(pullRequests) != 1 || pullRequests[0].Merged {
			t.Errorf("got %+v, want an unmerged review", pullRequests)
		}
	})

	t.Run("reports no review as none rather than as an error", func(t *testing.T) {
		scenario := Reviewed()
		scenario.PullRequests = nil
		arrange(t, scenario)
		pullRequests, err := adapter.PullRequestsForRevision(ctx, target, Revision)
		if err != nil {
			t.Fatalf("a revision with no review read as unavailable: %v", err)
		}
		if len(pullRequests) != 0 {
			t.Errorf("got %+v, want none", pullRequests)
		}
	})

	// Containment and merge base are read separately because the gate checks
	// both: a branch can contain a revision's history without containing the
	// revision. An adapter that inverts the comparison direction reports a
	// revision as on the branch when the branch is behind it.
	t.Run("reads containment and merge base", func(t *testing.T) {
		arrange(t, Reviewed())
		ancestry, err := adapter.RevisionAncestry(ctx, target, Revision, "main")
		if err != nil {
			t.Fatalf("reading ancestry failed: %v", err)
		}
		if !ancestry.Contains || ancestry.MergeBase != Revision {
			t.Errorf("got %+v, want the revision contained and its own merge base", ancestry)
		}
	})

	t.Run("reads a revision that is not on the branch", func(t *testing.T) {
		scenario := Reviewed()
		scenario.Ancestry = forge.Ancestry{Contains: false, MergeBase: strings.Repeat("b", 40)}
		arrange(t, scenario)
		ancestry, err := adapter.RevisionAncestry(ctx, target, Revision, "main")
		if err != nil {
			t.Fatalf("reading ancestry failed: %v", err)
		}
		if ancestry.Contains {
			t.Errorf("got %+v, want the revision reported as not contained", ancestry)
		}
	})

	// ARCHITECTURE §18: an unavailable provider renders unknown and must never
	// resolve to either answer. Every read has to fail, and fail recognisably,
	// or the gate cannot tell "not reviewed" from "could not ask".
	t.Run("reports unavailable rather than an answer", func(t *testing.T) {
		arrange(t, Scenario{Unavailable: true})
		if _, err := adapter.Repository(ctx, target); !errors.Is(err, forge.ErrUnavailable) {
			t.Errorf("repository read error = %v, want ErrUnavailable", err)
		}
		if _, err := adapter.PullRequestsForRevision(ctx, target, Revision); !errors.Is(err, forge.ErrUnavailable) {
			t.Errorf("review read error = %v, want ErrUnavailable", err)
		}
		if _, err := adapter.RevisionAncestry(ctx, target, Revision, "main"); !errors.Is(err, forge.ErrUnavailable) {
			t.Errorf("ancestry read error = %v, want ErrUnavailable", err)
		}
	})

	// A cancelled context must not be reported as a provider answer either. An
	// apply that was interrupted has not been authorized.
	t.Run("reports a cancelled read as unavailable", func(t *testing.T) {
		arrange(t, Reviewed())
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := adapter.Repository(cancelled, target); err == nil {
			t.Error("a cancelled read returned an answer")
		}
	})
}
