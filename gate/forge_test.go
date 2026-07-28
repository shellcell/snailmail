package gate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
)

// stubForge answers exactly what a test sets, so the gate's own reasoning can
// be exercised without a provider.
type stubForge struct {
	info         forge.RepositoryInfo
	infoErr      error
	pullRequests []forge.PullRequest
	pullErr      error
	ancestry     forge.Ancestry
	ancestryErr  error
}

func (*stubForge) Name() string { return "stub" }
func (stub *stubForge) Repository(context.Context, forge.Repository) (forge.RepositoryInfo, error) {
	return stub.info, stub.infoErr
}
func (stub *stubForge) PullRequestsForRevision(context.Context, forge.Repository, string) ([]forge.PullRequest, error) {
	return stub.pullRequests, stub.pullErr
}
func (stub *stubForge) RevisionAncestry(context.Context, forge.Repository, string, string) (forge.Ancestry, error) {
	return stub.ancestry, stub.ancestryErr
}

type stubResolver struct{ forge *stubForge }

func (resolver *stubResolver) Resolve(context.Context, forge.Repository) (forge.Forge, error) {
	return resolver.forge, nil
}

func authorizeWith(t *testing.T, stub *stubForge) error {
	t.Helper()
	evaluator := NewDefaultEvaluator("", &stubResolver{forge: stub})
	return evaluator.Authorize(context.Background(), Requirement{
		Policy: "pr", GitRevision: strings.Repeat("b", 40), Root: t.TempDir(), ForgeRepository: "shellcell/state",
	})
}

func mergedOnMain() *stubForge {
	return &stubForge{
		info:         forge.RepositoryInfo{Name: "shellcell/state", DefaultBranch: "main"},
		pullRequests: []forge.PullRequest{{Number: 12, Merged: true, BaseBranch: "main"}},
		ancestry:     forge.Ancestry{Contains: true, MergeBase: strings.Repeat("b", 40)},
	}
}

func TestPRGateAcceptsMergedReviewReachableFromDefaultBranch(t *testing.T) {
	if err := authorizeWith(t, mergedOnMain()); err != nil {
		t.Fatalf("a merged, reachable revision was refused: %v", err)
	}
}

// ARCHITECTURE §18: an unavailable provider API renders unknown and cannot
// silently authorize a mutation. Each read the gate performs must refuse.
func TestPRGateRefusesWhenAnyForgeReadFails(t *testing.T) {
	for name, mutate := range map[string]func(*stubForge){
		"repository":    func(stub *stubForge) { stub.infoErr = forge.ErrUnavailable },
		"pull requests": func(stub *stubForge) { stub.pullErr = forge.ErrUnavailable },
		"ancestry":      func(stub *stubForge) { stub.ancestryErr = forge.ErrUnavailable },
	} {
		t.Run(name, func(t *testing.T) {
			stub := mergedOnMain()
			mutate(stub)
			if err := authorizeWith(t, stub); err == nil {
				t.Fatalf("an unavailable %s read authorized publication", name)
			}
		})
	}
}

func TestPRGateRefusesReviewThatDoesNotProveTheRevisionLanded(t *testing.T) {
	for name, mutate := range map[string]func(*stubForge){
		"unmerged":          func(stub *stubForge) { stub.pullRequests[0].Merged = false },
		"other base branch": func(stub *stubForge) { stub.pullRequests[0].BaseBranch = "topic" },
		"no pull request":   func(stub *stubForge) { stub.pullRequests = nil },
		// A later force-push can leave a merged pull request standing while the
		// revision is no longer on the branch.
		"not reachable": func(stub *stubForge) { stub.ancestry.Contains = false },
		"different merge base": func(stub *stubForge) {
			stub.ancestry.MergeBase = strings.Repeat("c", 40)
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub := mergedOnMain()
			mutate(stub)
			if err := authorizeWith(t, stub); err == nil {
				t.Fatalf("%s authorized publication", name)
			}
		})
	}
}

func TestPRGateRefusesWithoutAReviewedRepository(t *testing.T) {
	evaluator := NewDefaultEvaluator("", &stubResolver{forge: mergedOnMain()})
	err := evaluator.Authorize(context.Background(), Requirement{
		Policy: "pr", GitRevision: strings.Repeat("b", 40), Root: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "forge repository") {
		t.Fatalf("error = %v, want a missing reviewed repository", err)
	}
}

func TestForgeUnavailableIsDistinguishable(t *testing.T) {
	if !errors.Is(forge.ErrUnavailable, forge.ErrUnavailable) {
		t.Fatal("ErrUnavailable is not comparable")
	}
}
