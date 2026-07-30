package plainforge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/forge/forgetest"
)

// This adapter is the one that deliberately fails the conformance suite: it
// answers nothing, because a remote with no review API has no review evidence to
// read. What it must get right is that every refusal is ErrUnavailable and none
// is a permissive default — the gate distinguishes "not reviewed" from "could
// not ask" only by this error, and both refuse.
func TestPlainForgeAnswersNothingAndSaysSo(t *testing.T) {
	adapter := New()
	target := forge.Repository{Name: "/srv/git/state.git", WorkingDirectory: t.TempDir()}
	ctx := context.Background()

	if adapter.Name() == "" {
		t.Error("an adapter with no name cannot be named in an error")
	}

	info, err := adapter.Repository(ctx, target)
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("repository read error = %v, want ErrUnavailable", err)
	}
	if info != (forge.RepositoryInfo{}) {
		t.Errorf("a refused read returned %+v, want nothing", info)
	}

	// An empty slice with a nil error would read as "reviewed by nothing", which
	// the gate would treat as a revision with no merged review — the same outcome,
	// but reached by claiming knowledge this adapter does not have.
	pullRequests, err := adapter.PullRequestsForRevision(ctx, target, strings.Repeat("a", 40))
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("review read error = %v, want ErrUnavailable", err)
	}
	if pullRequests != nil {
		t.Errorf("a refused read returned %+v, want nothing", pullRequests)
	}

	ancestry, err := adapter.RevisionAncestry(ctx, target, strings.Repeat("a", 40), "main")
	if !errors.Is(err, forge.ErrUnavailable) {
		t.Errorf("ancestry read error = %v, want ErrUnavailable", err)
	}
	if ancestry != (forge.Ancestry{}) {
		t.Errorf("a refused read returned %+v, want nothing", ancestry)
	}
}

// The refusal has to say which repository could not be read. A gate failure that
// does not name the remote leaves an operator guessing which of a workspace's
// references is the unreadable one.
func TestPlainForgeNamesWhatItCouldNotRead(t *testing.T) {
	_, err := New().Repository(context.Background(), forge.Repository{Name: "/srv/git/state.git"})
	if err == nil || !strings.Contains(err.Error(), "/srv/git/state.git") {
		t.Errorf("error = %v, want the remote named", err)
	}
}

func TestPlainResolverAlwaysReturnsAnAdapter(t *testing.T) {
	for _, name := range []string{forgetest.Repository, "", "/srv/git/state.git"} {
		selected, err := NewResolver().Resolve(context.Background(), forge.Repository{Name: name})
		if err != nil || selected == nil {
			t.Fatalf("resolving %q gave (%v, %v)", name, selected, err)
		}
		if selected.Name() != "plain" {
			t.Errorf("resolving %q selected %q", name, selected.Name())
		}
	}
}
