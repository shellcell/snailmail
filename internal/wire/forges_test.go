package wire

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
)

// Every workspace written before the manifest could name a forge was on GitHub,
// because that was the only adapter. Those manifests say nothing, and must keep
// resolving exactly as they did.
func TestAnUndeclaredForgeIsStillGitHub(t *testing.T) {
	selected, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "shellcell/state"})
	if err != nil {
		t.Fatalf("a manifest with no forge failed to resolve: %v", err)
	}
	if selected.Name() != "github" {
		t.Errorf("resolved %q, want github", selected.Name())
	}
}

// This is the bug the field exists to fix. A GitLab group/project has the same
// shape as a GitHub owner/name, so the old resolver handed it to the GitHub
// adapter and it was queried against github.com.
func TestAGitLabReferenceIsNoLongerQueriedAgainstGitHub(t *testing.T) {
	selected, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "acme/tools", Provider: forge.ProviderGitLab})
	if err == nil {
		t.Fatalf("a GitLab repository resolved to %q", selected.Name())
	}
	// The error has to distinguish "not implemented" from "unreachable", or it
	// sends an operator to look at credentials and networking for a missing
	// adapter.
	if !strings.Contains(err.Error(), "recognised") || !strings.Contains(err.Error(), "gitlab") {
		t.Errorf("error = %v, want a recognised-but-unimplemented forge named", err)
	}
	// And it has to say what to do instead, since the workspace is otherwise
	// stuck with a gate it cannot satisfy.
	if !strings.Contains(err.Error(), "approval") {
		t.Errorf("error = %v, want the usable gates suggested", err)
	}
}

func TestAnUnknownForgeIsRefusedAsUnknown(t *testing.T) {
	_, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "acme/tools", Provider: "gitbucket"})
	if err == nil || strings.Contains(err.Error(), "recognised") {
		t.Errorf("error = %v, want an unknown forge reported as unknown", err)
	}
}

// A plain remote has no review API, so it resolves to the adapter that answers
// nothing and a PR gate against it refuses.
func TestAPlainRemoteResolvesToTheAdapterThatAnswersNothing(t *testing.T) {
	selected, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "/srv/git/state.git", Provider: forge.ProviderNone})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Name() != "plain" {
		t.Errorf("resolved %q, want plain", selected.Name())
	}
}

// The GitHub adapter has always accepted an Enterprise hostname and nothing
// could set it. Now the manifest can.
func TestAnEnterpriseHostReachesTheAdapter(t *testing.T) {
	selected, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitHub, Host: "github.acme.example"})
	if err != nil {
		t.Fatalf("an Enterprise host was refused: %v", err)
	}
	if selected.Name() != "github" {
		t.Errorf("resolved %q, want github", selected.Name())
	}
	// github.com itself is not an Enterprise instance, and must resolve to the
	// shared adapter rather than a second one built per call.
	shared := NewForgeResolver()
	first, err := shared.Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitHub, Host: "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := shared.Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitHub})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("naming github.com explicitly built a different adapter than omitting it")
	}
}

// A hostname reaches gh as an argument, so one carrying a separator would become
// something other than a host. The adapter checks it; the resolver must surface
// that rather than return a nil provider, which would panic during authorization.
func TestAnUnusableHostIsAnErrorRatherThanANilProvider(t *testing.T) {
	selected, err := NewForgeResolver().Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitHub, Host: "host name/api"})
	if err == nil {
		t.Fatal("an unusable hostname was accepted")
	}
	// A typed nil pointer in an interface is not nil, passes a nil check, and
	// panics on the first read. This is what forwarding a constructor's two
	// results directly would produce.
	if selected != nil {
		t.Errorf("a refused resolution returned a non-nil %T holding nil", selected)
	}
}
