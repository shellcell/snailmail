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
	if err != nil {
		t.Fatalf("a GitLab repository failed to resolve: %v", err)
	}
	if selected.Name() != forge.ProviderGitLab {
		t.Errorf("resolved %q, want gitlab", selected.Name())
	}
}

// A self-hosted GitLab is reached by hostname, and gitlab.com must still resolve
// to the shared adapter rather than a second one built per call.
func TestASelfHostedGitLabReachesTheAdapter(t *testing.T) {
	shared := NewForgeResolver()
	selected, err := shared.Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitLab, Host: "git.acme.example"})
	if err != nil {
		t.Fatalf("a self-hosted GitLab was refused: %v", err)
	}
	if selected.Name() != forge.ProviderGitLab {
		t.Errorf("resolved %q, want gitlab", selected.Name())
	}
	explicit, err := shared.Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitLab, Host: "gitlab.com"})
	if err != nil {
		t.Fatal(err)
	}
	implicit, err := shared.Resolve(context.Background(),
		forge.Repository{Name: "acme/state", Provider: forge.ProviderGitLab})
	if err != nil {
		t.Fatal(err)
	}
	if explicit != implicit {
		t.Error("naming gitlab.com explicitly built a different adapter than omitting it")
	}
	if _, err := shared.Resolve(context.Background(), forge.Repository{
		Name: "acme/state", Provider: forge.ProviderGitLab, Host: "git acme/api"}); err == nil {
		t.Error("an unusable GitLab hostname was accepted")
	}
}

// Forgejo and Gitea resolve to the HTTP adapter. Neither has a hostname of its
// own, so the instance always has to be named — and a workspace that omits it
// gets told that rather than a network error later.
func TestForgejoAndGiteaResolveToTheirAdapter(t *testing.T) {
	for _, provider := range []string{forge.ProviderForgejo, forge.ProviderGitea} {
		selected, err := NewForgeResolver().Resolve(context.Background(),
			forge.Repository{Name: "acme/state", Provider: provider, Host: "git.acme.example"})
		if err != nil {
			t.Fatalf("%s was refused: %v", provider, err)
		}
		if selected.Name() != provider {
			t.Errorf("resolved %q, want %q", selected.Name(), provider)
		}
		_, err = NewForgeResolver().Resolve(context.Background(),
			forge.Repository{Name: "acme/state", Provider: provider})
		if err == nil || !strings.Contains(err.Error(), "forge_host") {
			t.Errorf("%s without a host gave %v, want a request for forge_host", provider, err)
		}
	}
}

// A recognised provider with no adapter at all must still be reported as such,
// separately from one that cannot be reached. Bitbucket is the case this guards:
// it is not in the provider list, so it reads as unknown, and nothing silently
// falls through to an adapter that would answer about something else.
func TestNoRecognisedProviderFallsThroughToTheWrongAdapter(t *testing.T) {
	resolver := NewForgeResolver()
	for _, provider := range forge.Providers() {
		selected, err := resolver.Resolve(context.Background(),
			forge.Repository{Name: "acme/state", Provider: provider, Host: "git.acme.example"})
		if err != nil {
			t.Errorf("%s is a declared provider but did not resolve: %v", provider, err)
			continue
		}
		// "none" is the provider name for a remote with no review API, and the
		// adapter that serves it is called "plain". Every other provider names its
		// own adapter.
		want := provider
		if provider == forge.ProviderNone {
			want = "plain"
		}
		if selected.Name() != want {
			t.Errorf("provider %q resolved to the %q adapter, want %q", provider, selected.Name(), want)
		}
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
