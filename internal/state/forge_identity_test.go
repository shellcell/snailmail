package state

import (
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
)

// A manifest written before the forge could be named must keep loading. Every
// such workspace is on GitHub, because that was the only adapter, and one that
// stopped loading would be one that could no longer publish.
func TestAManifestThatNamesNoForgeIsUnchanged(t *testing.T) {
	for _, workspace := range []Workspace{
		{Name: "postoffice", ForgeRepository: "shellcell/postoffice"},
		{Name: "local-only"},
	} {
		if err := validateForgeIdentity(workspace); err != nil {
			t.Errorf("workspace %+v no longer validates: %v", workspace, err)
		}
	}
}

// GitLab nests groups arbitrarily deep and GitHub does not, so the same
// reference is valid for one and a misconfiguration for the other. This is the
// difference that made resolving by name shape wrong.
func TestARepositoryReferenceIsValidForAProviderRatherThanInGeneral(t *testing.T) {
	nested := "acme/platform/tools/state"
	if !forge.ValidRepositoryReference(forge.ProviderGitLab, nested) {
		t.Errorf("GitLab refused a nested group %q", nested)
	}
	if forge.ValidRepositoryReference(forge.ProviderGitHub, nested) {
		t.Errorf("GitHub accepted %q, which it cannot address", nested)
	}
	for _, provider := range []string{forge.ProviderGitHub, forge.ProviderGitLab} {
		for _, reference := range []string{"", "state", "acme/", "/state", "acme//state",
			"acme/state.git", "acme/../state", "acme/st ate", "acme/.hidden"} {
			if forge.ValidRepositoryReference(provider, reference) {
				t.Errorf("%s accepted %q", provider, reference)
			}
		}
	}
}

func TestAnUnknownForgeIsRefusedWithTheAlternatives(t *testing.T) {
	err := validateForgeIdentity(Workspace{Name: "w", Forge: "gitbucket", ForgeRepository: "acme/state"})
	if err == nil {
		t.Fatal("an unknown forge was accepted")
	}
	// An operator who typed a name snailmail does not know needs to see the ones
	// it does, or the next guess is as blind as the first.
	for _, provider := range forge.Providers() {
		if !strings.Contains(err.Error(), provider) {
			t.Errorf("error = %v, want %q listed", err, provider)
		}
	}
}

// Forgejo and Gitea have no hostname of their own — they exist only as instances
// someone runs — so there is nothing to fall back to and the manifest must say.
func TestASelfHostedForgeMustNameItsHost(t *testing.T) {
	for _, provider := range []string{forge.ProviderForgejo, forge.ProviderGitea} {
		err := validateForgeIdentity(Workspace{Name: "w", Forge: provider, ForgeRepository: "acme/state"})
		if err == nil || !strings.Contains(err.Error(), "forge_host") {
			t.Errorf("%s without a host gave %v, want a request for forge_host", provider, err)
		}
		if err := validateForgeIdentity(Workspace{
			Name: "w", Forge: provider, ForgeRepository: "acme/state", ForgeHost: "git.acme.example",
		}); err != nil {
			t.Errorf("%s with a host was refused: %v", provider, err)
		}
	}
	// GitHub and GitLab have their own, so omitting the host is not an error.
	for _, provider := range []string{forge.ProviderGitHub, forge.ProviderGitLab} {
		if forge.DefaultHost(provider) == "" {
			t.Errorf("%s has no default host", provider)
		}
		if err := validateForgeIdentity(Workspace{Name: "w", Forge: provider, ForgeRepository: "acme/state"}); err != nil {
			t.Errorf("%s without a host was refused: %v", provider, err)
		}
	}
}

// A named forge with nothing to read leaves a PR gate configurable and
// permanently unsatisfiable, which is worse than refusing the manifest.
func TestANamedForgeNeedsARepositoryToRead(t *testing.T) {
	err := validateForgeIdentity(Workspace{Name: "w", Forge: forge.ProviderGitHub})
	if err == nil || !strings.Contains(err.Error(), "forge_repository") {
		t.Errorf("error = %v, want a request for forge_repository", err)
	}
	// A plain remote is the exception: there is nothing to read by definition.
	if err := validateForgeIdentity(Workspace{Name: "w", Forge: forge.ProviderNone}); err != nil {
		t.Errorf("a plain remote with no repository was refused: %v", err)
	}
}

// The host reaches a provider CLI as an argument, so one carrying a separator
// would become an endpoint or a second argument.
func TestAnUnusableForgeHostIsRefused(t *testing.T) {
	for _, host := range []string{"git acme.example", "git.acme.example/api", "git\nacme",
		".acme.example", "acme.example.", "user@acme.example", "acme?x", strings.Repeat("a", 254)} {
		err := validateForgeIdentity(Workspace{
			Name: "w", Forge: forge.ProviderGitHub, ForgeRepository: "acme/state", ForgeHost: host,
		})
		if err == nil {
			t.Errorf("host %q was accepted", host)
		}
	}
}

// A plain remote is a path or a URL rather than a namespaced reference, and
// nothing reads it, so it must not be rejected for failing to look like a forge.
func TestAPlainRemoteAcceptsAPath(t *testing.T) {
	for _, reference := range []string{"/srv/git/state.git", "git@example.test:acme/state.git",
		"https://git.example.test/acme/state.git"} {
		if err := validateForgeIdentity(Workspace{
			Name: "w", Forge: forge.ProviderNone, ForgeRepository: reference,
		}); err != nil {
			t.Errorf("plain remote %q was refused: %v", reference, err)
		}
	}
}
