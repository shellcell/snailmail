package wire

import (
	"context"
	"fmt"
	"sync"

	forgejoforge "github.com/shellcell/snailmail/adapters/forge/forgejo"
	githubforge "github.com/shellcell/snailmail/adapters/forge/github"
	gitlabforge "github.com/shellcell/snailmail/adapters/forge/gitlab"
	plainforge "github.com/shellcell/snailmail/adapters/forge/plain"
	tokenbroker "github.com/shellcell/snailmail/adapters/forge/token"
	"github.com/shellcell/snailmail/forge"
)

// ForgeResolver selects a review provider from what the manifest declared.
//
// It used to select by the shape of the reference, treating every owner/name as
// github.com. That is a shape every provider shares, so a GitLab group/project
// was queried against GitHub: the gate still refused, because a revision is a
// SHA and cannot collide across services, but it refused by reporting that the
// state repository could not be identified — and no configuration could correct
// it. Selection is now on the declared provider, so an unreadable forge and an
// unimplemented one are different errors.
type ForgeResolver struct {
	plain *plainforge.Adapter
	// The token broker snapshots a helper program, so it is opened once and
	// shared rather than per resolution.
	once      sync.Once
	tokens    *tokenbroker.Broker
	tokensErr error
}

func NewForgeResolver() *ForgeResolver {
	return &ForgeResolver{plain: plainforge.New()}
}

func (resolver *ForgeResolver) Resolve(_ context.Context, repository forge.Repository) (forge.Forge, error) {
	provider := repository.Provider
	if provider == "" {
		provider = forge.DefaultProvider
	}
	switch provider {
	case forge.ProviderGitHub:
		broker, err := resolver.forgeToken()
		if err != nil {
			return nil, err
		}
		// An Enterprise instance is reached by hostname. The default is the
		// adapter's own, so a workspace that names no host is unaffected.
		if host := repository.Host; host != "" && host != forge.DefaultHost(forge.ProviderGitHub) {
			// Returned explicitly rather than forwarded: a *Adapter typed nil
			// assigned to a forge.Forge is a non-nil interface holding nil, which
			// passes a nil check and panics on the first read.
			adapter, err := githubforge.NewForHost(host, broker)
			if err != nil {
				return nil, err
			}
			return adapter, nil
		}
		return githubforge.New(broker), nil
	case forge.ProviderGitLab:
		broker, err := resolver.forgeToken()
		if err != nil {
			return nil, err
		}
		if host := repository.Host; host != "" && host != forge.DefaultHost(forge.ProviderGitLab) {
			adapter, err := gitlabforge.NewForHost(host, broker)
			if err != nil {
				return nil, err
			}
			return adapter, nil
		}
		return gitlabforge.New(broker), nil
	case forge.ProviderForgejo, forge.ProviderGitea:
		// No vendor CLI to delegate to, so this speaks HTTP and needs a token —
		// except against a public repository, where reading without one is
		// legitimate and the broker stays absent.
		if repository.Host == "" {
			return nil, fmt.Errorf("forge %q is self-hosted and needs forge_host", provider)
		}
		broker, err := resolver.forgeToken()
		if err != nil {
			return nil, err
		}
		return forgejoforge.NewForHost(provider, repository.Host, broker)
	case forge.ProviderNone:
		return resolver.plain, nil
	}
	// A provider snailmail recognises but has no adapter for must say so. Falling
	// through to the plain adapter would refuse safely, but it would refuse as
	// though review evidence were unreadable, when what is missing is the code to
	// read it — which sends an operator to look at their credentials and their
	// network instead of at this list.
	if forge.KnownProvider(provider) {
		return nil, fmt.Errorf("forge %q is recognised but snailmail cannot read its reviews yet; "+
			"use gate = \"approval\" or gate = \"auto\" until an adapter exists", provider)
	}
	return nil, fmt.Errorf("forge %q is unknown", provider)
}

// forgeToken opens the token broker, or reports that none is configured as an
// absence rather than a failure.
//
// A public state repository is read without authenticating, so no broker is an
// ordinary configuration and not an error. One that is configured and refuses is
// a different matter, and says so.
func (resolver *ForgeResolver) forgeToken() (forge.TokenBroker, error) {
	if !tokenbroker.Configured() {
		return nil, nil
	}
	resolver.once.Do(func() {
		resolver.tokens, resolver.tokensErr = tokenbroker.NewFromEnvironment()
	})
	if resolver.tokensErr != nil {
		return nil, resolver.tokensErr
	}
	return resolver.tokens, nil
}
