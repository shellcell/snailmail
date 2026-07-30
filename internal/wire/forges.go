package wire

import (
	"context"
	"fmt"

	githubforge "github.com/shellcell/snailmail/adapters/forge/github"
	plainforge "github.com/shellcell/snailmail/adapters/forge/plain"
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
	github *githubforge.Adapter
	plain  *plainforge.Adapter
}

func NewForgeResolver() *ForgeResolver {
	return &ForgeResolver{github: githubforge.New(), plain: plainforge.New()}
}

func (resolver *ForgeResolver) Resolve(_ context.Context, repository forge.Repository) (forge.Forge, error) {
	provider := repository.Provider
	if provider == "" {
		provider = forge.DefaultProvider
	}
	switch provider {
	case forge.ProviderGitHub:
		// An Enterprise instance is reached by hostname. The default is the
		// adapter's own, so a workspace that names no host is unaffected.
		if host := repository.Host; host != "" && host != forge.DefaultHost(forge.ProviderGitHub) {
			// Returned explicitly rather than forwarded: a *Adapter typed nil
			// assigned to a forge.Forge is a non-nil interface holding nil, which
			// passes a nil check and panics on the first read.
			adapter, err := githubforge.NewForHost(host)
			if err != nil {
				return nil, err
			}
			return adapter, nil
		}
		return resolver.github, nil
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
