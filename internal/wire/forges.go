package wire

import (
	"context"

	githubforge "github.com/shellcell/snailmail/adapters/forge/github"
	plainforge "github.com/shellcell/snailmail/adapters/forge/plain"
	"github.com/shellcell/snailmail/forge"
)

// ForgeResolver selects a review provider from a repository reference.
//
// Only GitHub owner/name references resolve to a provider today. Anything else
// resolves to the plain adapter, which reports that review evidence cannot be
// read rather than allowing a gate to pass unchecked.
type ForgeResolver struct {
	github *githubforge.Adapter
	plain  *plainforge.Adapter
}

func NewForgeResolver() *ForgeResolver {
	return &ForgeResolver{github: githubforge.New(), plain: plainforge.New()}
}

func (resolver *ForgeResolver) Resolve(_ context.Context, repository forge.Repository) (forge.Forge, error) {
	if isGitHubReference(repository.Name) {
		return resolver.github, nil
	}
	return resolver.plain, nil
}

// isGitHubReference reports whether a name is an owner/name pair, which is the
// only shape the manifest accepts for a forge repository today.
func isGitHubReference(name string) bool {
	owner, repository, found := cut(name, "/")
	return found && owner != "" && repository != "" &&
		!contains(owner, "/") && !contains(repository, "/")
}

func cut(value, separator string) (string, string, bool) {
	for index := 0; index+len(separator) <= len(value); index++ {
		if value[index:index+len(separator)] == separator {
			return value[:index], value[index+len(separator):], true
		}
	}
	return value, "", false
}

func contains(value, separator string) bool {
	_, _, found := cut(value, separator)
	return found
}
