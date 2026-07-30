package forge

import "strings"

// Provider names the code-hosting service a workspace's state repository lives
// on. It is recorded in the manifest rather than inferred from the repository's
// name, because owner/name is a shape every provider shares: resolving it by
// shape sent a GitLab group/project to github.com.
//
// It is also not inferred from the git remote at read time. A remote can be
// changed by anyone who can write to a checkout, and this value decides which
// service is asked whether a revision was reviewed. The wizard may fill it in
// from the remote once, when the workspace is created; from then on the manifest
// is the record, and it is reviewed like any other change to it.
const (
	ProviderGitHub  = "github"
	ProviderGitLab  = "gitlab"
	ProviderForgejo = "forgejo"
	ProviderGitea   = "gitea"
	// ProviderNone is a remote with no review API — a bare repository, a mirror,
	// a local path. It resolves to an adapter that answers nothing, so a PR gate
	// configured against it refuses.
	ProviderNone = "none"
)

// DefaultProvider is assumed when a manifest does not say. Every workspace
// written before the field existed and configured with a PR gate is on GitHub,
// because that was the only adapter, so this preserves them exactly.
const DefaultProvider = ProviderGitHub

// providerRules is what each provider accepts as a repository reference. The
// shape is part of identifying a provider correctly: GitLab nests groups
// arbitrarily deep and GitHub does not, so a reference valid for one is a
// misconfiguration for the other rather than a harmless difference.
var providerRules = map[string]struct {
	// maxSegments bounds the path depth. GitHub is exactly owner/name; GitLab
	// allows subgroups, which its API addresses as one URL-encoded path.
	minSegments, maxSegments int
	// defaultHost is the service's own hostname, used when the manifest names no
	// host. Self-hosted instances set one; there is no default for those.
	defaultHost string
}{
	ProviderGitHub:  {minSegments: 2, maxSegments: 2, defaultHost: "github.com"},
	ProviderGitLab:  {minSegments: 2, maxSegments: 20, defaultHost: "gitlab.com"},
	ProviderForgejo: {minSegments: 2, maxSegments: 2},
	ProviderGitea:   {minSegments: 2, maxSegments: 2},
	ProviderNone:    {minSegments: 1, maxSegments: 1},
}

// KnownProvider reports whether a name is one snailmail recognises. A recognised
// name with no adapter is a different failure from an unrecognised one, and the
// two must not be reported the same way: one is not implemented yet, the other is
// a typo or a service snailmail has never heard of.
func KnownProvider(name string) bool {
	_, known := providerRules[name]
	return known
}

// Providers lists the recognised provider names, for error messages that tell an
// operator what they could have written instead.
func Providers() []string {
	return []string{ProviderGitHub, ProviderGitLab, ProviderForgejo, ProviderGitea, ProviderNone}
}

// DefaultHost is the provider's own hostname, or empty for a provider that only
// exists self-hosted and therefore must be given one.
func DefaultHost(provider string) string {
	return providerRules[provider].defaultHost
}

// ValidRepositoryReference reports whether a reference has the shape the named
// provider addresses repositories by.
//
// This is a shape check and nothing more. Whether the repository exists, and
// whether it is the one the operator meant, is answered by the adapter reading
// it — Repository refuses a provider that answers about a different repository.
func ValidRepositoryReference(provider, reference string) bool {
	rule, known := providerRules[provider]
	if !known || reference == "" || len(reference) > 512 {
		return false
	}
	if provider == ProviderNone {
		// A plain remote is a path or a URL, not a namespaced reference, and
		// nothing reads it. Requiring only that it be sayable keeps a bare
		// repository from being rejected for not looking like a forge.
		return !strings.ContainsAny(reference, " \t\r\n")
	}
	segments := strings.Split(reference, "/")
	if len(segments) < rule.minSegments || len(segments) > rule.maxSegments {
		return false
	}
	for index, segment := range segments {
		if !validPathSegment(segment) {
			return false
		}
		// A trailing .git is how a clone URL ends, not how an API addresses a
		// repository, and passing one through produces a confusing 404.
		if index == len(segments)-1 && strings.HasSuffix(strings.ToLower(segment), ".git") {
			return false
		}
	}
	return true
}

func validPathSegment(value string) bool {
	if value == "" || len(value) > 100 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

// ValidHost reports whether a hostname can be passed to a provider CLI as an
// argument. A value carrying whitespace or a path would become a second argument
// or an endpoint rather than a host.
func ValidHost(host string) bool {
	return host != "" && len(host) <= 253 && !strings.ContainsAny(host, " \t\r\n/\\?#@") &&
		!strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".")
}
