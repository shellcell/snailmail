package forge

import "context"

// TokenBroker supplies the API token for one forge instance.
//
// The GitHub and GitLab adapters normally need none: they run gh or glab, and
// the vendor CLI owns authentication, so snailmail never sees a token. This
// exists for the cases where that is not possible — Forgejo and Gitea have no
// generic API passthrough in their CLI, and a container with neither gh nor glab
// installed cannot run a gate at all — so the token has to come from somewhere
// declared rather than from an environment variable that every child process
// inherits.
//
// Scoped per instance rather than globally. A workspace reads review evidence
// from one forge, and a broker that answered for any host would hand a token for
// gitlab.com to something claiming to be an internal instance.
type TokenBroker interface {
	// Token returns a bearer token for the scope, or an error. An error must not
	// be read as "no token needed": a gate that cannot authenticate cannot read
	// review evidence, and unknown must refuse.
	Token(ctx context.Context, scope TokenScope) (Token, error)
	// Identity records which helper answered, so a deployment receipt can say.
	Identity() string
}

// TokenScope says what the token is for. It reaches the helper as JSON, so a
// helper can hand back different tokens for different repositories without
// snailmail knowing how it decides.
type TokenScope struct {
	// Provider is the forge name, as the manifest records it.
	Provider string `json:"provider"`
	// Host is the instance the token is for.
	Host string `json:"host"`
	// Repository is the reference whose reviews are being read.
	Repository string `json:"repository"`
}

// Token is a bearer credential held for the length of one read.
//
// Destroy overwrites it. A token is read once per request and then discarded, so
// nothing keeps one alive between operations.
type Token interface {
	Bearer(ctx context.Context) (string, error)
	Destroy()
}
