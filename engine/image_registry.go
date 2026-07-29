package engine

import (
	"errors"
	"fmt"
	"strings"
)

// ImageWithRegistry moves a digest-pinned image reference to another registry.
//
// It exists because the registry a verification image is fetched from is a
// property of the network doing the fetching, not of the repository being
// published. Docker Hub rate-limits anonymous pulls by source address, and
// hosted CI runners share addresses, so a workspace that can only pull from
// there fails for reasons that have nothing to do with its packages. Pointing
// at a mirror or a pull-through cache fixes that.
//
// Doing it here rather than by writing mirrored references into a workflow
// keeps one copy of each pinned digest. A workflow that repeated them would
// drift from the defaults the tool ships the moment either changed, and a stale
// digest in a mirror is exactly the kind of quiet difference this project
// exists to prevent.
//
// Only digest-pinned references may be moved. A digest names the same bytes at
// every registry, so the pin survives the move intact and the trust is
// unchanged; a tag names whatever a particular registry decided it means, and
// moving one would silently change what is verified.
func ImageWithRegistry(reference, registry string) (string, error) {
	if registry == "" {
		return reference, nil
	}
	if strings.ContainsAny(registry, "@ \t") || strings.HasPrefix(registry, "/") || strings.HasSuffix(registry, "/") {
		return "", fmt.Errorf("%q is not a registry host", registry)
	}
	repository, digest, pinned := strings.Cut(reference, "@")
	if !pinned || !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("%w: %s", errUnpinnedImageMove, reference)
	}
	// The leading segment is a registry host only where it looks like one; a
	// reference such as alpine/helm names a Docker Hub repository whose first
	// segment is an organisation, and dropping it would fetch something else.
	if host, path, split := strings.Cut(repository, "/"); split && isRegistryHost(host) {
		repository = path
	}
	return registry + "/" + repository + "@" + digest, nil
}

// errUnpinnedImageMove is stated rather than wrapped anonymously so the reason
// reads as a refusal to weaken a pin rather than as a parse failure.
var errUnpinnedImageMove = errors.New("only a digest-pinned image can be moved to another registry")

// isRegistryHost reports whether a reference's first segment names a registry
// rather than being part of the repository path. This is the same rule the
// container ecosystem uses: a host has a dot or a port, or is localhost.
func isRegistryHost(segment string) bool {
	return segment == "localhost" || strings.ContainsAny(segment, ".:")
}
