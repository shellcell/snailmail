package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrPlatformUnresolved reports that the platform image behind a pinned index
// could not be resolved, so a cross-platform run cannot be set up. It is
// separate from a verification failure: nothing has been checked and nothing
// has been found wrong. Callers that can proceed without the check — tests on a
// workstation with no registry access — match on it rather than on message text.
var ErrPlatformUnresolved = errors.New("container platform image could not be resolved")

// ErrForeignPlatformUnsupported reports that the host cannot execute the
// requested architecture. Resolving the right image is not enough: running a
// foreign-architecture container needs binfmt_misc handlers and QEMU registered
// on the host, which Docker Desktop provides and a plain Linux runner does not
// until qemu-user-static is installed. Nothing was verified and nothing was
// found wrong, so callers that can proceed without the check match on this
// rather than on message text.
var ErrForeignPlatformUnsupported = errors.New("host cannot run containers for this architecture")

// foreignPlatformUnsupported reports whether a runner failed because the image
// could not be executed at all. The kernel refuses the binary before any of the
// verification script runs, so this is never a repository problem.
func foreignPlatformUnsupported(output []byte) bool {
	return strings.Contains(strings.ToLower(string(output)), "exec format error")
}

// ErrVerificationImageUnavailable reports that the client image could not be
// fetched, so no verification was attempted. It is not a verification failure:
// the repository was never examined, and reporting a registry outage as though
// the packages were bad would send someone looking in the wrong place.
var ErrVerificationImageUnavailable = errors.New("container image for verification could not be fetched")

// registryUnavailable reports whether a runner failed to obtain the image
// rather than failing to run it.
//
// The signatures are deliberately narrow and all describe a transfer: a
// verification that genuinely fails does so from inside the container, with the
// client's own output, and must never be mistaken for this.
func registryUnavailable(output []byte) bool {
	text := strings.ToLower(string(output))
	// The gate is what keeps a client's own output from being read as a
	// transfer problem. It only applies where the output could be a client's:
	// see registryRefusal for the paths where it never can.
	if !strings.Contains(text, "error response from daemon") &&
		!strings.Contains(text, "failed to resolve") && !strings.Contains(text, "pulling") &&
		!strings.Contains(text, "trying to pull") {
		return false
	}
	return registryRefusal(text)
}

// registryRefusal reports whether a message describes a registry declining to
// serve, without requiring the pull-shaped preamble registryUnavailable looks
// for.
//
// It is separate because some failures happen before any container is created —
// resolving a multi-platform index, for one — where the output cannot be a
// client's verification output and there is nothing to disambiguate from. A
// registry quota is worded differently on each of those paths, and demanding a
// preamble that only the pull path prints would silently classify the same
// refusal as a repository defect.
func registryRefusal(text string) bool {
	text = strings.ToLower(text)
	for _, signature := range []string{
		"received unexpected http status",
		"bad gateway",
		"service unavailable",
		"toomanyrequests",
		"rate limit",
		"unauthorized",
		"no such host",
		"connection refused",
		"i/o timeout",
		"tls handshake timeout",
		"temporary failure in name resolution",
	} {
		if strings.Contains(text, signature) {
			return true
		}
	}
	return false
}

// platformImage resolves a pinned image reference to one that can run as the
// requested platform.
//
// A digest-pinned reference is usually a multi-platform index rather than an
// image. Docker refuses `run --platform X index@digest` whenever the flag would
// select a different manifest than the digest resolves to on its own, reporting
// "cannot overwrite digest". That makes verifying an amd64 repository from an
// arm64 workstation impossible, which is a normal case for a tool whose job is
// catching publication errors before they ship.
//
// Resolving the child digest from the index fixes it without weakening the pin:
// the child is named by the index whose digest was pinned and reviewed, so
// trust still chains from the pinned value, and no --platform flag is needed
// because the reference now identifies exactly one platform.
//
// When the requested platform is the one the runtime runs natively, the pinned
// reference already selects it and no resolution is needed. That is the common
// case, and skipping it keeps an ordinary verification off the network.
func platformImage(ctx context.Context, runner, image, platform string) (reference string, platformFlag bool, err error) {
	if !digestPinnedImage(image) {
		// A tag can be repointed at another manifest, so the flag does the work.
		return image, true, nil
	}
	if hostPlatform(ctx, runner) == platform {
		return image, false, nil
	}
	repository, _, found := strings.Cut(image, "@")
	if !found {
		return "", false, fmt.Errorf("%w: %s is not digest-pinned", ErrPlatformUnresolved, image)
	}
	digest, err := childManifestDigest(ctx, runner, image, platform)
	if err != nil {
		// A registry that will not serve the index is the same condition as one
		// that will not serve the image, and must be reported as such. Resolving
		// the platform is a fetch like any other: an exhausted pull quota here
		// says nothing about the repository, and calling it an unresolvable
		// platform sends the reader to look at their image pin instead of at
		// their registry credentials.
		if registryRefusal(err.Error()) {
			return "", false, fmt.Errorf("%w: %s as %s: %w", ErrVerificationImageUnavailable, image, platform, err)
		}
		return "", false, fmt.Errorf("%w: %s as %s: %w", ErrPlatformUnresolved, image, platform, err)
	}
	return repository + "@" + digest, false, nil
}

// hostPlatform reports what the runtime runs without emulation, or "" when it
// cannot be determined — an unknown platform simply means resolution proceeds.
func hostPlatform(ctx context.Context, runner string) string {
	output, err := exec.CommandContext(ctx, runner, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}").Output()
	if err != nil {
		return ""
	}
	reported := strings.TrimSpace(string(output))
	if strings.Count(reported, "/") != 1 || strings.HasPrefix(reported, "/") || strings.HasSuffix(reported, "/") {
		return ""
	}
	return reported
}

func childManifestDigest(ctx context.Context, runner, image, platform string) (string, error) {
	command := exec.CommandContext(ctx, runner, "manifest", "inspect", image)
	var failure strings.Builder
	command.Stderr = &failure
	output, err := command.Output()
	if err != nil {
		if reason := strings.TrimSpace(failure.String()); reason != "" {
			return "", fmt.Errorf("%s manifest inspect: %s", runner, reason)
		}
		return "", fmt.Errorf("%s manifest inspect: %w", runner, err)
	}
	digest, err := selectPlatformDigest(output, platform)
	if err != nil {
		return "", fmt.Errorf("%s: %w", image, err)
	}
	return digest, nil
}

// selectPlatformDigest picks the child manifest for a platform out of an index.
//
// A platform name usually carries no variant, while the index entry does: the
// official images publish linux/arm64 as variant v8 and linux/arm as v5 and v7.
// Requiring the variants to be equal therefore matched nothing for exactly the
// architectures that need a variant, so an unqualified request accepts any
// variant and prefers an exact match when the index offers one.
func selectPlatformDigest(index []byte, platform string) (string, error) {
	var parsed struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(index, &parsed); err != nil {
		return "", fmt.Errorf("read manifest index: %w", err)
	}
	if len(parsed.Manifests) == 0 {
		// A single-platform image, or a runtime that printed nothing useful.
		return "", errors.New("carries no manifest index")
	}
	wantOS, wantArchitecture, wantVariant := splitPlatform(platform)
	fallback := ""
	for _, manifest := range parsed.Manifests {
		// Attestation entries ride along as unknown/unknown. Nothing would ask
		// for that platform, but selecting one would hand back a reference that
		// cannot run, so they are refused rather than merely unmatched.
		if manifest.Platform.OS == "unknown" || manifest.Platform.Architecture == "unknown" {
			continue
		}
		if manifest.Digest == "" || manifest.Platform.OS != wantOS || manifest.Platform.Architecture != wantArchitecture {
			continue
		}
		if manifest.Platform.Variant == wantVariant {
			return manifest.Digest, nil
		}
		if wantVariant == "" && fallback == "" {
			fallback = manifest.Digest
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("has no %s manifest", platform)
}

// splitPlatform parses "linux/amd64" or "linux/arm/v7".
func splitPlatform(platform string) (operatingSystem, architecture, variant string) {
	parts := strings.Split(platform, "/")
	switch len(parts) {
	case 2:
		return parts[0], parts[1], ""
	case 3:
		return parts[0], parts[1], parts[2]
	default:
		return platform, "", ""
	}
}
