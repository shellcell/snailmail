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
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(output, &index); err != nil {
		return "", fmt.Errorf("read %s manifest index: %w", image, err)
	}
	if len(index.Manifests) == 0 {
		// A single-platform image, or a runtime that printed nothing useful.
		return "", fmt.Errorf("image %s carries no manifest index", image)
	}
	wantOS, wantArchitecture, wantVariant := splitPlatform(platform)
	for _, manifest := range index.Manifests {
		if manifest.Platform.OS != wantOS || manifest.Platform.Architecture != wantArchitecture {
			continue
		}
		if manifest.Platform.Variant != wantVariant {
			continue
		}
		if manifest.Digest == "" {
			continue
		}
		return manifest.Digest, nil
	}
	return "", fmt.Errorf("image %s has no %s manifest", image, platform)
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
