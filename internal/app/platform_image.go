package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// platformImage resolves a pinned image reference to one that can run as the
// requested platform.
//
// A digest-pinned reference is usually a multi-platform index rather than an
// image. Some runtimes refuse `run --platform X index@digest` outright — docker
// reports "cannot overwrite digest" — because the index digest is not the
// digest of the platform image it would run. That makes verifying an amd64
// repository from an arm64 workstation impossible, which is a normal case for a
// tool whose job is catching publication errors before they ship.
//
// Resolving the child digest from the index fixes it without weakening the pin:
// the child is named by the index whose digest was pinned and reviewed, so
// trust still chains from the pinned value, and no --platform flag is needed
// because the reference now identifies exactly one platform.
//
// A single-platform image has no index to walk, and a runtime may not implement
// manifest inspection, so both cases fall back to the original reference with
// the flag.
func platformImage(ctx context.Context, runner, image, platform string) (reference string, platformFlag bool) {
	digest, err := childManifestDigest(ctx, runner, image, platform)
	if err != nil || digest == "" {
		return image, true
	}
	repository, _, found := strings.Cut(image, "@")
	if !found {
		return image, true
	}
	return repository + "@" + digest, false
}

func childManifestDigest(ctx context.Context, runner, image, platform string) (string, error) {
	output, err := exec.CommandContext(ctx, runner, "manifest", "inspect", image).Output()
	if err != nil {
		return "", err
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
		return "", err
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
