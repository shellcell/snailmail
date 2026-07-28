package app

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The pinned reference is a multi-platform index; resolving the child digest is
// what lets a workstation verify a repository built for another architecture.
func TestPlatformImageResolvesForeignArchitecture(t *testing.T) {
	runner := ""
	for _, candidate := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(candidate); err == nil {
			runner = candidate
			break
		}
	}
	if runner == "" {
		t.Skip("no container runner is available")
	}
	foreign := "linux/amd64"
	if runtime.GOARCH == "amd64" {
		foreign = "linux/arm64"
	}
	reference, platformFlag, err := platformImage(context.Background(), runner,
		"docker.io/library/debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818", foreign)
	if errors.Is(err, ErrPlatformUnresolved) {
		t.Skipf("%s cannot reach the registry to resolve the index: %v", runner, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if platformFlag {
		t.Fatalf("a digest-pinned index resolved to %s with --platform still set", reference)
	}
	t.Logf("resolved %s -> %s", foreign, reference)

	// The resolved reference must actually run as that architecture, where the
	// host can execute it at all.
	command := exec.Command(runner, "run", "--rm", reference, "dpkg", "--print-architecture")
	var failure strings.Builder
	command.Stderr = &failure
	output, err := command.Output()
	if err != nil {
		if foreignPlatformUnsupported([]byte(failure.String())) {
			t.Skipf("host cannot execute %s containers: %s", foreign, strings.TrimSpace(failure.String()))
		}
		t.Fatalf("resolved reference did not run: %v: %s", err, failure.String())
	}
	want := "amd64"
	if foreign == "linux/arm64" {
		want = "arm64"
	}
	if got := string(output); got != want+"\n" {
		t.Fatalf("architecture = %q, want %q", got, want)
	}
}

// realDebianIndex mirrors what `docker manifest inspect` prints for the pinned
// Debian image: arm64 carries variant v8, arm carries v5 and v7, and each image
// is followed by an unknown/unknown attestation entry.
const realDebianIndex = `{"manifests":[
 {"digest":"sha256:amd64","platform":{"architecture":"amd64","os":"linux"}},
 {"digest":"sha256:att1","platform":{"architecture":"unknown","os":"unknown"}},
 {"digest":"sha256:armv5","platform":{"architecture":"arm","os":"linux","variant":"v5"}},
 {"digest":"sha256:armv7","platform":{"architecture":"arm","os":"linux","variant":"v7"}},
 {"digest":"sha256:arm64v8","platform":{"architecture":"arm64","os":"linux","variant":"v8"}},
 {"digest":"sha256:i386","platform":{"architecture":"386","os":"linux"}},
 {"digest":"sha256:s390x","platform":{"architecture":"s390x","os":"linux"}}
]}`

// A platform name carries no variant while the index entry does, so requiring
// them to be equal matched nothing for exactly the architectures that have one.
// This is what failed a real publish: "has no linux/arm64 manifest".
func TestSelectPlatformDigestMatchesVariantBearingArchitectures(t *testing.T) {
	for platform, want := range map[string]string{
		"linux/arm64":  "sha256:arm64v8",
		"linux/amd64":  "sha256:amd64",
		"linux/arm":    "sha256:armv5", // unqualified takes the first arm
		"linux/arm/v7": "sha256:armv7", // qualified takes exactly that variant
		"linux/386":    "sha256:i386",
	} {
		t.Run(platform, func(t *testing.T) {
			got, err := selectPlatformDigest([]byte(realDebianIndex), platform)
			if err != nil {
				t.Fatalf("%s: %v", platform, err)
			}
			if got != want {
				t.Fatalf("%s selected %s, want %s", platform, got, want)
			}
		})
	}
}

func TestSelectPlatformDigestRejectsWhatItCannotServe(t *testing.T) {
	for name, testCase := range map[string]struct{ index, platform string }{
		"absent architecture": {realDebianIndex, "linux/riscv64"},
		"absent variant":      {realDebianIndex, "linux/arm/v9"},
		"wrong os":            {realDebianIndex, "windows/amd64"},
		"single-platform":     {`{"schemaVersion":2,"config":{}}`, "linux/amd64"},
		"not an index":        {`not json`, "linux/amd64"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := selectPlatformDigest([]byte(testCase.index), testCase.platform); err == nil {
				t.Fatalf("selected %q where nothing matches", got)
			}
		})
	}
}

// An attestation entry is not an image, and selecting one would run nothing.
func TestSelectPlatformDigestIgnoresAttestations(t *testing.T) {
	got, err := selectPlatformDigest([]byte(realDebianIndex), "unknown/unknown")
	if err == nil {
		t.Fatalf("an attestation entry was selected: %s", got)
	}
}

// The text a runner emits when the kernel refuses the image outright. Resolving
// the correct digest still leaves this: executing a foreign architecture needs
// QEMU and binfmt_misc, which Docker Desktop registers and a plain Linux runner
// does not. Taken verbatim from a failing run.
func TestForeignPlatformUnsupportedRecognisesAnUnrunnableImage(t *testing.T) {
	unrunnable := []string{
		`WARNING: image platform (linux/arm64/v8) does not match the expected platform (linux/amd64)
{"msg":"exec container process ` + "`/usr/bin/sh`" + `: Exec format error","level":"error"}`,
		"standard_init_linux.go:228: exec user process caused: exec format error",
	}
	for _, output := range unrunnable {
		if !foreignPlatformUnsupported([]byte(output)) {
			t.Errorf("did not recognise an unrunnable image in:\n%s", output)
		}
	}
	// A real verification failure must not be mistaken for an unrunnable host,
	// or a broken repository would be quietly skipped instead of reported.
	for _, output := range []string{
		"E: Unable to locate package snailmail",
		"dpkg: error processing archive",
		"",
	} {
		if foreignPlatformUnsupported([]byte(output)) {
			t.Errorf("a verification failure was treated as an unrunnable host: %q", output)
		}
	}
}
