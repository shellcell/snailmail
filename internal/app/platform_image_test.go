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
		if registryUnavailable([]byte(failure.String())) {
			// The registry was unreachable, so the reference was never run and
			// there is nothing this test could have learned.
			t.Skipf("registry is unavailable: %s", strings.TrimSpace(failure.String()))
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

// A registry outage and a broken repository must not look alike: the first
// means nothing was checked, the second that something is wrong with what was
// published. Both arrive as a failed container run.
func TestRegistryUnavailableIsNotAVerificationFailure(t *testing.T) {
	outages := []string{
		`Unable to find image 'debian@sha256:9b67' locally
docker: Error response from daemon: Get "https://registry-1.docker.io/v2/library/debian/manifests/sha256:9b67": received unexpected HTTP status: 502 Bad Gateway`,
		`Trying to pull docker.io/library/alpine...
Error response from daemon: toomanyrequests: You have reached your unauthenticated pull rate limit.`,
		`Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io: no such host`,
	}
	for _, output := range outages {
		if !registryUnavailable([]byte(output)) {
			t.Errorf("did not recognise an outage in:\n%s", output)
		}
	}
	// A client that ran and reported a problem is a verification failure, and
	// treating it as an outage would hide a broken repository.
	for _, output := range []string{
		"E: Unable to locate package snailmail",
		"ERROR: snailmail-0.0.8-r1: package mentioned in index not found",
		"No match for argument: snail-demo",
		"installed 1.2.3-1, index advertised 1.2.4-1",
		"",
	} {
		if registryUnavailable([]byte(output)) {
			t.Errorf("a verification failure was treated as an outage: %q", output)
		}
	}
}

// Resolving a multi-platform index happens before any container exists, so a
// registry refusing there is a transfer problem however it is worded. These are
// the exact messages a rate-limited Docker Hub produced on that path; they carry
// none of the pull-shaped preamble the run path prints, which is why they need
// their own classification.
func TestManifestPathRecognisesARegistryRefusal(t *testing.T) {
	for _, message := range []string{
		"/usr/local/bin/docker manifest inspect: toomanyrequests: You have reached your unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit",
		"docker manifest inspect: unauthorized: authentication required",
		`docker manifest inspect: Get "https://registry-1.docker.io/v2/": received unexpected HTTP status: 503 Service Unavailable`,
	} {
		if !registryRefusal(message) {
			t.Errorf("a registry refusal was not recognised: %q", message)
		}
		// The stricter pull-path check deliberately does not fire here, which is
		// exactly why the manifest path needs its own.
		if registryUnavailable([]byte(message)) {
			t.Errorf("the pull-path gate should not match a manifest failure: %q", message)
		}
	}
}

// A missing or genuinely wrong image is the operator's pin to fix, and must not
// be excused as somebody else's outage.
func TestManifestPathKeepsRealResolutionFailures(t *testing.T) {
	for _, message := range []string{
		"docker manifest inspect: manifest unknown",
		"docker manifest inspect: no matching manifest for linux/riscv64 in the manifest list entries",
		"docker manifest inspect: invalid reference format",
		"",
	} {
		if registryRefusal(message) {
			t.Errorf("a real resolution failure was excused as a registry refusal: %q", message)
		}
	}
}
