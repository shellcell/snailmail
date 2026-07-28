package app

import (
	"context"
	"os/exec"
	"runtime"
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
	reference, platformFlag := platformImage(context.Background(), runner,
		"docker.io/library/debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818", foreign)
	if platformFlag {
		t.Skipf("%s cannot inspect the manifest index; falling back to --platform", runner)
	}
	t.Logf("resolved %s -> %s", foreign, reference)

	// The resolved reference must actually run as that architecture.
	output, err := exec.Command(runner, "run", "--rm", reference, "dpkg", "--print-architecture").Output()
	if err != nil {
		t.Fatalf("resolved reference did not run: %v", err)
	}
	want := "amd64"
	if foreign == "linux/arm64" {
		want = "arm64"
	}
	if got := string(output); got != want+"\n" {
		t.Fatalf("architecture = %q, want %q", got, want)
	}
}
