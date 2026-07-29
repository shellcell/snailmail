package engine

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/testutil"
)

// A workspace with enough artifacts that the cost of planning one is visible.
func benchWorkspace(b *testing.B, versions int) string {
	b.Helper()
	root := b.TempDir()
	if out, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		b.Fatalf("git init: %v: %s", err, out)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "bench"}); err != nil {
		b.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "apt", Format: "deb", HostType: "local", Output: "public/apt",
		Visibility: "public", Suite: "stable", Component: "main",
		Architectures: []string{"amd64"}, AllowUnsigned: true,
	}); err != nil {
		b.Fatal(err)
	}
	staging := b.TempDir()
	for i := range versions {
		name, err := testutil.WriteDeb(staging, "demo", fmt.Sprintf("1.%d.0", i), "amd64", nil)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "apt", Artifacts: []string{name}}); err != nil {
			b.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.email=b@b", "-c", "user.name=b", "commit", "-qm", "state"}} {
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			b.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return root
}

func BenchmarkPlanWorkspace(b *testing.B) {
	for _, n := range []int{20, 40, 80} {
		b.Run(fmt.Sprintf("%dversions", n), func(b *testing.B) { benchPlan(b, n) })
	}
}

func benchPlan(b *testing.B, versions int) {
	root := benchWorkspace(b, versions)
	for b.Loop() {
		if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
			Root: root, Output: filepath.Join(b.TempDir(), "plan.json"),
			ExpiresIn: time.Hour, VerificationMode: "structural",
		}); err != nil {
			b.Fatal(err)
		}
	}
}
