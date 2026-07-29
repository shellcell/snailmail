package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/state"
)

// A workspace of several repositories is prepared concurrently and committed in
// order. This exercises that with the race detector: preparation reads the
// manifest, the locks and the content-addressed store, and writes into staging
// directories, all of which are shared enough to be worth proving.
func multiRepositoryWorkspace(t *testing.T, formats ...string) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "concurrent-apply"}); err != nil {
		t.Fatal(err)
	}
	for _, format := range formats {
		setup := SetupRepositoryRequest{
			Root: root, Name: format, Format: format, HostType: "local",
			Output: "public/" + format, Visibility: "public", AllowUnsigned: true,
		}
		if format == "deb" {
			setup.Suite, setup.Component, setup.Architectures = "stable", "main", []string{"amd64"}
		}
		if err := SetupRepository(setup); err != nil {
			t.Fatal(err)
		}
		// Two versions each, so more than one repository has more than one thing
		// to do and the preparations genuinely overlap.
		for _, version := range []string{"1.2.3", "1.3.0"} {
			artifact := workspaceArtifact(t, root, format, version)
			if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: format, Artifacts: []string{artifact}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	commitWorkspace(t, root, "desired state")
	return root
}

func TestApplyPreparesRepositoriesConcurrently(t *testing.T) {
	formats := []string{"pypi", "deb", "helm"}
	root := multiRepositoryWorkspace(t, formats...)

	planName := filepath.Join(root, "plan.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	})
	if err != nil {
		t.Fatal(err)
	}
	if planned.Changes != len(formats) {
		t.Fatalf("planned %d changes, want %d", planned.Changes, len(formats))
	}
	applied, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Applied != len(formats) {
		t.Fatalf("applied %d repositories, want %d", applied.Applied, len(formats))
	}
	// Every repository must actually be published: a preparation whose result
	// was dropped on the floor would still let the apply report success.
	for _, format := range formats {
		published := filepath.Join(root, "public", format)
		entries, err := os.ReadDir(published)
		if err != nil || len(entries) == 0 {
			t.Errorf("repository %q published nothing: %v", format, err)
		}
	}
}

// A failure in one repository must not leave another's staged tree behind, and
// must name the same repository however the goroutines were scheduled.
func TestApplyReportsTheFirstFailureInPlanOrder(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi", "deb", "helm")
	planName := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	// Changing a lock after the plan makes exactly one repository stale, which
	// every apply below must agree about.
	lock := filepath.Join(root, "repos", "deb.lock.toml")
	content, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, append(content, []byte("\n# changed after planning\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	first := ""
	for range 5 {
		_, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
			Root: root, Plan: planName, StructuralOnly: true,
		})
		if err == nil {
			t.Fatal("a stale lock was accepted")
		}
		if first == "" {
			first = err.Error()
		}
		if err.Error() != first {
			t.Fatalf("the same defect was reported two ways:\n%s\n%s", first, err)
		}
	}
}

// A failed apply releases the workspace lock.
//
// openApply takes the lock and hands it back for the caller to defer, so the
// lock outlives the call that acquired it. Every way of failing in between has
// to release it — when one did not, the workspace stayed locked by a process
// that had already exited, and the next run failed with "another snailmail
// workspace operation is running" instead of the real problem.
func TestFailedApplyReleasesTheWorkspaceLock(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi", "deb")
	planName := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	// Make the plan stale, so the apply fails after the lock has been taken.
	lock := filepath.Join(root, "repos", "deb.lock.toml")
	content, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, append(content, []byte("\n# changed after planning\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true,
	}); err == nil {
		t.Fatal("a stale plan was accepted")
	}
	// The lock must be free: taking it here is what proves the failed apply let
	// go of it, and any other workspace operation would find the same.
	release, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		t.Fatalf("the workspace stayed locked after a failed apply: %v", err)
	}
	release()
}

// Artifacts are read concurrently, so a repository must build identically
// however the goroutines were scheduled — and a failure must name the same
// artifact every time.
func TestConcurrentBlobLoadingIsDeterministic(t *testing.T) {
	root := multiRepositoryWorkspace(t, "deb", "helm")
	planName := filepath.Join(root, "plan.json")

	digests := map[string]bool{}
	for range 4 {
		os.RemoveAll(filepath.Join(root, "public"))
		if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
			Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
		}); err != nil {
			t.Fatal(err)
		}
		plan, err := state.LoadPlan(planName)
		if err != nil {
			t.Fatal(err)
		}
		for _, repository := range plan.Payload.Repositories {
			digests[repository.Name+":"+repository.DesiredTreeSHA256] = true
		}
	}
	// Two repositories, one digest each: more would mean the tree depended on
	// which artifact finished reading first.
	if len(digests) != 2 {
		t.Fatalf("planning four times produced %d distinct trees: %v", len(digests), digests)
	}
}
