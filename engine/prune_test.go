package engine

import (
	"context"
	"github.com/shellcell/snailmail/formats"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/state"
)

func TestPruneRetainsHistoryAndSupportsRepromotion(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "prune-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	older := workspaceArtifact(t, root, "pypi", "1.9")
	newer := workspaceArtifact(t, root, "pypi", "1.10")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "python", Artifacts: []string{newer, older}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "configure prune fixture")
	baseTime := time.Date(2026, time.July, 26, 2, 3, 4, 0, time.UTC)
	initialPlan := filepath.Join(root, "initial-prune.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: initialPlan, createdAt: baseTime, GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: initialPlan, now: baseTime.Add(time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	result, err := Prune(PruneRequest{Root: root, Repository: "python", Keep: 1})
	if err != nil || result.Removed != 1 {
		t.Fatalf("prune=%#v err=%v", result, err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["python"])
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.PackageVersion) != 2 || len(lock.Placement) != 1 || lock.Placement[0].Version != "1.10" {
		t.Fatalf("pruned lock %#v", lock)
	}
	for _, version := range lock.PackageVersion {
		for _, blob := range version.Blobs {
			_, name, err := state.LoadBlob(root, "pypi", blob, formats.Identity{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(name); err != nil {
				t.Fatalf("prune removed CAS blob: %v", err)
			}
		}
	}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: filepath.Join(root, "dirty-prune.json"), createdAt: baseTime.Add(time.Hour)}); err == nil {
		t.Fatal("planning accepted uncommitted prune")
	}
	commitWorkspace(t, root, "prune old stable placement")
	prunePlanName := filepath.Join(root, "prune.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: prunePlanName, createdAt: baseTime.Add(2 * time.Hour), GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural",
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(prunePlanName)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Changes != 1 || plan.Payload.Repositories[0].PublicationRecords || len(plan.Payload.Repositories[0].PublicationBindings) != 0 {
		t.Fatalf("prune plan effects %#v", plan.Payload.Repositories[0])
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: prunePlanName, now: baseTime.Add(2*time.Hour + time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	if retry, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: prunePlanName, now: baseTime.Add(2*time.Hour + 2*time.Minute), StructuralOnly: true}); err != nil || retry.Current != 1 {
		t.Fatalf("prune retry=%#v err=%v", retry, err)
	}
	published, err := app.VerifyRepository(filepath.Join(root, "public", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if len(published.VerificationCases) != 1 || published.VerificationCases[0].Version != "1.10" {
		t.Fatalf("pruned repository cases %#v", published.VerificationCases)
	}
	if promoted, err := Promote(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.9"}); err != nil || promoted.Changed != 1 {
		t.Fatalf("re-promote=%#v err=%v", promoted, err)
	}
	commitWorkspace(t, root, "re-promote retained package version")
	restorePlanName := filepath.Join(root, "prune-restore.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: restorePlanName, createdAt: baseTime.Add(4 * time.Hour), GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural"}); err != nil {
		t.Fatal(err)
	}
	restorePlan, err := state.LoadPlan(restorePlanName)
	if err != nil {
		t.Fatal(err)
	}
	if restorePlan.Payload.Repositories[0].PublicationRecords {
		t.Fatal("re-promotion attempted to replace historical publication binding")
	}
}
