package engine

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/state"
)

func TestPromoteAndYankPlacementLifecycle(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "placement-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "python", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "configure placement fixture")
	baseTime := time.Date(2026, time.July, 26, 1, 2, 3, 0, time.UTC)
	planAndApply := func(label string, at time.Time, wantChanges int) {
		t.Helper()
		planName := filepath.Join(root, label+".json")
		planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
			Root: root, Output: planName, createdAt: at, GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural",
		})
		if err != nil {
			t.Fatalf("%s plan: %v", label, err)
		}
		if planned.Changes != wantChanges {
			t.Fatalf("%s changes=%d want=%d", label, planned.Changes, wantChanges)
		}
		if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: planName, now: at.Add(time.Minute), StructuralOnly: true}); err != nil {
			t.Fatalf("%s apply: %v", label, err)
		}
	}
	planAndApply("initial", baseTime, 1)

	promoted, err := Promote(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.2.3", Track: "testing"})
	if err != nil || promoted.Changed != 1 {
		t.Fatalf("promote=%#v err=%v", promoted, err)
	}
	if repeated, err := Promote(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.2.3", Track: "testing"}); err != nil || repeated.Changed != 0 {
		t.Fatalf("duplicate promote=%#v err=%v", repeated, err)
	}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: filepath.Join(root, "dirty.json"), createdAt: baseTime.Add(time.Hour)}); err == nil {
		t.Fatal("planning accepted uncommitted promotion")
	}
	commitWorkspace(t, root, "promote package to testing")
	planAndApply("promoted", baseTime.Add(2*time.Hour), 0)

	yanked, err := Yank(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.2.3", Track: "stable"})
	if err != nil || yanked.Changed != 1 {
		t.Fatalf("exact yank=%#v err=%v", yanked, err)
	}
	commitWorkspace(t, root, "yank stable placement")
	planAndApply("one-placement", baseTime.Add(4*time.Hour), 1)
	if result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: filepath.Join(root, "one-placement.json"), now: baseTime.Add(4*time.Hour + 2*time.Minute), StructuralOnly: true}); err != nil || result.Current != 1 {
		t.Fatalf("removal-only apply retry=%#v err=%v", result, err)
	}
	converged, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "one-placement-converged.json"), createdAt: baseTime.Add(5 * time.Hour), GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural",
	})
	if err != nil || converged.Changes != 0 {
		t.Fatalf("removal-only convergence=%#v err=%v", converged, err)
	}

	yanked, err = Yank(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.2.3", All: true})
	if err != nil || yanked.Changed != 1 {
		t.Fatalf("all yank=%#v err=%v", yanked, err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["python"])
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Placement) != 0 || len(lock.PackageVersion) != 1 || len(lock.PackageVersion[0].Blobs) != 1 {
		t.Fatalf("yank removed immutable package state: %#v", lock)
	}
	commitWorkspace(t, root, "yank final placement")
	planAndApply("empty", baseTime.Add(6*time.Hour), 0)
	if result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: filepath.Join(root, "empty.json"), now: baseTime.Add(6*time.Hour + 2*time.Minute), StructuralOnly: true}); err != nil || result.Current != 1 {
		t.Fatalf("empty apply retry=%#v err=%v", result, err)
	}
	converged, err = PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "empty-converged.json"), createdAt: baseTime.Add(7 * time.Hour), GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural",
	})
	if err != nil || converged.Changes != 0 {
		t.Fatalf("empty convergence=%#v err=%v", converged, err)
	}
	empty, err := app.VerifyRepository(filepath.Join(root, "public", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.VerificationCases) != 0 {
		t.Fatalf("empty repository has verification cases: %#v", empty.VerificationCases)
	}

	promoted, err = Promote(PlacementMutationRequest{Root: root, Repository: "python", Package: "snail-demo", Version: "1.2.3"})
	if err != nil || promoted.Changed != 1 || promoted.Track != "stable" {
		t.Fatalf("re-promote=%#v err=%v", promoted, err)
	}
	commitWorkspace(t, root, "restore stable placement")
	planAndApply("restored", baseTime.Add(8*time.Hour), 1)
	if result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: filepath.Join(root, "restored.json"), now: baseTime.Add(8*time.Hour + 2*time.Minute), StructuralOnly: true}); err != nil || result.Current != 1 {
		t.Fatalf("restored apply retry=%#v err=%v", result, err)
	}
	restoredPlan, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "restored-converged.json"), createdAt: baseTime.Add(9 * time.Hour), GeneratedAt: baseTime, ExpiresIn: time.Hour, VerificationMode: "structural",
	})
	if err != nil || restoredPlan.Changes != 0 {
		t.Fatalf("restored convergence=%#v err=%v", restoredPlan, err)
	}
	restored, err := app.VerifyRepository(filepath.Join(root, "public", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.VerificationCases) != 1 {
		t.Fatalf("restored repository cases=%#v", restored.VerificationCases)
	}
	records, err := state.LoadLedgerHistory(root, "python")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("placement lifecycle discarded publication history")
	}
}

func TestFinalYankBuildsEveryEmptyRepositoryFormat(t *testing.T) {
	for _, format := range []string{"pypi", "deb", "helm"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			command := exec.Command("git", "init", "-b", "main")
			command.Dir = root
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v: %s", err, output)
			}
			if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "empty-" + format}); err != nil {
				t.Fatal(err)
			}
			setup := SetupRepositoryRequest{
				Root: root, Name: "packages", Format: format, HostType: "local", Output: "public/packages", Visibility: "public",
			}
			if selected, err := formats.For(format); err == nil && selected.ImplementsSigning() {
				setup.AllowUnsigned = true
			}
			if err := SetupRepository(setup); err != nil {
				t.Fatal(err)
			}
			artifact := workspaceArtifact(t, root, format, "1.2.3")
			added, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "packages", Artifacts: []string{artifact}})
			if err != nil || len(added.Packages) != 1 {
				t.Fatalf("add=%#v err=%v", added, err)
			}
			packageName, version := splitPackageVersion(t, added.Packages[0])
			if result, err := Yank(PlacementMutationRequest{Root: root, Repository: "packages", Package: packageName, Version: version, All: true}); err != nil || result.Changed != 1 {
				t.Fatalf("yank=%#v err=%v", result, err)
			}
			commitWorkspace(t, root, "configure empty "+format+" repository")
			at := time.Date(2026, time.July, 26, 1, 2, 3, 0, time.UTC)
			planName := filepath.Join(root, "empty.json")
			if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName, createdAt: at, GeneratedAt: at, ExpiresIn: time.Hour, VerificationMode: "structural"}); err != nil {
				t.Fatal(err)
			}
			if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: planName, now: at.Add(time.Minute), StructuralOnly: true}); err != nil {
				t.Fatal(err)
			}
			manifest, err := app.VerifyRepository(filepath.Join(root, "public", "packages"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(manifest.Format, format+"/") || len(manifest.VerificationCases) != 0 {
				t.Fatalf("empty %s manifest %#v", format, manifest)
			}
		})
	}
}

func TestPublicationBindingsDescribeEntireLedgerEffect(t *testing.T) {
	lock := state.RepositoryLock{
		PackageVersion: []state.PackageVersion{
			{Package: "demo", Version: "1.0", Blobs: []state.LockedBlob{{SHA256: strings.Repeat("a", 64)}}},
			{Package: "demo", Version: "2.0", Blobs: []state.LockedBlob{{SHA256: strings.Repeat("b", 64)}}},
		},
		Placement: []state.Placement{
			{Package: "demo", Version: "1.0", Track: "stable"},
			{Package: "demo", Version: "2.0", Track: "stable"},
		},
	}
	repository := state.Repository{Format: "pypi", Track: "stable"}
	records := []state.PublicationRecord{{Package: "demo", Version: "1.0", BlobSHA256: []string{strings.Repeat("a", 64)}}}
	missing := missingPublicationBindings(lock, repository, records)
	if len(missing) != 1 || missing[0].Version != "2.0" {
		t.Fatalf("missing bindings %#v", missing)
	}
	effect := publicationBindingsForVersions(visiblePackageVersions(lock, repository))
	if len(effect) != 2 || effect[0].Version != "1.0" || effect[1].Version != "2.0" {
		t.Fatalf("ledger effect bindings %#v", effect)
	}
}

func splitPackageVersion(t *testing.T, value string) (string, string) {
	t.Helper()
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == '@' {
			return value[:index], value[index+1:]
		}
	}
	t.Fatalf("invalid package version %q", value)
	return "", ""
}
