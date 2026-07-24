package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestWorkspacePlanApplyAllFormats(t *testing.T) {
	for _, format := range []string{"pypi", "deb", "helm"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			artifact := workspaceArtifact(t, root, format, "1.2.3")
			initializeRepository(t, root, format)
			added, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: format, Artifacts: []string{artifact}})
			if err != nil {
				t.Fatal(err)
			}
			if added.Added != 1 {
				t.Fatalf("added %d artifacts, want 1", added.Added)
			}
			createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
			planName := filepath.Join(root, "reviewed.json")
			planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
				Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			if planned.Changes != 1 {
				t.Fatalf("planned %d changes, want 1", planned.Changes)
			}
			applied, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
				Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if applied.Applied != 1 {
				t.Fatalf("applied %d changes, want 1", applied.Applied)
			}
			info, err := InspectRepository(filepath.Join(root, "public", format))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := state.LoadPlan(planName)
			if err != nil {
				t.Fatal(err)
			}
			if info.TreeSHA256 != plan.Payload.Repositories[0].DesiredTreeSHA256 {
				t.Fatal("published tree differs from reviewed plan")
			}
			records, err := state.LoadLedger(root, format)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].PlanID != planned.PlanID {
				t.Fatalf("unexpected publication records: %#v", records)
			}
			retried, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
				Root: root, Plan: planName, Now: createdAt.Add(2 * time.Minute), StructuralOnly: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if retried.Current != 1 || retried.Applied != 0 {
				t.Fatalf("retry was not idempotent: %#v", retried)
			}
		})
	}
}

func TestApplyRejectsLockChangedAfterPlan(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	first := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{first}}); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	second := workspaceArtifact(t, root, "helm", "2.0.0")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{second}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true}); err == nil {
		t.Fatal("expected changed lock to make plan stale")
	}
}

func TestLoadPlanRejectsTamperedPayload(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(planName)
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(content, &plan); err != nil {
		t.Fatal(err)
	}
	payload := plan["payload"].(map[string]any)
	payload["generated_at"] = "2030-01-01T00:00:00Z"
	content, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planName, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := state.LoadPlan(planName); err == nil {
		t.Fatal("expected modified plan payload to fail its ID check")
	}
}

func TestPublishedChartCannotChangeBytes(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	metadata := "apiVersion: v2\nname: snail-demo\nversion: 1.2.3\ndescription: changed bytes\n"
	content, filename, err := testutil.HelmChartWithMetadata("snail-demo", "1.2.3", metadata)
	if err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(root, "inputs", "changed", filename)
	if err := os.MkdirAll(filepath.Dir(changed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{changed}}); err == nil {
		t.Fatal("expected published chart version byte change to fail")
	}
}

func initializeRepository(t *testing.T, root, format string) {
	t.Helper()
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "test-workspace"}); err != nil {
		t.Fatal(err)
	}
	request := SetupRepositoryRequest{Root: root, Name: format, Format: format, Output: filepath.ToSlash(filepath.Join("public", format))}
	if format == "deb" {
		request.Suite, request.Component, request.Architectures = "stable", "main", []string{"amd64"}
	}
	if err := SetupRepository(request); err != nil {
		t.Fatal(err)
	}
}

func workspaceArtifact(t *testing.T, root, format, version string) string {
	t.Helper()
	directory := filepath.Join(root, "inputs", format, version)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	var name string
	var err error
	switch format {
	case "pypi":
		name, err = testutil.WriteWheel(directory, "snail-demo", version, ">=3.8")
	case "deb":
		name, err = testutil.WriteDeb(directory, "snail-demo", version+"-1", "amd64", nil)
	case "helm":
		name, err = testutil.WriteHelmChart(directory, "snail-demo", version)
	default:
		t.Fatalf("unknown fixture format %q", format)
	}
	if err != nil {
		t.Fatal(err)
	}
	return name
}
