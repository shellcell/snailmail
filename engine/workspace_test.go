package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
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
			commitWorkspace(t, root, "add artifact")
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

func TestWorkspacePlanApplyRemoteHost(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "phase2-test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "phase2-test-secret-key")
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "remote-workspace"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "python", Region: "us-east-1",
		CanonicalEndpoint: "https://packages.example/python",
	}); err != nil {
		t.Fatal(err)
	}
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "python", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add remote wheel")
	remote := &recordingHost{}
	resolver := staticHostResolver{host: remote}
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "remote.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt,
		ExpiresIn: time.Hour, Hosts: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := os.ReadFile(planName)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(planBytes), "phase2-test-access-key") || strings.Contains(string(planBytes), "phase2-test-secret-key") {
		t.Fatal("provider credentials leaked into plan")
	}
	if plan.Payload.Repositories[0].Host.Type != "s3" || plan.Payload.Repositories[0].ObservedRevision != "" || plan.Payload.Repositories[0].CanonicalEndpoint != "https://packages.example/python" ||
		plan.Payload.Repositories[0].InstallDocSHA256 == "" || plan.Payload.Repositories[0].DesiredManifestSHA256 == "" {
		t.Fatalf("plan did not bind remote host state: %#v", plan.Payload.Repositories[0])
	}
	document, err := os.ReadFile(filepath.Join(root, "docs", "install-python.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), "python -m pip install --index-url 'https://packages.example/python/simple/' PACKAGE") {
		t.Fatalf("unexpected install document %q", document)
	}
	result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true, Hosts: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied != 1 || remote.stageCalls != 1 || remote.commitCalls != 1 || remote.revision.TreeSHA256 != plan.Payload.Repositories[0].DesiredTreeSHA256 {
		t.Fatalf("unexpected remote apply result %#v stage=%d commit=%d revision=%#v", result, remote.stageCalls, remote.commitCalls, remote.revision)
	}
	retried, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(2 * time.Minute), StructuralOnly: true, Hosts: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if retried.Current != 1 || remote.stageCalls != 1 || remote.commitCalls != 1 {
		t.Fatalf("remote retry was not idempotent: %#v", retried)
	}
	remote.revision.ManifestSHA256 = strings.Repeat("f", 64)
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(3 * time.Minute), StructuralOnly: true, Hosts: resolver,
	}); err == nil || !strings.Contains(err.Error(), "desired tree was published by another change") {
		t.Fatalf("apply accepted a different desired manifest: %v", err)
	}
	records, err := state.LoadLedger(root, "python")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PlanID != planned.PlanID {
		t.Fatalf("unexpected remote publication records %#v", records)
	}
	remote.revision.ManifestSHA256 = plan.Payload.Repositories[0].DesiredManifestSHA256
	secondPlanName := filepath.Join(root, "remote-second.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: secondPlanName, CreatedAt: createdAt.Add(10 * time.Minute), GeneratedAt: createdAt.Add(10 * time.Minute),
		ExpiresIn: time.Hour, Hosts: resolver,
	}); err != nil {
		t.Fatal(err)
	}
	secondPlan, err := state.LoadPlan(secondPlanName)
	if err != nil {
		t.Fatal(err)
	}
	if secondPlan.Payload.Repositories[0].Action != "update" || secondPlan.Payload.Repositories[0].ObservedTreeSHA256 != secondPlan.Payload.Repositories[0].DesiredTreeSHA256 ||
		secondPlan.Payload.Repositories[0].ObservedManifestSHA256 == secondPlan.Payload.Repositories[0].DesiredManifestSHA256 {
		t.Fatalf("same-tree manifest change was not planned as an update: %#v", secondPlan.Payload.Repositories[0])
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: secondPlanName, Now: createdAt.Add(11 * time.Minute), StructuralOnly: true, Hosts: resolver,
	}); err != nil {
		t.Fatalf("apply same-tree manifest update: %v", err)
	}
}

func TestApplyRejectsLockChangedAfterPlan(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	first := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{first}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add first chart")
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
	commitWorkspace(t, root, "add wheel")
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

func TestApplyRejectsStructurallyInvalidRehashedPlan(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add wheel")
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName}); err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	plan.Payload.Repositories[0].DesiredTreeSHA256 = "00"
	plan.Payload.Repositories[0].ChangeID = "pypi:00"
	plan, err = state.FinalizePlan(plan.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.WritePlan(planName, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: planName, StructuralOnly: true}); err == nil {
		t.Fatal("expected structurally invalid rehashed plan to be rejected")
	}
}

func TestPublishedChartCannotChangeBytes(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add chart")
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

func TestPlanRequiresCommittedAuthoritativeState(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root}); err == nil {
		t.Fatal("expected uncommitted manifest and lock to block planning")
	}
}

func TestPlanRejectsUntrackedCustomLock(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	repository := manifest.Repositories["pypi"]
	oldLock, err := state.WorkspacePath(root, repository.Lock)
	if err != nil {
		t.Fatal(err)
	}
	repository.Lock = "state/custom-pypi.lock.toml"
	manifest.Repositories["pypi"] = repository
	newLock, err := state.WorkspacePath(root, repository.Lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(newLock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldLock, newLock); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteManifest(root, manifest); err != nil {
		t.Fatal(err)
	}
	commitGitPaths(t, root, "configure custom lock", ".gitignore", "snailmail.toml")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root}); err == nil {
		t.Fatal("expected untracked custom lock to block planning")
	}
}

func TestWorkspaceSupportsNestedGitDirectory(t *testing.T) {
	top := t.TempDir()
	if output, err := exec.Command("git", "-C", top, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	root := filepath.Join(top, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "nested-workspace"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "pypi", Format: "pypi", Output: "public/pypi"}); err != nil {
		t.Fatal(err)
	}
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add nested wheel")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	paths, err := exec.Command("git", "-C", top, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(paths) != "workspace/publications/pypi.jsonl\n" {
		t.Fatalf("unexpected nested publication path %q", paths)
	}
}

func TestPlanRejectsAssumeUnchangedAuthoritativeFile(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	commitWorkspace(t, root, "initialize workspace")
	if output, err := exec.Command("git", "-C", root, "update-index", "--assume-unchanged", "repos/pypi.lock.toml").CombinedOutput(); err != nil {
		t.Fatalf("git update-index: %v: %s", err, output)
	}
	lockName := filepath.Join(root, "repos", "pypi.lock.toml")
	file, err := os.OpenFile(lockName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("# hidden worktree change\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root}); err == nil {
		t.Fatal("expected hidden authoritative change to block planning")
	}
}

func TestWorkspaceUsesConfiguredGitIndex(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add chart")
	indexContent, err := os.ReadFile(filepath.Join(root, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	customIndex := filepath.Join(root, "custom.git-index")
	if err := os.WriteFile(customIndex, indexContent, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_INDEX_FILE", customIndex)
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(customIndex); err != nil {
		t.Fatal("apply did not preserve the configured Git index")
	}
}

func TestNoopPlanDoesNotWritePublicationLedger(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add wheel")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	firstPlan := filepath.Join(root, "first.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: firstPlan, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: firstPlan, Now: createdAt.Add(time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	headBefore, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	ledgerName := filepath.Join(root, "publications", "pypi.jsonl")
	ledgerBefore, err := os.ReadFile(ledgerName)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan := filepath.Join(root, "second.json")
	secondCreatedAt := createdAt.Add(5 * time.Minute)
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: secondPlan, CreatedAt: secondCreatedAt, GeneratedAt: createdAt, ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if planned.Changes != 0 {
		t.Fatalf("planned %d changes, want no-op", planned.Changes)
	}
	result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: secondPlan, Now: secondCreatedAt.Add(time.Minute), StructuralOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied != 0 || result.Current != 1 {
		t.Fatalf("unexpected no-op result %#v", result)
	}
	headAfter, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	ledgerAfter, err := os.ReadFile(ledgerName)
	if err != nil {
		t.Fatal(err)
	}
	if string(headAfter) != string(headBefore) || string(ledgerAfter) != string(ledgerBefore) {
		t.Fatal("no-op apply changed Git or publication ledger state")
	}
}

func TestPutArtifactRejectsCorruptExistingCASObject(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	blob, err := state.PutArtifact(root, "pypi", artifact)
	if err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(root, ".snailmail", "cas", "sha256", blob.SHA256[:2], blob.SHA256)
	if err := os.Chmod(stored, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, make([]byte, blob.Size), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := state.PutArtifact(root, "pypi", artifact); err == nil {
		t.Fatal("expected corrupt existing CAS object to be rejected")
	}
}

func TestApplyRejectsForgedLedgerRetryCommit(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add chart")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["helm"])
	if err != nil {
		t.Fatal(err)
	}
	packageVersion := activeLock(lock).PackageVersion[0]
	forged := state.PublicationRecord{
		SchemaVersion: state.LedgerSchema,
		PlanID:        "forged-plan",
		ChangeID:      "forged-change",
		Repository:    "helm",
		Package:       packageVersion.Package,
		Version:       packageVersion.Version,
		BlobSHA256:    []string{packageVersion.Blobs[0].SHA256},
		TreeSHA256:    plan.Payload.Repositories[0].DesiredTreeSHA256,
		RecordedAt:    plan.Payload.CreatedAt,
	}
	content, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(root, "publications", "helm.jsonl")
	if err := os.MkdirAll(filepath.Dir(ledger), 0o755); err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(ledger, content, 0o644); err != nil {
		t.Fatal(err)
	}
	commitGitPaths(t, root, "forged publication\n\nSnailmail-Plan: "+planned.PlanID, "publications/helm.jsonl")
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true,
	}); err == nil {
		t.Fatal("expected forged publication commit to be rejected")
	}
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(content) {
		t.Fatal("rejected retry modified the committed publication ledger")
	}
	if _, err := os.Lstat(filepath.Join(root, "public", "helm")); !os.IsNotExist(err) {
		t.Fatal("rejected retry published a target")
	}
}

func TestLedgerCommitRejectsChangedIndex(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add wheel")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["pypi"])
	if err != nil {
		t.Fatal(err)
	}
	plannedRepository := plan.Payload.Repositories[0]
	if err := state.AppendPublicationRecords(root, "pypi", planned.PlanID, plannedRepository.ChangeID, plannedRepository.DesiredTreeSHA256, plan.Payload.CreatedAt, activeLock(lock)); err != nil {
		t.Fatal(err)
	}
	gitignore := filepath.Join(root, ".gitignore")
	file, err := os.OpenFile(gitignore, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("# concurrent index change\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", ".gitignore").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	if _, err := state.CommitPublicationLedgers(root, planned.PlanID, plan.Payload.GitRevision, []string{"pypi"}); err == nil {
		t.Fatal("expected changed Git index to block ledger commit")
	}
	current, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != plan.Payload.GitRevision+"\n" {
		t.Fatal("failed ledger commit changed HEAD")
	}
}

func TestApplyResumesAfterLedgerCommitBeforePublication(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add chart")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["helm"])
	if err != nil {
		t.Fatal(err)
	}
	repository := plan.Payload.Repositories[0]
	if err := state.PreparePublicationRecords(
		root, plan.Payload.GitRevision, "helm", planned.PlanID, repository.ChangeID,
		repository.DesiredTreeSHA256, plan.Payload.CreatedAt, activeLock(lock),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := state.CommitPublicationLedgers(root, planned.PlanID, plan.Payload.GitRevision, []string{"helm"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "public", "helm")); !os.IsNotExist(err) {
		t.Fatal("ledger-only transaction unexpectedly published the target")
	}
	result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, Now: createdAt.Add(time.Minute), StructuralOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied != 1 {
		t.Fatalf("resumed apply result %#v", result)
	}
}

func TestLedgerCommitStagesAssumeUnchangedLedger(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "pypi")
	first := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{first}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add first wheel")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	firstPlan := filepath.Join(root, "first.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: firstPlan, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: firstPlan, Now: createdAt.Add(time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	second := workspaceArtifact(t, root, "pypi", "2.0.0")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "pypi", Artifacts: []string{second}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add second wheel")
	secondCreatedAt := createdAt.Add(5 * time.Minute)
	secondPlan := filepath.Join(root, "second.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: secondPlan, CreatedAt: secondCreatedAt, GeneratedAt: secondCreatedAt, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "update-index", "--assume-unchanged", "publications/pypi.jsonl").CombinedOutput(); err != nil {
		t.Fatalf("git update-index: %v: %s", err, output)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: secondPlan, Now: secondCreatedAt.Add(time.Minute), StructuralOnly: true}); err != nil {
		t.Fatal(err)
	}
	records, err := state.LoadLedger(root, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("ledger has %d records, want 3", len(records))
	}
}

func TestLedgerCommitRestoresIndexWhenRefTransactionFails(t *testing.T) {
	root := t.TempDir()
	initializeRepository(t, root, "helm")
	artifact := workspaceArtifact(t, root, "helm", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "helm", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "add chart")
	createdAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	planName := filepath.Join(root, "reviewed.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName, CreatedAt: createdAt, GeneratedAt: createdAt, ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["helm"])
	if err != nil {
		t.Fatal(err)
	}
	repository := plan.Payload.Repositories[0]
	if err := state.PreparePublicationRecords(root, plan.Payload.GitRevision, "helm", planned.PlanID, repository.ChangeID, repository.DesiredTreeSHA256, plan.Payload.CreatedAt, activeLock(lock)); err != nil {
		t.Fatal(err)
	}
	indexName := filepath.Join(root, ".git", "index")
	indexBefore, err := os.ReadFile(indexName)
	if err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(root, ".git", "hooks", "reference-transaction")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\n[ \"$1\" != prepared ]\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := state.CommitPublicationLedgers(root, planned.PlanID, plan.Payload.GitRevision, []string{"helm"}); err == nil {
		t.Fatal("expected reference transaction hook to reject ledger commit")
	}
	indexAfter, err := os.ReadFile(indexName)
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("failed ref transaction did not restore the Git index")
	}
	current, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != plan.Payload.GitRevision+"\n" {
		t.Fatal("rejected ref transaction changed HEAD")
	}
}

func TestCleanGitRejectsShallowHistory(t *testing.T) {
	source := t.TempDir()
	initializeRepository(t, source, "pypi")
	commitWorkspace(t, source, "initialize workspace")
	clone := filepath.Join(t.TempDir(), "clone")
	if output, err := exec.Command("git", "clone", "--depth=1", "file://"+source, clone).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v: %s", err, output)
	}
	if _, err := state.RequireCleanGit(clone); err == nil {
		t.Fatal("expected shallow Git history to be rejected")
	}
}

func TestVerifiedPublicationHonorsTargetPrecondition(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "snail-demo", "1.2.3", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	target := filepath.Join(t.TempDir(), "repository")
	initial, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: target, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	desiredInput := t.TempDir()
	if _, err := testutil.WriteWheel(desiredInput, "snail-demo", "2.0.0", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "repository")
	desired, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: desiredInput, Output: staged, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	rogueInput := t.TempDir()
	if _, err := testutil.WriteWheel(rogueInput, "snail-demo", "3.0.0", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	rogue, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: rogueInput, Output: target, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.PublishVerifiedDirectory(context.Background(), staged, target, initial.TreeSHA256, desired.TreeSHA256); err == nil {
		t.Fatal("expected changed target to reject verified publication")
	}
	current, err := InspectRepository(target)
	if err != nil {
		t.Fatal(err)
	}
	if current.TreeSHA256 != rogue.TreeSHA256 {
		t.Fatal("stale publication overwrote the newer target")
	}
}

func initializeRepository(t *testing.T, root, format string) {
	t.Helper()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
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

func commitWorkspace(t *testing.T, root, message string) {
	t.Helper()
	paths := []string{".gitignore", "snailmail.toml", "repos"}
	if info, err := os.Lstat(filepath.Join(root, "docs")); err == nil && info.IsDir() {
		paths = append(paths, "docs")
	}
	arguments := append([]string{"-C", root, "add", "--"}, paths...)
	if output, err := exec.Command("git", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	command := exec.Command("git", "-C", root,
		"-c", "user.name=snailmail-test", "-c", "user.email=test@example.invalid",
		"commit", "-m", message,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
}

func commitGitPaths(t *testing.T, root, message string, paths ...string) {
	t.Helper()
	arguments := append([]string{"-C", root, "add", "--"}, paths...)
	if output, err := exec.Command("git", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	command := exec.Command("git", "-C", root,
		"-c", "user.name=snailmail-test", "-c", "user.email=test@example.invalid",
		"commit", "-m", message,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
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

type staticHostResolver struct {
	host host.Host
}

func (resolver staticHostResolver) Resolve(context.Context, host.Repository) (host.Host, error) {
	return resolver.host, nil
}

type recordingHost struct {
	revision    host.PublishedRevision
	staged      host.StagedPublication
	stageCalls  int
	commitCalls int
}

func (remote *recordingHost) Capabilities(context.Context, host.Repository) (host.Capabilities, error) {
	return host.Capabilities{FaithfulPreview: true, ConditionalCommit: true, ConditionalRestore: true}, nil
}

func (remote *recordingHost) Observe(context.Context, host.Repository) (host.PublishedRevision, error) {
	return remote.revision, nil
}

func (remote *recordingHost) Stage(_ context.Context, _ host.Repository, request host.StageRequest) (host.StagedPublication, error) {
	remote.stageCalls++
	remote.staged = host.StagedPublication{
		ID: request.PlanID + ":" + request.ChangeID, PlanID: request.PlanID, ChangeID: request.ChangeID,
		PreviewEndpoint: "https://preview.example/python",
		TreeSHA256:      request.TreeSHA256, Files: request.Files, CommitPaths: request.CommitPaths,
	}
	return remote.staged, nil
}

func (remote *recordingHost) Commit(_ context.Context, repository host.Repository, staged host.StagedPublication, expected host.ExpectedRevision) (host.CommitResult, error) {
	remote.commitCalls++
	if expected.NativeRevision != remote.revision.NativeRevision || expected.TreeSHA256 != remote.revision.TreeSHA256 || staged.ID != remote.staged.ID {
		return host.CommitResult{}, errors.New("remote commit precondition mismatch")
	}
	manifestSHA256 := ""
	for _, file := range staged.Files {
		if file.Path == "snailmail.repository.json" {
			manifestSHA256 = file.SHA256
			break
		}
	}
	remote.revision = host.PublishedRevision{
		NativeRevision: "revision-1", TreeSHA256: staged.TreeSHA256,
		PlanID: staged.PlanID, ChangeID: staged.ChangeID,
		ReleaseSHA256: strings.Repeat("1", 64), ManifestSHA256: manifestSHA256,
		RestoreID: strings.Repeat("2", 64), RestoreSHA256: strings.Repeat("3", 64),
	}
	return host.CommitResult{Revision: remote.revision, CanonicalEndpoint: repository.CanonicalEndpoint}, nil
}

func (remote *recordingHost) Restore(context.Context, host.Repository, host.RestoreRef, host.ExpectedRevision) (host.PublishedRevision, error) {
	return host.PublishedRevision{}, errors.New("unexpected restore")
}

func (remote *recordingHost) Abort(context.Context, host.Repository, host.StagedPublication) error {
	return nil
}
