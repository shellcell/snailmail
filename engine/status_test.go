package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

func TestStatusWorkspaceReportsCommittedEvidenceOnly(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "status-test"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zulu", "alpha"} {
		if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: name, Format: "pypi", HostType: "local", Output: "public/" + name, Visibility: "public"}); err != nil {
			t.Fatal(err)
		}
	}
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "zulu", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "record desired package state")
	result, err := StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.Workspace != "status-test" || result.ObservationScope != "committed workspace evidence only" || len(result.Repositories) != 2 {
		t.Fatalf("status result %#v", result)
	}
	if result.Repositories[0].Name != "alpha" || result.Repositories[1].Name != "zulu" {
		t.Fatalf("repository ordering %#v", result.Repositories)
	}
	zulu := result.Repositories[1]
	if zulu.RetainedPackageVersions != 1 || zulu.VisiblePackageVersions != 1 || zulu.VisibleBindingState != "incomplete" || zulu.Deployment.State != "unrecorded" || len(zulu.VisiblePackages) != 1 || zulu.VisiblePackages[0].Binding != "incomplete" {
		t.Fatalf("zulu status %#v", zulu)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["zulu"])
	if err != nil {
		t.Fatal(err)
	}
	digests := make([]string, 0, len(lock.PackageVersion[0].Blobs))
	for _, locked := range lock.PackageVersion[0].Blobs {
		digests = append(digests, locked.SHA256)
	}
	sort.Strings(digests)
	treeSHA := strings.Repeat("b", 64)
	record := state.PublicationRecord{
		SchemaVersion: state.LedgerSchema, PlanID: strings.Repeat("a", 64), ChangeID: "zulu:" + treeSHA[:12], Repository: "zulu",
		Package: lock.PackageVersion[0].Package, Version: lock.PackageVersion[0].Version, BlobSHA256: digests,
		TreeSHA256: treeSHA, RecordedAt: "2026-07-26T12:00:00Z",
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "publications"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "publications", "zulu.jsonl"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	commitGitPaths(t, root, "record publication binding", "publications/zulu.jsonl")
	result, err = StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	zulu = result.Repositories[1]
	if zulu.VisibleBindingState != "complete" || zulu.VisiblePackages[0].Binding != "complete" {
		t.Fatalf("bound status %#v", zulu)
	}
	base, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.CommitDeployments(root, record.PlanID, strings.TrimSpace(string(base)), []state.DeploymentRecord{{
		Repository: "zulu", PlanID: record.PlanID, ChangeID: record.ChangeID, TreeSHA256: record.TreeSHA256,
		NativeRevision: "local-status-test", DeployedAt: "2026-07-26T12:01:00Z",
	}}); err != nil {
		t.Fatal(err)
	}
	result, err = StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	zulu = result.Repositories[1]
	if zulu.Deployment.State != "recorded" || zulu.Deployment.PlanID != record.PlanID || zulu.Deployment.NativeRevision != "local-status-test" {
		t.Fatalf("deployment status %#v", zulu.Deployment)
	}
	if _, err := Yank(PlacementMutationRequest{Root: root, Repository: "zulu", Package: lock.PackageVersion[0].Package, Version: lock.PackageVersion[0].Version, All: true}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "yank desired package placement")
	statusBefore, err := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	if err != nil {
		t.Fatal(err)
	}
	result, err = StatusWorkspace(context.Background(), StatusWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	zulu = result.Repositories[1]
	if zulu.RetainedPackageVersions != 1 || zulu.VisiblePackageVersions != 0 || zulu.VisibleBindingState != "complete" || len(zulu.VisiblePackages) != 0 {
		t.Fatalf("yanked status %#v", zulu)
	}
	output, err := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	if err != nil || string(output) != string(statusBefore) {
		t.Fatalf("status mutated workspace: %v: %s", err, output)
	}
}

func TestStatusWorkspaceHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "status-cancel"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StatusWorkspace(ctx, StatusWorkspaceRequest{Root: root}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled status error = %v", err)
	}
}
