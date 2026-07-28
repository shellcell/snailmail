package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Raw is the one format whose identity does not come from the bytes, so the
// locked build cannot re-inspect an input directory the way the others do.
// This exercises the whole path — lock, plan, apply — because a renderer unit
// test cannot see identity being lost on the way to it.
func TestRawWorkspacePublishesSuppliedIdentity(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "raw-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "tools", Format: "raw", HostType: "local",
		Output: "public/tools", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}

	staging := t.TempDir()
	conventional := filepath.Join(staging, "ttysvg_0.1.2_linux_amd64.tar.gz")
	if err := os.WriteFile(conventional, []byte("conventional payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	unnamed := filepath.Join(staging, "build-final.bin")
	if err := os.WriteFile(unnamed, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := AddArtifacts(AddArtifactsRequest{
		Context: context.Background(), Root: root, Repository: "tools", Artifacts: []string{conventional},
	}); err != nil {
		t.Fatalf("adding a conventionally named artifact failed: %v", err)
	}
	if _, err := AddArtifacts(AddArtifactsRequest{
		Context: context.Background(), Root: root, Repository: "tools", Artifacts: []string{unnamed},
		Name: "ttysvg", Version: "0.2.0",
	}); err != nil {
		t.Fatalf("adding an artifact with supplied identity failed: %v", err)
	}

	commitWorkspace(t, root, "record raw artifacts")

	plan := filepath.Join(root, "raw.snailmail-plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: plan}); err != nil {
		t.Fatalf("planning a raw repository failed: %v", err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{Root: root, Plan: plan}); err != nil {
		t.Fatalf("applying a raw repository failed: %v", err)
	}

	// The published path is the record of identity: an artifact whose name came
	// from an operator flag must still be findable without that flag.
	site := filepath.Join(root, "public", "tools")
	for _, published := range []string{
		"ttysvg/0.1.2/ttysvg_0.1.2_linux_amd64.tar.gz",
		"ttysvg/0.2.0/build-final.bin",
	} {
		if _, err := os.Stat(filepath.Join(site, filepath.FromSlash(published))); err != nil {
			t.Errorf("%s was not published: %v", published, err)
		}
	}

	checksums, err := os.ReadFile(filepath.Join(site, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(strings.TrimSpace(string(checksums)))) / 2; got != 2 {
		t.Fatalf("SHA256SUMS covers %d artifacts, want 2:\n%s", got, checksums)
	}

	if _, err := VerifyRaw(VerifyRawRequest{Repository: site}); err != nil {
		t.Fatalf("verifying the published tree failed: %v", err)
	}
}

// Supplied identity must reach the format so it can refuse. Dropping it before
// the format sees it is worse than refusing: the operator is told the artifact
// was locked, under a name they did not choose and cannot see.
func TestSuppliedIdentityIsRefusedByFormatsThatReadTheBytes(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "identity-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "local",
		Output: "public/python", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}
	wheel := workspaceArtifact(t, root, "pypi", "1.0.0")

	if _, err := AddArtifacts(AddArtifactsRequest{
		Context: context.Background(), Root: root, Repository: "python", Artifacts: []string{wheel},
		Name: "impostor", Version: "9.9.9",
	}); err == nil {
		t.Fatal("relabelling a wheel was accepted")
	}
	// The same artifact without the flags is ordinary and must still be locked.
	if _, err := AddArtifacts(AddArtifactsRequest{
		Context: context.Background(), Root: root, Repository: "python", Artifacts: []string{wheel},
	}); err != nil {
		t.Fatalf("adding a wheel without supplied identity failed: %v", err)
	}
}
