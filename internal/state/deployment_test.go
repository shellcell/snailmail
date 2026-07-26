package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDeploymentAcceptsSchemaOneWithoutRotationProof(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "deployments"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := DeploymentRecord{
		SchemaVersion: 1, Repository: "debian", PlanID: strings.Repeat("a", 64), ChangeID: "debian:" + strings.Repeat("b", 12),
		TreeSHA256: strings.Repeat("b", 64), NativeRevision: "native", DeployedAt: "2026-07-25T00:00:00Z",
	}
	content, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deployments", "debian.json"), append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeployment(root, "debian")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != 1 || loaded.TrustSince != "" || len(loaded.TrustedSigningFingerprints) != 0 {
		t.Fatalf("schema-one receipt gained rotation authority: %#v", loaded)
	}
}

func TestCommitDeploymentsRestoresWorktreeOnGitFailure(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-b", "main").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := Init(root, InitOptions{Name: "deployment-test"}); err != nil {
		t.Fatal(err)
	}
	if err := Setup(root, SetupOptions{Name: "python", Format: "pypi", Output: "public/python"}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", ".gitignore", "snailmail.toml", "repos").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "initialize")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	base, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CommitDeployments(root, strings.Repeat("a", 64), base, []DeploymentRecord{{
		Repository: "python", PlanID: strings.Repeat("a", 64), ChangeID: "python:bbbbbbbbbbbb",
		TreeSHA256: strings.Repeat("b", 64), NativeRevision: "native", DeployedAt: "2026-07-25T00:00:00Z",
		ActiveSigningFingerprint: strings.Repeat("c", 40), TrustedSigningFingerprints: []string{strings.Repeat("c", 40), strings.Repeat("c", 40)},
		SigningRotationPhase: "introducing", SigningMinimumRefreshSeconds: MinimumSigningRefreshSeconds, TrustSince: "2026-07-25T00:00:00Z",
	}}); err == nil {
		t.Fatal("deployment commit accepted malformed signing trust")
	}
	indexPath, err := resolveGitPath(root, "index")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath+".lock", []byte("busy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = CommitDeployments(root, strings.Repeat("a", 64), base, []DeploymentRecord{{
		Repository: "python", PlanID: strings.Repeat("a", 64), ChangeID: "python:bbbbbbbbbbbb",
		TreeSHA256: strings.Repeat("b", 64), NativeRevision: "native", DeployedAt: "2026-07-25T00:00:00Z",
	}})
	if err == nil {
		t.Fatal("deployment commit unexpectedly ignored busy Git index")
	}
	if _, err := os.Lstat(filepath.Join(root, "deployments", "python.json")); !os.IsNotExist(err) {
		t.Fatalf("failed deployment commit left authoritative file: %v", err)
	}
}

func TestValidateDeploymentProvenanceRequiresManagedCommit(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-b", "main").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := Init(root, InitOptions{Name: "deployment-provenance"}); err != nil {
		t.Fatal(err)
	}
	if err := Setup(root, SetupOptions{Name: "python", Format: "pypi", Output: "public/python"}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", ".gitignore", "snailmail.toml", "repos").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "initialize")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	base, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	planID := strings.Repeat("a", 64)
	record := DeploymentRecord{
		Repository: "python", PlanID: planID, ChangeID: "python:bbbbbbbbbbbb",
		TreeSHA256: strings.Repeat("b", 64), NativeRevision: "native", DeployedAt: "2026-07-25T00:00:00Z",
	}
	if _, err := CommitDeployments(root, planID, base, []DeploymentRecord{record}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeployment(root, "python")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDeploymentProvenance(root, "python", loaded); err != nil {
		t.Fatalf("managed receipt rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateDeploymentProvenanceContext(ctx, root, "python", loaded); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled provenance error = %v", err)
	}
	loaded.NativeRevision = "fabricated"
	content, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deployments", "python.json"), append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", "deployments/python.json").CombinedOutput(); err != nil {
		t.Fatalf("git add fabricated receipt: %v: %s", err, output)
	}
	commit = exec.Command("git", "-C", root, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "fabricate receipt")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit fabricated receipt: %v: %s", err, output)
	}
	if err := ValidateDeploymentProvenance(root, "python", loaded); err == nil {
		t.Fatal("manually committed deployment record was accepted as managed")
	}
}
