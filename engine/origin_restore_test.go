package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

// adoptedWorkspace builds a workspace holding one adopted artifact, and returns
// the workspace root, the origin the lock recorded, and its bytes.
func adoptedWorkspace(t *testing.T) (string, string, []byte, source.Fetcher) {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "restore-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "local",
		Output: "public/python", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}
	artifact, err := testutil.WriteWheel(t.TempDir(), "demo", "1.2.3", ">=3.8")
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	origin := "https://downloads.example/" + filepath.Base(artifact)
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{origin: {StatusCode: 200, Body: content}}}
	if _, err := AdoptArtifact(context.Background(), AdoptArtifactRequest{
		Root: root, Repository: "python", URL: origin, SHA256: hex.EncodeToString(digest[:]),
		PublicOrigin: true, Fetcher: fetcher,
	}); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "adopt an artifact")
	return root, origin, content, fetcher
}

// discardCAS removes the workspace's content-addressed bytes, which is the state
// of any fresh clone: .gitignore keeps .snailmail out of Git, so CI holds the
// lock and none of the artifacts.
func discardCAS(t *testing.T, root string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(root, ".snailmail", "cas")); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRestoresAbsentBlobsFromTheirRecordedOrigin(t *testing.T) {
	root, _, _, fetcher := adoptedWorkspace(t)
	discardCAS(t, root)

	// Without the origin this is the failure a fresh clone hits today.
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "no-origin.snailmail-plan.json"),
	}); err == nil {
		t.Fatal("planning without any blob authority was expected to fail")
	}

	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "restored.snailmail-plan.json"), Sources: fetcher,
	}); err != nil {
		t.Fatalf("planning with a recorded origin failed: %v", err)
	}
}

// The digest in the lock was reviewed and committed, so an origin that has since
// been repointed must fail rather than publish whatever it now serves.
func TestRestoreRejectsAnOriginServingDifferentBytes(t *testing.T) {
	root, origin, content, _ := adoptedWorkspace(t)
	discardCAS(t, root)

	tampered := append(append([]byte(nil), content...), " extra"...)
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{origin: {StatusCode: 200, Body: tampered}}}
	_, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "tampered.snailmail-plan.json"), Sources: fetcher,
	})
	if err == nil {
		t.Fatal("an origin serving different bytes was accepted")
	}
	// Nothing may survive in the CAS: a rejected restore that left bytes behind
	// would be indistinguishable from a good one on the next run.
	if entries, statErr := os.ReadDir(filepath.Join(root, ".snailmail", "cas", "sha256")); statErr == nil && len(entries) != 0 {
		t.Fatalf("a rejected restore left %d entries in the CAS", len(entries))
	}
}

func TestRestoreReportsAnUnreachableOrigin(t *testing.T) {
	root, origin, _, _ := adoptedWorkspace(t)
	discardCAS(t, root)

	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{origin: {StatusCode: 404}}}
	_, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "missing.snailmail-plan.json"), Sources: fetcher,
	})
	if err == nil {
		t.Fatal("a missing origin was accepted")
	}
	// The operator has to be able to see which artifact and which URL failed.
	if !strings.Contains(err.Error(), origin) {
		t.Fatalf("error does not name the origin: %v", err)
	}
}

// A blob that is present and wrong is not absence. Replacing it from the network
// would hide precisely the tampering the digest exists to reveal.
func TestRestoreLeavesACorruptLocalBlobAlone(t *testing.T) {
	root, origin, content, fetcher := adoptedWorkspace(t)
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	object := filepath.Join(root, ".snailmail", "cas", "sha256", digestText[:2], digestText)
	if err := os.Chmod(object, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("corrupted"), 0o444); err != nil {
		t.Fatal(err)
	}
	_, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "corrupt.snailmail-plan.json"), Sources: fetcher,
	})
	if err == nil {
		t.Fatal("a corrupt local blob was silently replaced from its origin")
	}
	if strings.Contains(err.Error(), origin) {
		t.Fatalf("corruption was treated as absence and refetched: %v", err)
	}
}

// Restoration must not become a way to reach a private address through a lock.
func TestRestoreRefusesANonPublicOrigin(t *testing.T) {
	root, _, content, _ := adoptedWorkspace(t)
	discardCAS(t, root)

	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lockName, err := state.WorkspacePath(root, manifest.Repositories["python"].Lock)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(lockName)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(lock), "https://downloads.example/", "http://127.0.0.1:9/", 1)
	if rewritten == string(lock) {
		t.Fatal("lock does not record the origin URL as expected")
	}
	if err := os.WriteFile(lockName, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	commitWorkspace(t, root, "repoint the origin")

	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{
		"http://127.0.0.1:9/" + "demo-1.2.3-py3-none-any.whl": {StatusCode: 200, Body: content},
	}}
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: filepath.Join(root, "private.snailmail-plan.json"), Sources: fetcher,
	}); err == nil {
		t.Fatal("a loopback origin was fetched")
	}
}
