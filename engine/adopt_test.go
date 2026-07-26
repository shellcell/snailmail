package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

func TestAdoptArtifactPinsOriginAndSupportsDryRun(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "adopt-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
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
	digestText := hex.EncodeToString(digest[:])
	origin := "https://downloads.example/" + filepath.Base(artifact)
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{origin: {StatusCode: 200, Body: content}}}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lockName, err := state.WorkspacePath(root, manifest.Repositories["python"].Lock)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(lockName)
	if err != nil {
		t.Fatal(err)
	}
	request := AdoptArtifactRequest{Root: root, Repository: "python", URL: origin, SHA256: digestText, DryRun: true, PublicOrigin: true, Fetcher: fetcher}
	dryRun, err := AdoptArtifact(context.Background(), request)
	if err != nil || !dryRun.Changed || !dryRun.DryRun {
		t.Fatalf("dry-run result=%#v err=%v", dryRun, err)
	}
	after, err := os.ReadFile(lockName)
	if err != nil || string(after) != string(before) {
		t.Fatalf("dry-run changed lock: %v", err)
	}
	request.DryRun = false
	adopted, err := AdoptArtifact(context.Background(), request)
	if err != nil || !adopted.Changed {
		t.Fatalf("adopt result=%#v err=%v", adopted, err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["python"])
	if err != nil {
		t.Fatal(err)
	}
	locked := lock.PackageVersion[0].Blobs[0]
	if lock.SchemaVersion != state.LockSchema || locked.Origin == nil || locked.Origin.URL != origin || locked.SHA256 != digestText {
		t.Fatalf("adopted lock %#v", lock)
	}
	if _, _, err := state.LoadBlob(root, "pypi", locked); err != nil {
		t.Fatalf("adopted CAS blob: %v", err)
	}
	commitWorkspace(t, root, "record adopted artifact")
	planName := filepath.Join(root, "adopt-plan.json")
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root, Output: planName})
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.Acquisitions) != 1 || planned.Acquisitions[0].OriginURL != origin || planned.Acquisitions[0].SHA256 != digestText {
		t.Fatalf("adoption not visible in plan: %#v", planned.Acquisitions)
	}
	plan, err := state.LoadPlan(planName)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Payload.Repositories) != 1 || len(plan.Payload.Repositories[0].Acquisitions) != 1 {
		t.Fatalf("plan payload omitted acquisition: %#v", plan.Payload.Repositories)
	}
	repeated, err := AdoptArtifact(context.Background(), request)
	if err != nil || repeated.Changed {
		t.Fatalf("repeated adopt=%#v err=%v", repeated, err)
	}
	checked, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Origins: true, Sources: fetcher})
	if err != nil || checked.OriginsChecked != 1 || len(checked.Findings) != 0 {
		t.Fatalf("origin check=%#v err=%v", checked, err)
	}
	timeoutChecked, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Origins: true, Sources: errorSourceFetcher{err: context.DeadlineExceeded}})
	if err != nil || len(timeoutChecked.Findings) != 1 || timeoutChecked.Findings[0].State != "unknown" {
		t.Fatalf("origin timeout check=%#v err=%v", timeoutChecked, err)
	}
	fetcher.responses[origin] = source.Response{StatusCode: 404}
	missingChecked, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Origins: true, Sources: fetcher})
	if err != nil || len(missingChecked.Findings) != 1 || missingChecked.Findings[0].State != "missing" {
		t.Fatalf("missing origin check=%#v err=%v", missingChecked, err)
	}
	fetcher.responses[origin] = source.Response{StatusCode: 200, Body: []byte("changed")}
	checked, err = CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Origins: true, Sources: fetcher})
	if err != nil || len(checked.Findings) != 1 || checked.Findings[0].State != "changed" {
		t.Fatalf("changed origin check=%#v err=%v", checked, err)
	}
	if _, err := Yank(PlacementMutationRequest{Root: root, Repository: "python", Package: adopted.Package, Version: adopted.Version, All: true}); err != nil {
		t.Fatal(err)
	}
	fetcher.responses[origin] = source.Response{StatusCode: 200, Body: content}
	request.Track = "beta"
	replaced, err := AdoptArtifact(context.Background(), request)
	if err != nil || !replaced.Changed {
		t.Fatalf("replacement placement adopt=%#v err=%v", replaced, err)
	}
	lock, err = state.LoadLock(root, manifest.Repositories["python"])
	if err != nil || len(lock.Placement) != 1 || lock.Placement[0].Track != "beta" {
		t.Fatalf("replacement placement lock=%#v err=%v", lock, err)
	}
}

func TestAdoptArtifactRejectsWrongPinWithoutMutation(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "adopt-pin"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "charts", Format: "helm", HostType: "local", Output: "public/charts", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	origin := "https://downloads.example/demo-1.2.3.tgz"
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{origin: {StatusCode: 200, Body: []byte("not the pinned chart")}}}
	_, err := AdoptArtifact(context.Background(), AdoptArtifactRequest{
		Root: root, Repository: "charts", URL: origin, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicOrigin: true, Fetcher: fetcher,
	})
	if err == nil {
		t.Fatal("adopt accepted bytes that disagreed with the pin")
	}
	manifest, loadErr := state.LoadManifest(root)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	lock, loadErr := state.LoadLock(root, manifest.Repositories["charts"])
	if loadErr != nil || len(lock.PackageVersion) != 0 {
		t.Fatalf("failed adopt mutated lock=%#v err=%v", lock, loadErr)
	}
}

type adoptMemoryFetcher struct {
	responses map[string]source.Response
}

type errorSourceFetcher struct{ err error }

func (fetcher errorSourceFetcher) Fetch(context.Context, string, int64) (source.Response, error) {
	return source.Response{}, fetcher.err
}

func (fetcher *adoptMemoryFetcher) Fetch(ctx context.Context, rawURL string, maximum int64) (source.Response, error) {
	if err := ctx.Err(); err != nil {
		return source.Response{}, err
	}
	response := fetcher.responses[rawURL]
	if int64(len(response.Body)) > maximum {
		return source.Response{}, source.ErrLimit
	}
	return response, nil
}
