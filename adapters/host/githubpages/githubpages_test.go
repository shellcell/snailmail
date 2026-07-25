package githubpages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestGitHubPagesStageCommitRestoreContract(t *testing.T) {
	ctx := context.Background()
	production := createBareRepository(t, "production.git")
	preview := createBareRepository(t, "preview.git")
	adapter := NewWithRemoteResolver(func(repository string) string {
		if repository == "test/production" {
			return production
		}
		return preview
	})
	repository := testRepository()
	first := pagesStageFixture(t, "first", "1.0.0")
	firstStage, err := adapter.Stage(ctx, repository, first)
	if err != nil {
		t.Fatal(err)
	}
	assertRemotePublication(t, adapter, preview, repository.PreviewBranch, first.TreeSHA256)
	if observed, err := adapter.Observe(ctx, repository); err != nil || observed != (host.PublishedRevision{}) {
		t.Fatalf("initial observation=%#v err=%v", observed, err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if firstCommit.Revision.TreeSHA256 != first.TreeSHA256 || firstCommit.RestoreRef == nil {
		t.Fatalf("unexpected first commit %#v", firstCommit)
	}
	if retried, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{}); err != nil || retried.Revision != firstCommit.Revision {
		t.Fatalf("commit retry=%#v err=%v", retried, err)
	}
	second := pagesStageFixture(t, "second", "2.0.0")
	second.PreviousRevision = firstCommit.Revision.NativeRevision
	secondStage, err := adapter.Stage(ctx, repository, second)
	if err != nil {
		t.Fatal(err)
	}
	secondCommit, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, firstStage, expectedRevision(firstCommit.Revision)); !host.IsKind(err, host.ErrorStale) {
		t.Fatalf("stale commit error=%v", err)
	}
	restored, err := adapter.Restore(ctx, repository, *secondCommit.RestoreRef, expectedRevision(secondCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if restored != firstCommit.Revision {
		t.Fatalf("restored=%#v want=%#v", restored, firstCommit.Revision)
	}
	if err := adapter.Abort(ctx, repository, secondStage); err != nil {
		t.Fatal(err)
	}
	workspace, err := newGitWorkspace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	if _, err := workspace.lsRemote(ctx, production, stageRef(secondStage.ID)); !errorsIsRefNotFound(err) {
		t.Fatalf("aborted stage ref remained: %v", err)
	}
}

func TestGitHubPagesRejectsPrivateAndSamePreviewRepository(t *testing.T) {
	repository := testRepository()
	repository.Visibility = "private"
	if _, err := New().Capabilities(context.Background(), repository); err == nil {
		t.Fatal("private Pages repository was accepted")
	}
	repository.Visibility = "public"
	repository.PreviewRepository = repository.RemoteRepository
	if _, err := New().Capabilities(context.Background(), repository); err == nil {
		t.Fatal("production repository reused as preview site")
	}
	repository.PreviewRepository = strings.ToUpper(repository.RemoteRepository)
	if _, err := New().Capabilities(context.Background(), repository); err == nil {
		t.Fatal("case-variant production repository reused as preview site")
	}
}

func TestGitHubPagesEndpointAndRefValidation(t *testing.T) {
	if !sameEndpoint("https://Owner.github.io/Packages/", "https://owner.github.io/Packages") {
		t.Fatal("equivalent Pages endpoints did not match")
	}
	if sameEndpoint("https://owner.github.io/packages", "https://owner.github.io/other") {
		t.Fatal("different Pages paths matched")
	}
	for _, branch := range []string{"gh-pages", "releases/pages", "Pages_v2"} {
		if !validBranch(branch) {
			t.Fatalf("valid branch %q rejected", branch)
		}
	}
	for _, branch := range []string{"../escape", "bad..branch", "bad branch", ".hidden"} {
		if validBranch(branch) {
			t.Fatalf("invalid branch %q accepted", branch)
		}
	}
}

func assertRemotePublication(t *testing.T, adapter *Adapter, remote, branch, treeSHA256 string) {
	t.Helper()
	workspace, err := newGitWorkspace(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	commit, err := workspace.fetch(context.Background(), remote, branchRef(branch))
	if err != nil {
		t.Fatal(err)
	}
	revision, _, _, err := workspace.inspectPublication(context.Background(), commit)
	if err != nil || revision.TreeSHA256 != treeSHA256 {
		t.Fatalf("preview revision=%#v err=%v", revision, err)
	}
}

func pagesStageFixture(t *testing.T, label, version string) host.StageRequest {
	t.Helper()
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "pages-demo", version, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.ScanPyPI(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	artifact, err := pypi.Build(snapshot.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	artifact, _, err = buildgraph.Finalize(artifact, time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := app.Materialize(context.Background(), repository, artifact, snapshot.Sources); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := app.VerifyRepository(release)
	if err != nil {
		t.Fatal(err)
	}
	files := make([]host.File, 0, len(manifest.Files)+1)
	for _, file := range manifest.Files {
		files = append(files, host.File{Path: file.Path, Size: file.Size, SHA256: file.SHA256})
	}
	management := filepath.Join(release, "snailmail.repository.json")
	info, err := os.Stat(management)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256File(t, management)
	files = append(files, host.File{Path: "snailmail.repository.json", Size: info.Size(), SHA256: digest})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	plan := sha256.Sum256([]byte(label))
	return host.StageRequest{
		PlanID: hex.EncodeToString(plan[:]), ChangeID: "python:" + strings.Repeat(label[:1], 12), Directory: release,
		TreeSHA256: manifest.TreeSHA256, Files: files, CommitPaths: []string{"simple/index.html"},
	}
}

func testRepository() host.Repository {
	return host.Repository{
		Name: "python", Format: "pypi", Type: "github-pages", Visibility: "public",
		RemoteRepository: "test/production", Branch: "gh-pages", CanonicalEndpoint: "https://test.example/packages",
		PreviewRepository: "test/preview", PreviewBranch: "gh-pages", PreviewEndpoint: "https://preview.example/packages",
	}
}

func expectedRevision(revision host.PublishedRevision) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: revision.NativeRevision, TreeSHA256: revision.TreeSHA256,
		PlanID: revision.PlanID, ChangeID: revision.ChangeID, ManifestSHA256: revision.ManifestSHA256,
	}
}

func createBareRepository(t *testing.T, name string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), name)
	command := exec.Command("git", "init", "--bare", filename)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, output)
	}
	return filename
}

func sha256File(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func errorsIsRefNotFound(err error) bool { return err == errRefNotFound }
