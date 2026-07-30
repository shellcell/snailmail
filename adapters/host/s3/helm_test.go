package s3host

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/engine"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/testutil"
)

// Helm is the other publication shape. Its index is the only file rewritten
// between revisions — a chart is stored under its own digest — so a revision is
// written at canonical paths and committed by switching index.yaml, with no
// staging directory and no rebound root.
const helmRootPath = "index.yaml"

// requireHelmOnS3 skips while the shape is undeclared.
//
// Three of these tests pass and describe how the canonical-path shape works. The
// fourth found what is still open: a published tree carries snailmail's own
// generated files — index.html and snailmail.repository.json — at fixed paths that
// change every revision, and a second publication cannot write them without either
// overwriting what the live revision's descriptor points at or leaving the previous
// revision unverifiable. They are kept, and skipped, so the work is not
// rediscovered.
func requireHelmOnS3(t *testing.T) {
	t.Helper()
	t.Skip("s3 does not serve helm yet: snailmail's own generated files are mutable at canonical paths")
}

// helmRepository has no RootRewriter, which is what selects that shape.
func helmRepository(endpoint string) host.Repository {
	return host.Repository{
		Name: "charts", Format: "helm", CommitPaths: []string{helmRootPath},
		Type: "s3", Visibility: "public", Bucket: "packages", Prefix: "repo",
		CanonicalEndpoint: endpoint,
	}
}

func helmStageFixture(t *testing.T, planID, chart, version string) host.StageRequest {
	t.Helper()
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, chart, version); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "repository")
	planDigest := sha256.Sum256([]byte(planID))
	generatedAt := time.Unix(1_600_000_000+int64(binary.BigEndian.Uint32(planDigest[:4])), 0).UTC()
	result, err := engine.BuildHelm(context.Background(), engine.BuildHelmRequest{
		Input: input, Output: directory, GeneratedAt: generatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	var files []host.File
	if err := filepath.WalkDir(directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, name)
		if err != nil {
			return err
		}
		files = append(files, host.File{Path: filepath.ToSlash(relative), Size: int64(len(content)), SHA256: digestBytes(content)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return host.StageRequest{
		PlanID: hex.EncodeToString(planDigest[:]), ChangeID: "charts:" + result.TreeSHA256[:12],
		Directory: directory, TreeSHA256: result.TreeSHA256, Files: files,
		CommitPaths: []string{helmRootPath},
	}
}

// The whole point of the shape: a chart lands where a client will fetch it, and
// the index that names it is what goes live.
func TestHelmPublishesAtCanonicalPathsAndCommitsTheIndex(t *testing.T) {
	requireHelmOnS3(t)
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := helmRepository("https://charts.example/repo")
	request := helmStageFixture(t, "plan-1", "demo", "1.0.0")

	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}

	// Every chart is at its canonical path, not inside a release directory: a
	// client resolves index.yaml's urls against the repository root.
	var chart string
	for _, file := range request.Files {
		if strings.HasSuffix(file.Path, ".tgz") {
			chart = file.Path
		}
	}
	if chart == "" {
		t.Fatal("the fixture built no chart")
	}
	if _, err := objects.Head(ctx, objectKey(repository, chart)); err != nil {
		t.Errorf("chart %q is not at its canonical path: %v", chart, err)
	}
	// And it is not duplicated into the release directory, which would double the
	// storage for no further guarantee.
	if _, err := objects.Head(ctx, releaseKey(repository, request.TreeSHA256, chart)); err == nil {
		t.Errorf("chart %q was copied into the release directory as well", chart)
	}
	// The index is live at its canonical path and kept immutably beside the
	// release, which is what Observe compares against.
	if _, err := objects.Head(ctx, objectKey(repository, helmRootPath)); err != nil {
		t.Errorf("the index is not live: %v", err)
	}
	if _, err := objects.Head(ctx, releaseKey(repository, request.TreeSHA256, helmRootPath)); err != nil {
		t.Errorf("the index has no immutable copy: %v", err)
	}

	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.TreeSHA256 != request.TreeSHA256 {
		t.Errorf("observed tree %q, want %q", observed.TreeSHA256, request.TreeSHA256)
	}
	if observed != committed.Revision {
		t.Errorf("observed %+v, committed %+v", observed, committed.Revision)
	}
}

// The index is published exactly as built. For Helm that is merely simpler; for a
// signed yum repository it is the difference between a repository a client accepts
// and one whose signature no longer covers the document it signs.
func TestTheIndexIsPublishedUnmodified(t *testing.T) {
	requireHelmOnS3(t)
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := helmRepository("https://charts.example/repo")
	request := helmStageFixture(t, "plan-1", "demo", "1.0.0")

	built, err := os.ReadFile(filepath.Join(request.Directory, helmRootPath))
	if err != nil {
		t.Fatal(err)
	}
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	live, _, err := objects.Get(ctx, objectKey(repository, helmRootPath), maximumMetadataSize)
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != string(built) {
		t.Errorf("the published index differs from the one that was built:\n got %q\nwant %q", live, built)
	}
}

// A second revision goes live by switching one object. Until that object is
// switched a client sees the previous revision whole, which is the property the
// mechanism exists for.
func TestASecondRevisionIsLiveOnlyWhenTheIndexSwitches(t *testing.T) {
	requireHelmOnS3(t)
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := helmRepository("https://charts.example/repo")

	first := helmStageFixture(t, "plan-1", "demo", "1.0.0")
	firstStage, err := adapter.Stage(ctx, repository, first)
	if err != nil {
		t.Fatal(err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}

	second := helmStageFixture(t, "plan-2", "demo", "2.0.0")
	secondStage, err := adapter.Stage(ctx, repository, second)
	if err != nil {
		t.Fatal(err)
	}
	// Staging writes nothing a client reads, so the first revision is still what
	// is served.
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.TreeSHA256 != first.TreeSHA256 {
		t.Fatalf("staging the second revision changed what is live: %q", observed.TreeSHA256)
	}
	if observed != firstCommit.Revision {
		t.Errorf("observed %+v after staging, want the first revision", observed)
	}

	// The expectation names the whole revision being replaced, so a concurrent
	// publication cannot slip between the observation and the switch.
	previous := firstCommit.Revision
	if _, err := adapter.Commit(ctx, repository, secondStage, host.ExpectedRevision{
		NativeRevision: previous.NativeRevision, TreeSHA256: previous.TreeSHA256,
		PlanID: previous.PlanID, ChangeID: previous.ChangeID,
		ReleaseSHA256: previous.ReleaseSHA256, ManifestSHA256: previous.ManifestSHA256,
		RestoreID: previous.RestoreID, RestoreSHA256: previous.RestoreSHA256,
	}); err != nil {
		t.Fatal(err)
	}
	observed, err = adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.TreeSHA256 != second.TreeSHA256 {
		t.Errorf("observed tree %q after committing, want %q", observed.TreeSHA256, second.TreeSHA256)
	}
	// The first revision's chart is untouched: its path holds bytes fixed by that
	// path, so publishing the second could not have disturbed it.
	for _, file := range first.Files {
		if !strings.HasSuffix(file.Path, ".tgz") {
			continue
		}
		info, err := objects.Head(ctx, objectKey(repository, file.Path))
		if err != nil {
			t.Errorf("the first revision's chart %q went missing: %v", file.Path, err)
			continue
		}
		if info.SHA256 != file.SHA256 {
			t.Errorf("the first revision's chart %q changed bytes", file.Path)
		}
	}
}

// A client is told to fetch from where the objects actually are. Routes pointing
// into a release directory would be verified against paths a user never uses.
func TestClientRoutesPointAtCanonicalPaths(t *testing.T) {
	requireHelmOnS3(t)
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := helmRepository("https://charts.example/repo")
	request := helmStageFixture(t, "plan-1", "demo", "1.0.0")
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if len(committed.Access.Routes) == 0 {
		t.Fatal("no client routes were issued")
	}
	for _, route := range committed.Access.Routes {
		if strings.Contains(route.URL, ".snailmail/releases") {
			t.Errorf("route %q points into the release directory", route.URL)
		}
		if !strings.HasPrefix(route.URL, "https://charts.example/repo/") {
			t.Errorf("route %q is not under the canonical endpoint", route.URL)
		}
	}
}
