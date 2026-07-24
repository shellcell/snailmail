package s3host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shellcell/snailmail/engine"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestS3HostStageCommitRestoreContract(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	server := httptest.NewServer(http.HandlerFunc(objects.serveHTTP))
	defer server.Close()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: server.URL + "/repo",
	}
	adapter := New(objects)
	firstRoot := `<a href="demo/">first</a>`
	firstRequest := stageFixture(t, "plan-1", "", "", firstRoot)
	firstTree := firstRequest.TreeSHA256
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	retriedStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil || retriedStage.ID != firstStage.ID {
		t.Fatalf("stage retry was not recovered: stage=%#v err=%v", retriedStage, err)
	}
	assertHTTPContent(t, firstStage.PreviewEndpoint+"/simple/index.html", fixtureRoot(t, firstRequest))
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if firstCommit.Revision.TreeSHA256 != firstTree || firstCommit.Revision.NativeRevision == "" {
		t.Fatalf("unexpected first revision %#v", firstCommit.Revision)
	}
	assertHTTPContent(t, repository.CanonicalEndpoint+"/simple/index.html", rewrittenRoot(t, firstRequest, firstCommit.Revision))
	if _, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{}); err != nil {
		t.Fatalf("exact commit retry is not idempotent: %v", err)
	}

	secondRequest := stageFixture(t, "plan-2", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondCommit, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if secondCommit.RestoreRef == nil {
		t.Fatal("commit did not retain a restore reference")
	}
	assertHTTPContent(t, repository.CanonicalEndpoint+"/simple/index.html", rewrittenRoot(t, secondRequest, secondCommit.Revision))
	restored, err := adapter.Restore(ctx, repository, *secondCommit.RestoreRef, expectedRevision(secondCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if restored.TreeSHA256 != firstTree {
		t.Fatalf("restored tree = %q, want %q", restored.TreeSHA256, firstTree)
	}
	assertHTTPContent(t, repository.CanonicalEndpoint+"/simple/index.html", rewrittenRoot(t, firstRequest, firstCommit.Revision))
	republishRequest := stageFixture(t, "plan-3", "", "", firstRoot)
	if republishRequest.TreeSHA256 != firstTree {
		t.Fatal("equivalent tree did not retain its digest")
	}
	republishStage, err := adapter.Stage(ctx, repository, republishRequest)
	if err != nil {
		t.Fatal(err)
	}
	republished, err := adapter.Commit(ctx, repository, republishStage, expectedRevision(restored))
	if err != nil {
		t.Fatalf("republish prior tree: %v", err)
	}
	if republished.Revision.PlanID == firstCommit.Revision.PlanID {
		t.Fatal("republished tree retained the old publication identity")
	}
}

func TestS3HostRejectsStaleCommitAndRestore(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: "https://packages.example/repo",
	}
	adapter := New(objects)
	firstRequest := stageFixture(t, "plan-a", "", "", `<a href="demo/">first</a>`)
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := stageFixture(t, "plan-b", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, secondStage, host.ExpectedRevision{}); !host.IsKind(err, host.ErrorStale) {
		t.Fatalf("stale commit error = %v", err)
	}
	secondCommit, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	thirdRequest := stageFixture(t, "plan-c", "", "", `<a href="demo/">third</a>`)
	thirdStage, err := adapter.Stage(ctx, repository, thirdRequest)
	if err != nil {
		t.Fatal(err)
	}
	thirdCommit, err := adapter.Commit(ctx, repository, thirdStage, expectedRevision(secondCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Restore(ctx, repository, *secondCommit.RestoreRef, expectedRevision(secondCommit.Revision)); !host.IsKind(err, host.ErrorStale) {
		t.Fatalf("stale restore error = %v", err)
	}
	if thirdCommit.Revision.NativeRevision == secondCommit.Revision.NativeRevision {
		t.Fatal("third commit did not change native revision")
	}
}

func TestS3HostAbortMarksSharedStageForLifecycleCleanup(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: "https://packages.example/repo",
	}
	adapter := New(objects)
	staged, err := adapter.Stage(ctx, repository, stageFixture(t, "plan-d", "", "", `<a href="demo/">content</a>`))
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Abort(ctx, repository, staged); err != nil {
		t.Fatal(err)
	}
	for _, file := range staged.Files {
		if _, err := objects.Head(ctx, stageKey(repository, staged.ID, file.Path)); err != nil {
			t.Fatalf("shared stage object %q was removed: %v", file.Path, err)
		}
	}
	if _, err := objects.Head(ctx, stagePointerKey(repository, effectIdentifier(staged.PlanID, staged.ChangeID))); !errorsIs(err, ErrNotFound) {
		t.Fatal("effect stage pointer still exists")
	}
	if _, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{}); err != nil {
		t.Fatalf("abort invalidated another holder of the shared stage: %v", err)
	}
}

func TestS3HostFailedReleaseMaterializationLeavesCanonicalRoot(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: "https://packages.example/repo",
	}
	adapter := New(objects)
	firstRequest := stageFixture(t, "plan-e", "", "", `<a href="demo/">first</a>`)
	firstTree := firstRequest.TreeSHA256
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := stageFixture(t, "plan-f", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	objects.failCopyAt = objects.copyCalls + 1
	if _, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision)); err == nil {
		t.Fatal("expected release materialization failure")
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.NativeRevision != firstCommit.Revision.NativeRevision || observed.TreeSHA256 != firstTree {
		t.Fatalf("failed materialization changed canonical revision %#v", observed)
	}
	objects.failCopyAt = 0
	if _, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision)); err != nil {
		t.Fatalf("materialization retry failed: %v", err)
	}
}

func TestS3HostDetectsImmutableReleaseDrift(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: "https://packages.example/repo",
	}
	adapter := New(objects)
	request := stageFixture(t, "plan-7", "", "", `<a href="demo/">content</a>`)
	tree := request.TreeSHA256
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	changed := []byte("same")
	if _, err := objects.Put(ctx, PutRequest{
		Key:  releaseKey(repository, tree, "simple/demo/index.html"),
		Body: bytes.NewReader(changed), Size: int64(len(changed)), SHA256: digestBytes(changed),
		Metadata: map[string]string{"sha256": digestBytes(changed)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Observe(ctx, repository); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("release drift error = %v", err)
	}
}

func TestS3HostRejectsFileChangedBeforeStage(t *testing.T) {
	request := stageFixture(t, "plan-8", "", "", `<a href="demo/">content</a>`)
	root := filepath.Join(request.Directory, filepath.FromSlash(pypiRootPath))
	content, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 1
	if err := os.WriteFile(root, content, 0o644); err != nil {
		t.Fatal(err)
	}
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	if _, err := New(newMemoryObjects()).Stage(context.Background(), repository, request); !host.IsKind(err, host.ErrorStale) {
		t.Fatalf("changed stage file error = %v", err)
	}
}

func TestS3HostRejectsPrivateAndNonPyPI(t *testing.T) {
	adapter := New(newMemoryObjects())
	for _, repository := range []host.Repository{
		{Type: "s3", Format: "pypi", Visibility: "private", Bucket: "b", CanonicalEndpoint: "https://example.test"},
		{Type: "s3", Format: "helm", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"},
	} {
		if _, err := adapter.Capabilities(context.Background(), repository); !host.IsKind(err, host.ErrorInvalidConfiguration) {
			t.Fatalf("configuration error = %v", err)
		}
	}
}

func TestS3HostAdoptsAndRestoresUnmanagedRoot(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", Type: "s3", Visibility: "public",
		Bucket: "packages", Prefix: "repo", CanonicalEndpoint: "https://packages.example/repo",
	}
	unmanaged := []byte(`<a href="legacy/">legacy</a>`)
	root, err := objects.Put(ctx, PutRequest{
		Key: objectKey(repository, pypiRootPath), Body: bytes.NewReader(unmanaged),
		Size: int64(len(unmanaged)), SHA256: digestBytes(unmanaged),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := New(objects)
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.NativeRevision != root.ETag || observed.TreeSHA256 != "" {
		t.Fatalf("unexpected unmanaged observation %#v", observed)
	}
	request := stageFixture(t, "adopt-plan", "", "", `<a href="demo/">managed</a>`)
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{NativeRevision: root.ETag})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := adapter.Restore(ctx, repository, *committed.RestoreRef, expectedRevision(committed.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if restored.TreeSHA256 != "" || restored.NativeRevision == "" {
		t.Fatalf("unexpected unmanaged restore %#v", restored)
	}
	content, _, err := objects.Get(ctx, objectKey(repository, pypiRootPath), maximumMetadataSize)
	if err != nil || !bytes.Equal(content, unmanaged) {
		t.Fatal("restore did not recover unmanaged root bytes")
	}
}

func TestS3HostRejectsTreeDigestOutsideDescriptor(t *testing.T) {
	request := stageFixture(t, "invalid-tree", "", "", `<a href="demo/">content</a>`)
	request.TreeSHA256 = strings.Repeat("9", 64)
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	if _, err := New(newMemoryObjects()).Stage(context.Background(), repository, request); !host.IsKind(err, host.ErrorInvalidConfiguration) {
		t.Fatalf("tree mismatch error = %v", err)
	}
}

func TestS3HostRejectsTamperedRestoreBytes(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	firstRequest := stageFixture(t, "restore-first", "", "", `<a href="demo/">first</a>`)
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := stageFixture(t, "restore-second", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondCommit, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(firstCommit.Revision))
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte("tampered")
	if _, err := objects.Put(ctx, PutRequest{
		Key: restoreRootKey(repository, secondCommit.RestoreRef.ID), Body: bytes.NewReader(tampered),
		Size: int64(len(tampered)), SHA256: digestBytes(tampered),
		Metadata: map[string]string{"sha256": digestBytes(tampered)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Restore(ctx, repository, *secondCommit.RestoreRef, expectedRevision(secondCommit.Revision)); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("tampered restore error = %v", err)
	}
}

func TestS3HostRecoversAmbiguousStagePointerWrite(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	request := stageFixture(t, "ambiguous-stage", "", "", `<a href="demo/">content</a>`)
	objects.ambiguousPutKey = stagePointerKey(repository, effectIdentifier(request.PlanID, request.ChangeID))
	adapter := New(objects)
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := adapter.Stage(ctx, repository, request)
	if err != nil || retried.ID != staged.ID {
		t.Fatalf("ambiguous stage pointer was not recovered: staged=%#v retry=%#v err=%v", staged, retried, err)
	}
}

func TestS3HostRootBodyBindsPublicationManifest(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	firstRequest := stageFixture(t, "binding-first", "", "", `<a href="demo/">content</a>`)
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := stageFixture(t, "binding-second", "", "", `<a href="demo/">content</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(first.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision.ManifestSHA256 == second.Revision.ManifestSHA256 {
		t.Fatal("test publications unexpectedly share a manifest")
	}
	rootKey := objectKey(repository, pypiRootPath)
	objects.mutex.Lock()
	root := objects.objects[rootKey]
	root.info.Metadata["manifest-sha256"] = first.Revision.ManifestSHA256
	objects.objects[rootKey] = root
	objects.mutex.Unlock()
	if _, err := adapter.Observe(ctx, repository); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("metadata-only manifest rewrite error = %v", err)
	}
}

func TestS3HostCreateOnlyPromotionRejectsImmutableConflict(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	request := stageFixture(t, "immutable-conflict", "", "", `<a href="demo/">content</a>`)
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	conflict := []byte("evil")
	conflictKey := releaseKey(repository, request.TreeSHA256, "simple/demo/index.html")
	if _, err := objects.Put(ctx, PutRequest{
		Key: conflictKey, Body: bytes.NewReader(conflict), Size: int64(len(conflict)), SHA256: digestBytes(conflict),
		Metadata: map[string]string{"sha256": digestBytes(conflict)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{}); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("immutable conflict error = %v", err)
	}
	stored, _, err := objects.Get(ctx, conflictKey, maximumMetadataSize)
	if err != nil || !bytes.Equal(stored, conflict) {
		t.Fatal("create-only promotion overwrote the conflicting immutable object")
	}
}

func TestS3HostRejectsSemanticallyInvalidPublicationManifest(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	request := stageFixture(t, "invalid-manifest", "", "", `<a href="demo/">content</a>`)
	manifestName := filepath.Join(request.Directory, buildgraph.ManifestFilename)
	content, err := os.ReadFile(manifestName)
	if err != nil {
		t.Fatal(err)
	}
	var manifest buildgraph.RepositoryManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.VerificationCases[0].Version = "9999"
	content, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(manifestName, content, 0o644); err != nil {
		t.Fatal(err)
	}
	for index := range request.Files {
		if request.Files[index].Path == buildgraph.ManifestFilename {
			request.Files[index].Size = int64(len(content))
			request.Files[index].SHA256 = digestBytes(content)
		}
	}
	if _, err := adapter.Stage(ctx, repository, request); !host.IsKind(err, host.ErrorInvalidConfiguration) {
		t.Fatalf("invalid publication manifest error = %v", err)
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil || observed.NativeRevision != "" {
		t.Fatalf("invalid manifest changed canonical state: revision=%#v err=%v", observed, err)
	}
}

func TestS3HostMissingBoundReleaseIsIndeterminate(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	request := stageFixture(t, "missing-release", "", "", `<a href="demo/">content</a>`)
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	if err := objects.Delete(ctx, releaseDescriptorKey(repository, request.TreeSHA256), Conditions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Observe(ctx, repository); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("missing bound release error = %v", err)
	}
}

func TestS3HostRejectsInvalidDirectConfiguration(t *testing.T) {
	adapter := New(newMemoryObjects())
	valid := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	for _, mutate := range []func(*host.Repository){
		func(repository *host.Repository) { repository.Path = "local" },
		func(repository *host.Repository) { repository.Prefix = "/absolute" },
		func(repository *host.Repository) { repository.Prefix = "a/../b" },
		func(repository *host.Repository) { repository.Prefix = "a\\b" },
		func(repository *host.Repository) { repository.Prefix = "a\tb" },
		func(repository *host.Repository) { repository.CanonicalEndpoint = "https://user@example.test/repo" },
		func(repository *host.Repository) { repository.CanonicalEndpoint = "https://example.test/repo?query=1" },
		func(repository *host.Repository) { repository.Endpoint = "ftp://example.test" },
	} {
		repository := valid
		mutate(&repository)
		if _, err := adapter.Capabilities(context.Background(), repository); !host.IsKind(err, host.ErrorInvalidConfiguration) {
			t.Fatalf("configuration %#v error = %v", repository, err)
		}
	}
}

func TestS3HostMigratesLegacyManagedRootOnNextCommit(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	request := stageFixture(t, "legacy-first", "", "", `<a href="demo/">content</a>`)
	staged, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, staged, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot, _, err := objects.Get(ctx, releaseKey(repository, request.TreeSHA256, pypiRootPath), maximumMetadataSize)
	if err != nil {
		t.Fatal(err)
	}
	legacyRoot, err := rewriteLegacyPyPIRoot(releaseRoot, committed.Revision.TreeSHA256, committed.Revision.PlanID, committed.Revision.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	_, canonicalInfo, err := objects.Get(ctx, objectKey(repository, pypiRootPath), maximumMetadataSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Put(ctx, PutRequest{
		Key: objectKey(repository, pypiRootPath), Body: bytes.NewReader(legacyRoot), Size: int64(len(legacyRoot)), SHA256: digestBytes(legacyRoot),
		Metadata: canonicalInfo.Metadata,
	}); err != nil {
		t.Fatal(err)
	}
	legacy, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.NativeRevision == "" || legacy.TreeSHA256 != "" {
		t.Fatalf("legacy root was not exposed for migration: %#v", legacy)
	}
	republish := stageFixture(t, "legacy-second", "", "", `<a href="demo/">content</a>`)
	republishStage, err := adapter.Stage(ctx, repository, republish)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Commit(ctx, repository, republishStage, expectedRevision(legacy)); err != nil {
		t.Fatalf("migrate legacy root: %v", err)
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil || observed.TreeSHA256 != request.TreeSHA256 || observed.PlanID != republish.PlanID {
		t.Fatalf("unexpected migrated publication %#v err=%v", observed, err)
	}
}

func TestS3HostRecoversAmbiguousRestoreAndExactRetry(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	firstRequest := stageFixture(t, "ambiguous-restore-first", "", "", `<a href="demo/">first</a>`)
	firstStage, err := adapter.Stage(ctx, repository, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := stageFixture(t, "ambiguous-restore-second", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(first.Revision))
	if err != nil {
		t.Fatal(err)
	}
	objects.ambiguousPutKey = objectKey(repository, pypiRootPath)
	objects.ambiguousPutDone = false
	restored, err := adapter.Restore(ctx, repository, *second.RestoreRef, expectedRevision(second.Revision))
	if err != nil || restored.TreeSHA256 != first.Revision.TreeSHA256 {
		t.Fatalf("ambiguous restore was not recovered: revision=%#v err=%v", restored, err)
	}
	retried, err := adapter.Restore(ctx, repository, *second.RestoreRef, expectedRevision(second.Revision))
	if err != nil || retried != restored {
		t.Fatalf("restore retry was not idempotent: revision=%#v err=%v", retried, err)
	}
}

func TestS3HostDoesNotRebindPublishedEffectToNewRestoreState(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	adapter := New(objects)
	request := stageFixture(t, "fixed-effect", "", "", `<a href="demo/">content</a>`)
	firstStage, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Abort(ctx, repository, firstStage); err != nil {
		t.Fatal(err)
	}
	secondStage, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if secondStage.ID == firstStage.ID {
		t.Fatal("stage cleanup did not create a distinct retry stage")
	}
	if _, err := adapter.Commit(ctx, repository, secondStage, expectedRevision(committed.Revision)); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("rebound publication effect error = %v", err)
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil || observed != committed.Revision {
		t.Fatalf("rebind attempt changed publication: revision=%#v err=%v", observed, err)
	}
}

func TestS3HostRejectsPartialReservedRootMetadata(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	content := []byte(`<a href="demo/">content</a>`)
	if _, err := objects.Put(ctx, PutRequest{
		Key: objectKey(repository, pypiRootPath), Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: digestBytes(content),
		Metadata: map[string]string{"manifest-sha256": strings.Repeat("1", 64)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(objects).Observe(ctx, repository); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("partial reserved metadata error = %v", err)
	}
}

func TestS3HostRejectsInvalidRestoreBeforeIdentity(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{Type: "s3", Format: "pypi", Visibility: "public", Bucket: "b", CanonicalEndpoint: "https://example.test"}
	identifier := strings.Repeat("1", 64)
	descriptor := restoreDescriptor{
		PlanID: strings.Repeat("2", 64), ChangeID: "python:000000000000", AfterTreeSHA256: strings.Repeat("3", 64),
		RootExisted: true, BeforeTreeSHA256: strings.Repeat("4", 64), BeforePlanID: "invalid", BeforeChangeID: "invalid",
	}
	content, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Put(ctx, PutRequest{
		Key: restoreDescriptorKey(repository, identifier), Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: digestBytes(content),
		Metadata: map[string]string{"sha256": digestBytes(content)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(objects).loadRestore(ctx, repository, identifier); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("invalid restore descriptor error = %v", err)
	}
	descriptor = restoreDescriptor{
		PlanID: strings.Repeat("2", 64), ChangeID: "python:000000000000", AfterTreeSHA256: strings.Repeat("3", 64),
		RootExisted: true, BeforeMetadata: map[string]string{"manifest-sha256": strings.Repeat("4", 64)},
	}
	content, err = json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Put(ctx, PutRequest{
		Key: restoreDescriptorKey(repository, identifier), Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: digestBytes(content),
		Metadata: map[string]string{"sha256": digestBytes(content)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(objects).loadRestore(ctx, repository, identifier); !host.IsKind(err, host.ErrorIndeterminate) {
		t.Fatalf("partial legacy restore metadata error = %v", err)
	}
}

func stageFixture(t *testing.T, planID, changeID, tree, rootContent string) host.StageRequest {
	t.Helper()
	input := t.TempDir()
	seed := sha256.Sum256([]byte(rootContent))
	version := fmt.Sprintf("1.%d", binary.BigEndian.Uint64(seed[:8]))
	if _, err := testutil.WriteWheel(input, "demo", version, ""); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "repository")
	planDigest := sha256.Sum256([]byte(planID))
	generatedAt := time.Unix(1_600_000_000+int64(binary.BigEndian.Uint32(planDigest[:4])), 0).UTC()
	result, err := engine.BuildPyPI(context.Background(), engine.BuildPyPIRequest{Input: input, Output: directory, GeneratedAt: generatedAt})
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
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fixture contains non-regular file %q", name)
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
		PlanID: hex.EncodeToString(planDigest[:]), ChangeID: "python:" + result.TreeSHA256[:12], Directory: directory, TreeSHA256: result.TreeSHA256,
		Files: files, CommitPaths: []string{pypiRootPath},
	}
}

func assertHTTPContent(t *testing.T, address, expected string) {
	t.Helper()
	response, err := http.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(content) != expected {
		t.Fatalf("GET %s = %d %q, want %q", address, response.StatusCode, content, expected)
	}
}

type memoryObject struct {
	content []byte
	info    ObjectInfo
}

type memoryObjects struct {
	mutex            sync.Mutex
	objects          map[string]memoryObject
	version          int
	copyCalls        int
	failCopyAt       int
	ambiguousPutKey  string
	ambiguousPutDone bool
}

func newMemoryObjects() *memoryObjects {
	return &memoryObjects{objects: make(map[string]memoryObject)}
}

func (store *memoryObjects) Head(_ context.Context, key string) (ObjectInfo, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, exists := store.objects[key]
	if !exists {
		return ObjectInfo{}, ErrNotFound
	}
	return cloneInfo(object.info), nil
}

func (store *memoryObjects) Get(_ context.Context, key string, maximum int64) ([]byte, ObjectInfo, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, exists := store.objects[key]
	if !exists {
		return nil, ObjectInfo{}, ErrNotFound
	}
	if int64(len(object.content)) > maximum {
		return nil, ObjectInfo{}, errors.New("object exceeds size limit")
	}
	return append([]byte(nil), object.content...), cloneInfo(object.info), nil
}

func (store *memoryObjects) Put(_ context.Context, request PutRequest) (ObjectInfo, error) {
	content, err := io.ReadAll(request.Body)
	if err != nil {
		return ObjectInfo{}, err
	}
	if int64(len(content)) != request.Size {
		return ObjectInfo{}, fmt.Errorf("size mismatch")
	}
	if request.SHA256 != "" {
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != request.SHA256 {
			return ObjectInfo{}, fmt.Errorf("checksum mismatch")
		}
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	existing, exists := store.objects[request.Key]
	if request.Conditions.IfNoneMatch && exists {
		return ObjectInfo{}, ErrPrecondition
	}
	if request.Conditions.IfMatch != "" && (!exists || existing.info.ETag != request.Conditions.IfMatch) {
		return ObjectInfo{}, ErrPrecondition
	}
	store.version++
	info := ObjectInfo{
		ETag: fmt.Sprintf("\"%d\"", store.version), Size: int64(len(content)),
		SHA256: digestBytes(content), Metadata: cloneMetadata(request.Metadata),
	}
	store.objects[request.Key] = memoryObject{content: append([]byte(nil), content...), info: info}
	if request.Key == store.ambiguousPutKey && !store.ambiguousPutDone {
		store.ambiguousPutDone = true
		return ObjectInfo{}, errors.New("injected lost put response")
	}
	return cloneInfo(info), nil
}

func (store *memoryObjects) CopyCreate(_ context.Context, source, destination string, expectedSize int64, expectedSHA256 string) (ObjectInfo, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.copyCalls++
	if store.failCopyAt != 0 && store.copyCalls == store.failCopyAt {
		return ObjectInfo{}, errors.New("injected copy failure")
	}
	object, exists := store.objects[source]
	if !exists {
		return ObjectInfo{}, ErrNotFound
	}
	if object.info.Size != expectedSize || object.info.SHA256 != expectedSHA256 || object.info.Metadata["sha256"] != expectedSHA256 {
		return ObjectInfo{}, errors.New("copy source mismatch")
	}
	if _, exists := store.objects[destination]; exists {
		return ObjectInfo{}, ErrPrecondition
	}
	store.version++
	object.content = append([]byte(nil), object.content...)
	object.info = cloneInfo(object.info)
	object.info.ETag = fmt.Sprintf("\"%d\"", store.version)
	store.objects[destination] = object
	return cloneInfo(object.info), nil
}

func (store *memoryObjects) Delete(_ context.Context, key string, conditions Conditions) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, exists := store.objects[key]
	if !exists {
		return ErrNotFound
	}
	if conditions.IfMatch != "" && object.info.ETag != conditions.IfMatch {
		return ErrPrecondition
	}
	delete(store.objects, key)
	return nil
}

func (store *memoryObjects) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	content, info, err := store.Get(request.Context(), strings.TrimPrefix(request.URL.Path, "/"), maximumTreeBytes)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("ETag", info.ETag)
	_, _ = writer.Write(content)
}

func cloneInfo(info ObjectInfo) ObjectInfo {
	info.Metadata = cloneMetadata(info.Metadata)
	return info
}

func cloneMetadata(metadata map[string]string) map[string]string {
	copy := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}

func errorsIs(err, target error) bool {
	return err == target
}

func fixtureRoot(t *testing.T, request host.StageRequest) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(request.Directory, filepath.FromSlash(pypiRootPath)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func rewrittenRoot(t *testing.T, request host.StageRequest, revision host.PublishedRevision) string {
	t.Helper()
	content, err := rewritePyPIRoot([]byte(fixtureRoot(t, request)), rootBindingFromRevision(revision))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func expectedRevision(revision host.PublishedRevision) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: revision.NativeRevision, TreeSHA256: revision.TreeSHA256, PlanID: revision.PlanID, ChangeID: revision.ChangeID,
		ReleaseSHA256: revision.ReleaseSHA256, ManifestSHA256: revision.ManifestSHA256, RestoreID: revision.RestoreID,
		RestoreSHA256: revision.RestoreSHA256, RestoreRootSHA256: revision.RestoreRootSHA256,
	}
}
