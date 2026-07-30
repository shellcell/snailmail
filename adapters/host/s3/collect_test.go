package s3host

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
)

// expectedFrom names every field of a revision, because Commit and Restore compare
// all of them and a hand-written subset fails with two identical-looking values.
func expectedFrom(revision host.PublishedRevision) host.ExpectedRevision {
	return host.ExpectedRevision{
		NativeRevision: revision.NativeRevision, TreeSHA256: revision.TreeSHA256,
		PlanID: revision.PlanID, ChangeID: revision.ChangeID,
		ReleaseSHA256: revision.ReleaseSHA256, ManifestSHA256: revision.ManifestSHA256,
		RestoreID: revision.RestoreID, RestoreSHA256: revision.RestoreSHA256,
		RestoreRootSHA256: revision.RestoreRootSHA256,
	}
}

// publishInto adds one more revision and returns it.
func publishInto(t *testing.T, adapter *Adapter, repository host.Repository, plan, content string) host.CommitResult {
	t.Helper()
	ctx := context.Background()
	request := stageFixture(t, plan, "", "", content)
	stage, err := adapter.Stage(ctx, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := adapter.Commit(ctx, repository, stage, expectedFrom(observed))
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

// publishTwice leaves a repository with a live revision and one superseded one,
// which is the state collection exists for.
func publishTwice(t *testing.T) (*Adapter, *memoryObjects, host.Repository, host.CommitResult, host.CommitResult) {
	t.Helper()
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := host.Repository{
		Name: "python", Format: "pypi", CommitPaths: []string{pypiRootPath}, RootRewriter: pypiRootRewriter(),
		Type: "s3", Visibility: "public", Bucket: "packages", Prefix: "repo",
		CanonicalEndpoint: "https://packages.example/repo",
	}
	first := stageFixture(t, "plan-1", "", "", `<a href="demo/">first</a>`)
	firstStage, err := adapter.Stage(ctx, repository, first)
	if err != nil {
		t.Fatal(err)
	}
	firstCommit, err := adapter.Commit(ctx, repository, firstStage, host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	second := stageFixture(t, "plan-2", "", "", `<a href="demo/">second</a>`)
	secondStage, err := adapter.Stage(ctx, repository, second)
	if err != nil {
		t.Fatal(err)
	}
	previous := firstCommit.Revision
	secondCommit, err := adapter.Commit(ctx, repository, secondStage, expectedFrom(previous))
	if err != nil {
		t.Fatal(err)
	}
	return adapter, objects, repository, firstCommit, secondCommit
}

func releaseObjectCount(t *testing.T, objects *memoryObjects, repository host.Repository, tree string) int {
	t.Helper()
	page, err := objects.List(context.Background(), ListRequest{
		Prefix: objectKey(repository, releasePrefix+tree+"/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Objects)
}

// The live revision survives whatever the caller asked for. A caller whose ledger
// was behind — a publication from another machine, a restore not yet recorded —
// would otherwise delete what is being served.
//
// Three revisions, because two are both protected: the live one and the one its
// restore rolls back to. The first collectable revision is the third publication's
// grandparent, which is worth knowing when reading what this reclaims.
func TestCollectNeverRemovesTheLiveRevision(t *testing.T) {
	adapter, objects, repository, _, _ := publishTwice(t)
	thirdCommit := publishInto(t, adapter, repository, "plan-3", `<a href="demo/">third</a>`)
	live := thirdCommit.Revision.TreeSHA256
	// Deliberately naming nothing, which is the worst thing a caller can pass.
	result, err := adapter.Collect(context.Background(), repository, host.Retention{})
	if err != nil {
		t.Fatal(err)
	}
	if count := releaseObjectCount(t, objects, repository, live); count == 0 {
		t.Fatal("collection removed the live revision's release")
	}
	if result.Removed == 0 {
		t.Error("collection removed nothing, so the superseded revision is still there")
	}
	// And the repository still observes as the revision it was.
	observed, err := adapter.Observe(context.Background(), repository)
	if err != nil {
		t.Fatalf("the repository no longer observes after collection: %v", err)
	}
	if observed != thirdCommit.Revision {
		t.Errorf("observed %+v after collection, want the revision that was live", observed)
	}
}

// Restore reads the release it is rolling back to before putting its root back, so
// the tree the live revision replaced has to outlive it. Removing that turns a
// recoverable failure into an unrecoverable one.
func TestCollectKeepsWhatARestoreDependsOn(t *testing.T) {
	adapter, objects, repository, firstCommit, secondCommit := publishTwice(t)
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{}); err != nil {
		t.Fatal(err)
	}
	if count := releaseObjectCount(t, objects, repository, firstCommit.Revision.TreeSHA256); count == 0 {
		t.Fatal("collection removed the release the live revision's restore depends on")
	}
	// The proof that it matters: a restore back to it still works.
	restored, err := adapter.Restore(context.Background(), repository, host.RestoreRef{
		ID: secondCommit.Revision.RestoreID, PlanID: secondCommit.Revision.PlanID,
		ChangeID: secondCommit.Revision.ChangeID, FailedTree: secondCommit.Revision.TreeSHA256,
		DescriptorSHA256: secondCommit.Revision.RestoreSHA256, RootSHA256: secondCommit.Revision.RestoreRootSHA256,
	}, expectedFrom(secondCommit.Revision))
	if err != nil {
		t.Fatalf("restore failed after collection, so collection broke rollback: %v", err)
	}
	if restored.TreeSHA256 != firstCommit.Revision.TreeSHA256 {
		t.Errorf("restored to %q, want %q", restored.TreeSHA256, firstCommit.Revision.TreeSHA256)
	}
}

// A dry run has to report the same numbers and change nothing, or it is no use for
// showing an operator the size of a deletion before making it.
func TestCollectDryRunReportsWithoutRemoving(t *testing.T) {
	adapter, objects, repository, _, _ := publishTwice(t)
	// A third publication, so there is something neither live nor restorable.
	publishInto(t, adapter, repository, "plan-3", `<a href="demo/">third</a>`)
	before, err := objects.List(context.Background(), ListRequest{Prefix: objectKey(repository, releasePrefix)})
	if err != nil {
		t.Fatal(err)
	}
	dry, err := adapter.Collect(context.Background(), repository, host.Retention{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun {
		t.Error("the result does not say it was a dry run")
	}
	if dry.Removed == 0 {
		t.Fatal("a dry run reported nothing to remove")
	}
	after, err := objects.List(context.Background(), ListRequest{Prefix: objectKey(repository, releasePrefix)})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Objects) != len(before.Objects) {
		t.Errorf("a dry run changed the bucket: %d objects became %d", len(before.Objects), len(after.Objects))
	}
	// And the real thing removes exactly what the dry run said.
	wet, err := adapter.Collect(context.Background(), repository, host.Retention{})
	if err != nil {
		t.Fatal(err)
	}
	if wet.Removed != dry.Removed || wet.RemovedBytes != dry.RemovedBytes {
		t.Errorf("dry run said %d objects / %d bytes, collection removed %d / %d",
			dry.Removed, dry.RemovedBytes, wet.Removed, wet.RemovedBytes)
	}
}

// A retention naming a tree keeps it, which is how a caller preserves more history
// than the minimum the host protects on its own.
func TestCollectKeepsTreesTheRetentionNames(t *testing.T) {
	adapter, objects, repository, firstCommit, _ := publishTwice(t)
	publishInto(t, adapter, repository, "plan-3", `<a href="demo/">third</a>`)
	// The first revision is now two behind, so nothing protects it but the request.
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{firstCommit.Revision.TreeSHA256},
	}); err != nil {
		t.Fatal(err)
	}
	if count := releaseObjectCount(t, objects, repository, firstCommit.Revision.TreeSHA256); count == 0 {
		t.Error("collection removed a tree the retention named")
	}
}

// A retention carrying something that is not a tree digest is a caller bug, and
// acting on it would mean deleting on the strength of a value nobody validated.
func TestCollectRefusesAnInvalidRetention(t *testing.T) {
	adapter, _, repository, _, _ := publishTwice(t)
	for _, tree := range []string{"not-a-digest", "", strings.Repeat("z", 64)} {
		if _, err := adapter.Collect(context.Background(), repository, host.Retention{
			KeepTrees: []string{tree},
		}); err == nil {
			t.Errorf("retention naming %q was accepted", tree)
		}
	}
}

// A repository with no managed revision cannot have a superseded one identified,
// so collection refuses rather than deleting whatever it finds.
func TestCollectRefusesARepositoryItDidNotPublish(t *testing.T) {
	adapter := New(newMemoryObjects())
	repository := host.Repository{
		Name: "python", Format: "pypi", CommitPaths: []string{pypiRootPath}, RootRewriter: pypiRootRewriter(),
		Type: "s3", Visibility: "public", Bucket: "packages", CanonicalEndpoint: "https://packages.example",
	}
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{}); err == nil {
		t.Error("collection ran against a repository with no managed revision")
	}
}

// A key under the release prefix that does not name a revision was put there by
// something else, and deleting what this adapter does not recognise is not
// collection.
func TestCollectLeavesUnrecognisedKeysAlone(t *testing.T) {
	adapter, objects, repository, _, _ := publishTwice(t)
	foreign := objectKey(repository, releasePrefix+"notes.txt")
	if _, err := objects.Put(context.Background(), PutRequest{
		Key: foreign, Body: strings.NewReader("x"), Size: 1, SHA256: digestBytes([]byte("x")),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{}); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Head(context.Background(), foreign); err != nil {
		t.Errorf("collection removed a key it did not write: %v", err)
	}
}

// Collection is offered only where it is implemented, and a caller decides by
// asking the host rather than by naming a type.
func TestTheS3HostIsACollector(t *testing.T) {
	if _, ok := any(New(newMemoryObjects())).(host.Collector); !ok {
		t.Error("the S3 host does not satisfy host.Collector")
	}
}
