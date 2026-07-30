package s3host

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
)

// publishHelmVersions publishes one revision per chart version, each revision
// holding only that version — so the earlier chart objects become unreferenced
// exactly as they do when a chart is dropped from a workspace.
func publishHelmVersions(t *testing.T, versions ...string) (*Adapter, *memoryObjects, host.Repository, []host.CommitResult) {
	t.Helper()
	ctx := context.Background()
	objects := newMemoryObjects()
	adapter := New(objects)
	repository := helmRepository("https://charts.example/repo")
	var commits []host.CommitResult
	expected := host.ExpectedRevision{}
	for index, version := range versions {
		request := helmStageFixture(t, "plan-"+version, "demo", version)
		staged, err := adapter.Stage(ctx, repository, request)
		if err != nil {
			t.Fatal(err)
		}
		committed, err := adapter.Commit(ctx, repository, staged, expected)
		if err != nil {
			t.Fatalf("commit %d: %v", index, err)
		}
		commits = append(commits, committed)
		expected = expectedFrom(committed.Revision)
	}
	return adapter, objects, repository, commits
}

func canonicalChartKeys(t *testing.T, objects *memoryObjects, repository host.Repository) []string {
	t.Helper()
	page, err := objects.List(context.Background(), ListRequest{Prefix: objectKey(repository, "")})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	reserved := objectKey(repository, ".snailmail")
	for _, object := range page.Objects {
		if strings.HasPrefix(object.Key, reserved) {
			continue
		}
		if strings.HasSuffix(object.Key, ".tgz") {
			keys = append(keys, object.Key)
		}
	}
	return keys
}

// The gap this closes. A helm repository writes its charts at the paths clients
// fetch them from, outside any release directory, because index.yaml names those
// paths. Collecting release directories therefore never touches them, and a chart
// dropped from the workspace stays a billable object indefinitely.
func TestCollectRemovesChartsNoSurvivingRevisionNames(t *testing.T) {
	adapter, objects, repository, commits := publishHelmVersions(t, "1.0.0", "2.0.0", "3.0.0")
	before := canonicalChartKeys(t, objects, repository)
	if len(before) != 3 {
		t.Fatalf("expected three charts at canonical paths, found %v", before)
	}
	// Three revisions because two are always protected — the live one and the one
	// its restore rolls back to — so the first publication is the first collectable
	// one. The same rule governs release directories, and the charts follow it
	// rather than a rule of their own.
	result, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{commits[len(commits)-1].Revision.TreeSHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := canonicalChartKeys(t, objects, repository)
	if len(after) != 2 {
		t.Errorf("charts after collection = %v, want the live revision's and its restore target's", after)
	}
	for _, key := range after {
		if strings.Contains(key, "1.0.0") {
			t.Errorf("the superseded chart survived: %q", key)
		}
	}
	if result.Removed == 0 {
		t.Error("collection reported removing nothing")
	}
	if result.RemovedBytes == 0 {
		t.Error("collection reported reclaiming no bytes, so an operator cannot see what it was worth")
	}
}

// A chart the live revision still serves must survive, which is the failure that
// would take a repository down rather than merely cost storage.
func TestCollectKeepsChartsTheLiveRevisionServes(t *testing.T) {
	adapter, objects, repository, _ := publishHelmVersions(t, "1.0.0")
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{}); err != nil {
		t.Fatal(err)
	}
	if keys := canonicalChartKeys(t, objects, repository); len(keys) != 1 {
		t.Fatalf("the live revision's chart was removed: %v", keys)
	}
}

// A dry run has to report the reclaim without making it, or it is no use for
// deciding whether to.
func TestCollectDryRunLeavesOrphanedChartsInPlace(t *testing.T) {
	adapter, objects, repository, commits := publishHelmVersions(t, "1.0.0", "2.0.0", "3.0.0")
	dry, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{commits[2].Revision.TreeSHA256}, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Removed == 0 {
		t.Fatal("a dry run reported nothing to remove")
	}
	if keys := canonicalChartKeys(t, objects, repository); len(keys) != 3 {
		t.Errorf("a dry run removed charts: %v", keys)
	}
	// And the real collection removes what the dry run reported.
	wet, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{commits[2].Revision.TreeSHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wet.Removed != dry.Removed || wet.RemovedBytes != dry.RemovedBytes {
		t.Errorf("dry run said %d objects and %d bytes, collection did %d and %d",
			dry.Removed, dry.RemovedBytes, wet.Removed, wet.RemovedBytes)
	}
}

// The reference set comes from the surviving revisions' manifests. If one cannot be
// read, every canonical object might belong to it — so the collection refuses
// rather than deleting against an unknown reference set. This is the difference
// between costing storage and costing a repository.
func TestCollectRefusesWhenASurvivingManifestCannotBeRead(t *testing.T) {
	adapter, objects, repository, commits := publishHelmVersions(t, "1.0.0", "2.0.0")
	live := commits[1].Revision.TreeSHA256
	// Removed directly rather than through Delete, because this is the state a
	// lifecycle rule or a stray console deletion leaves behind, not one snailmail
	// would produce.
	objects.mutex.Lock()
	delete(objects.objects, releaseDescriptorKey(repository, live))
	objects.mutex.Unlock()

	_, err := adapter.Collect(context.Background(), repository, host.Retention{KeepTrees: []string{live}})
	if err == nil {
		t.Fatal("a collection ran without knowing what the live revision publishes")
	}
	if keys := canonicalChartKeys(t, objects, repository); len(keys) != 2 {
		t.Errorf("charts were removed despite the refusal: %v", keys)
	}
}

// A staged repository writes every file inside its release directory, so there is
// nothing at a canonical path to orphan — and a collection that went looking would
// find the artifacts of a format whose index it does not govern.
func TestCollectLeavesAStagedRepositoryAlone(t *testing.T) {
	adapter, objects, repository, first, second := publishTwice(t)
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{second.Revision.TreeSHA256},
	}); err != nil {
		t.Fatal(err)
	}
	// A staged repository does have one object outside .snailmail — the root, which
	// is rebound at its canonical path so clients can fetch it. That must survive,
	// and nothing else out there should have been invented to delete.
	page, err := objects.List(context.Background(), ListRequest{Prefix: objectKey(repository, "")})
	if err != nil {
		t.Fatal(err)
	}
	var canonical []string
	for _, object := range page.Objects {
		if !strings.HasPrefix(object.Key, objectKey(repository, ".snailmail")) {
			canonical = append(canonical, object.Key)
		}
	}
	// Two, and both are meant to be there: the rebound root a client fetches, and
	// the browsable page a person opens. A staged repository keeps nothing else
	// outside .snailmail, so nothing was invented to delete.
	if len(canonical) != 2 {
		t.Errorf("canonical objects after collection = %v, want the root and the browsable page", canonical)
	}
	var foundRoot, foundPage bool
	for _, key := range canonical {
		switch key {
		case objectKey(repository, pypiRootPath):
			foundRoot = true
		case browsablePageKey(repository):
			foundPage = true
		}
	}
	if !foundRoot {
		t.Error("the rebound root was collected")
	}
	if !foundPage {
		t.Error("the browsable page was collected")
	}
	// The live revision is still readable, which is the thing a wrong collection
	// here would break.
	if _, err := adapter.Observe(context.Background(), repository); err != nil {
		t.Errorf("the repository is no longer observable after collection: %v", err)
	}
	_ = first
}
