package s3host

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
)

// Two CI runners on separate machines are not serialised by the workspace lock,
// which is a file in a checkout. What protects a repository is the conditional
// commit here: each runner states the revision it observed, and the second to
// arrive is refused because that is no longer what is live.
//
// This is the scenario in full — both runners plan against the same empty
// repository, then both publish — rather than a synthetic stale expectation.
func TestTwoRunnersPublishingToOneBucket(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", CommitPaths: []string{pypiRootPath}, RootRewriter: pypiRootRewriter(),
		Type: "s3", Visibility: "public", Bucket: "packages", Prefix: "repo",
		CanonicalEndpoint: "https://packages.example/repo",
	}
	// Two adapters over one store, which is two runners against one bucket.
	runnerA, runnerB := New(objects), New(objects)

	// Both observe the same empty repository, which is the race.
	observedByA, err := runnerA.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	observedByB, err := runnerB.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observedByA != observedByB {
		t.Fatalf("the two runners disagree about the starting state: %+v vs %+v", observedByA, observedByB)
	}

	requestA := stageFixture(t, "plan-a", "", "", `<a href="demo/">runner a</a>`)
	requestB := stageFixture(t, "plan-b", "", "", `<a href="demo/">runner b</a>`)
	stageA, err := runnerA.Stage(ctx, repository, requestA)
	if err != nil {
		t.Fatal(err)
	}
	// Both stage successfully. Staging is not exclusive, and must not be: it writes
	// only under its own stage identifier and touches nothing a client reads.
	stageB, err := runnerB.Stage(ctx, repository, requestB)
	if err != nil {
		t.Fatalf("the second runner could not stage alongside the first: %v", err)
	}

	committedByA, err := runnerA.Commit(ctx, repository, stageA, expectedFrom(observedByA))
	if err != nil {
		t.Fatalf("the first runner failed to publish: %v", err)
	}

	// The second runner commits against the state it observed, which is no longer
	// live. This is the collision, and it has to be refused as stale rather than
	// overwrite what the first published.
	_, err = runnerB.Commit(ctx, repository, stageB, expectedFrom(observedByB))
	if err == nil {
		t.Fatal("the second runner published over the first without being told")
	}
	if !host.IsKind(err, host.ErrorStale) {
		t.Errorf("the second runner was refused as %v, want a stale-plan error so a caller knows to replan", err)
	}

	// And the first runner's publication is intact and observable.
	observed, err := runnerA.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed != committedByA.Revision {
		t.Errorf("observed %+v after the collision, want the first runner's revision", observed)
	}
	// Compared by tree identity rather than by content: the index is generated, so
	// the string a fixture was seeded with does not appear in it.
	root, _, err := objects.Get(ctx, objectKey(repository, pypiRootPath), maximumMetadataSize)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(root), committedByA.Revision.TreeSHA256) {
		t.Errorf("the live root does not point at the first runner's release %s",
			committedByA.Revision.TreeSHA256)
	}
	if observed.TreeSHA256 == requestB.TreeSHA256 {
		t.Error("the second runner's tree is live, so its commit was not refused")
	}
}

// Once the second runner replans against what is actually live, it succeeds. The
// refusal above is a retry signal, not a dead end — which is the difference between
// a usable failure mode and a broken one.
func TestTheRefusedRunnerSucceedsAfterReplanning(t *testing.T) {
	ctx := context.Background()
	objects := newMemoryObjects()
	repository := host.Repository{
		Name: "python", Format: "pypi", CommitPaths: []string{pypiRootPath}, RootRewriter: pypiRootRewriter(),
		Type: "s3", Visibility: "public", Bucket: "packages", Prefix: "repo",
		CanonicalEndpoint: "https://packages.example/repo",
	}
	runnerA, runnerB := New(objects), New(objects)
	stale, err := runnerA.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	requestA := stageFixture(t, "plan-a", "", "", `<a href="demo/">runner a</a>`)
	stageA, err := runnerA.Stage(ctx, repository, requestA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runnerA.Commit(ctx, repository, stageA, expectedFrom(stale)); err != nil {
		t.Fatal(err)
	}
	// Runner B replans: observes again, stages again, commits against what is live.
	current, err := runnerB.Observe(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	requestB := stageFixture(t, "plan-b", "", "", `<a href="demo/">runner b</a>`)
	stageB, err := runnerB.Stage(ctx, repository, requestB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runnerB.Commit(ctx, repository, stageB, expectedFrom(current)); err != nil {
		t.Fatalf("a runner that replanned against live state was still refused: %v", err)
	}
}
