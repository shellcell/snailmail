package s3host

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/listing"
)

func browsablePage(t *testing.T, objects *memoryObjects, repository host.Repository) ([]byte, bool) {
	t.Helper()
	content, _, err := objects.Get(context.Background(), browsablePageKey(repository), maximumListingSize)
	if err != nil {
		return nil, false
	}
	return content, true
}

// The gap: a bucket-hosted repository had no page a person could open, because the
// listing lives in the release directory where Observe can verify it.
func TestAPublishedRepositoryHasAPageAPersonCanOpen(t *testing.T) {
	_, objects, repository, _ := publishHelmVersions(t, "1.0.0")
	content, found := browsablePage(t, objects, repository)
	if !found {
		t.Fatal("no browsable page at the repository root")
	}
	if !strings.Contains(string(content), "<html") {
		t.Errorf("the object at the root is not a page: %.60q", content)
	}
}

// It is a second copy, not a move. The verified one has to stay in the release
// directory, or a rollback leaves the previous revision unverifiable — Observe
// checks the whole file set and would find the newer bytes.
func TestTheVerifiedListingStaysInTheRelease(t *testing.T) {
	_, objects, repository, commits := publishHelmVersions(t, "1.0.0")
	tree := commits[0].Revision.TreeSHA256
	if _, _, err := objects.Get(context.Background(),
		releaseKey(repository, tree, listing.Filename), maximumListingSize); err != nil {
		t.Errorf("the release copy of the listing is gone: %v", err)
	}
}

// The page is written after the root is committed, so it advertises the revision
// that actually became live, and it is refreshed by each publication.
func TestTheBrowsablePageFollowsTheLiveRevision(t *testing.T) {
	_, objects, repository, _ := publishHelmVersions(t, "1.0.0", "2.0.0")
	content, found := browsablePage(t, objects, repository)
	if !found {
		t.Fatal("no browsable page")
	}
	if !strings.Contains(string(content), "2.0.0") {
		t.Error("the page does not show the live revision's chart")
	}
}

// It is named by no descriptor, so it looks exactly like an orphan to the
// collector added for helm and rpm. Collecting it would delete the page on every
// collection and leave the repository unbrowsable until the next publication.
func TestCollectionKeepsTheBrowsablePage(t *testing.T) {
	adapter, objects, repository, commits := publishHelmVersions(t, "1.0.0", "2.0.0", "3.0.0")
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{commits[2].Revision.TreeSHA256},
	}); err != nil {
		t.Fatal(err)
	}
	if _, found := browsablePage(t, objects, repository); !found {
		t.Error("collection deleted the browsable page")
	}
	// And the collection still did its job, so this is not passing because nothing
	// was collected.
	if count := releaseObjectCount(t, objects, repository, commits[0].Revision.TreeSHA256); count != 0 {
		t.Errorf("the superseded release kept %d objects", count)
	}
}

// The page is outside the publication's guarantees, and the guarantee itself must
// not depend on it. A repository whose page is missing observes normally.
func TestAMissingBrowsablePageDoesNotAffectTheRepository(t *testing.T) {
	adapter, objects, repository, _ := publishHelmVersions(t, "1.0.0")
	objects.mutex.Lock()
	delete(objects.objects, browsablePageKey(repository))
	objects.mutex.Unlock()

	observed, err := adapter.Observe(context.Background(), repository)
	if err != nil {
		t.Fatalf("a repository with no browsable page failed to observe: %v", err)
	}
	if observed.TreeSHA256 == "" {
		t.Error("the live revision was lost with the page")
	}
}
