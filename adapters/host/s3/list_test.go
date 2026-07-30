package s3host

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Listing is the one operation that does not address a key the caller already
// knows, so it is the one where a caller can silently see part of the truth. The
// contract that matters is that following the token returns every key exactly
// once.
func TestListPagesOverEveryKeyExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := newMemoryObjects()
	const total = 2500
	for index := range total {
		key := fmt.Sprintf("repo/.snailmail/releases/tree-%04d/index.html", index)
		if _, err := store.Put(ctx, PutRequest{Key: key, Body: strings.NewReader("x"), Size: 1, SHA256: digestBytes([]byte("x"))}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]int{}
	pages := 0
	after := ""
	for {
		page, err := store.List(ctx, ListRequest{Prefix: "repo/.snailmail/releases/", After: after, Limit: 400})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if pages > 20 {
			t.Fatal("listing did not terminate; the continuation token is not advancing")
		}
		for _, object := range page.Objects {
			seen[object.Key]++
		}
		if page.More == "" {
			break
		}
		after = page.More
	}
	if len(seen) != total {
		t.Errorf("saw %d distinct keys across %d pages, want %d", len(seen), pages, total)
	}
	for key, count := range seen {
		if count != 1 {
			t.Errorf("key %q was returned %d times", key, count)
		}
	}
	if pages < 2 {
		t.Errorf("a %d-key listing came back in %d page, so paging was never exercised", total, pages)
	}
}

// The prefix is what keeps a listing scoped to one repository. An unscoped one
// would enumerate a bucket that may not be only snailmail's, which is expensive
// and not something to do by accident.
func TestListRefusesAnUnscopedRequest(t *testing.T) {
	if _, err := newMemoryObjects().List(context.Background(), ListRequest{}); err == nil {
		t.Error("a listing with no prefix was accepted")
	}
}

// A prefix returns what is under it and nothing beside it — including the case
// that catches a naive implementation, where one repository's prefix is a prefix
// of another's name.
func TestListReturnsOnlyWhatIsUnderThePrefix(t *testing.T) {
	ctx := context.Background()
	store := newMemoryObjects()
	for _, key := range []string{
		"repo/a.txt",
		"repo/.snailmail/releases/one/index.html",
		"repo/.snailmail/releases/two/index.html",
		"repo-other/.snailmail/releases/three/index.html",
		"other/b.txt",
	} {
		if _, err := store.Put(ctx, PutRequest{Key: key, Body: strings.NewReader("x"), Size: 1, SHA256: digestBytes([]byte("x"))}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.List(ctx, ListRequest{Prefix: "repo/.snailmail/releases/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 2 {
		t.Fatalf("got %d objects, want the two under the prefix: %+v", len(page.Objects), page.Objects)
	}
	for _, object := range page.Objects {
		if !strings.HasPrefix(object.Key, "repo/.snailmail/releases/") {
			t.Errorf("listing returned %q, which is not under the prefix", object.Key)
		}
	}
	if page.More != "" {
		t.Errorf("a complete listing reported more to come: %q", page.More)
	}
}

// The size comes back because a collector adding up what it would reclaim needs
// it, and heading every object to find out would turn one listing into thousands
// of requests.
func TestListReportsSizes(t *testing.T) {
	ctx := context.Background()
	store := newMemoryObjects()
	content := "twelve bytes"
	if _, err := store.Put(ctx, PutRequest{
		Key: "repo/x/index.html", Body: strings.NewReader(content),
		Size: int64(len(content)), SHA256: digestBytes([]byte(content)),
	}); err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ctx, ListRequest{Prefix: "repo/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 1 || page.Objects[0].Size != int64(len(content)) {
		t.Errorf("got %+v, want one object of %d bytes", page.Objects, len(content))
	}
}
