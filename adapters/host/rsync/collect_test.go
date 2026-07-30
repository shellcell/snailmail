package rsynchost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
)

func releasesPresent(t *testing.T, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(base, releasesDirectory))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// The gap this closes: the swap that makes a revision live does not remove the one
// it replaced, so a project publishing daily leaves a copy a day on the far side.
func TestCollectRemovesSupersededReleases(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)

	first, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := publish(t, adapter, repository, "2.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if len(releasesPresent(t, base)) != 2 {
		t.Fatalf("expected two releases before collection, found %v", releasesPresent(t, base))
	}
	result, err := adapter.Collect(context.Background(), repository, host.Retention{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 1 || result.KeptRevisions != 1 {
		t.Errorf("collected %+v, want one removed and the live one kept", result)
	}
	remaining := releasesPresent(t, base)
	if len(remaining) != 1 || remaining[0] != second.Revision.TreeSHA256 {
		t.Errorf("releases after collection = %v, want the live revision alone", remaining)
	}
	// And the repository is still being served, which is what a wrong collection
	// here would break.
	if _, err := os.ReadFile(filepath.Join(repository.Path, "simple", "index.html")); err != nil {
		t.Errorf("the live revision is no longer served: %v", err)
	}
}

// Unlike the object store, this host protects only the live revision and what the
// retention names — there is no restore target, because Restore is not offered. So
// a caller that wants an older revision kept has to say so.
func TestCollectKeepsWhatTheRetentionNames(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)

	first, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish(t, adapter, repository, "2.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256}); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Collect(context.Background(), repository, host.Retention{
		KeepTrees: []string{first.Revision.TreeSHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 0 || result.KeptRevisions != 2 {
		t.Errorf("collected %+v, want both kept", result)
	}
	if len(releasesPresent(t, base)) != 2 {
		t.Error("a release the retention named was removed")
	}
}

// A dry run reports the reclaim without making it.
func TestCollectDryRunRemovesNothing(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)
	first, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish(t, adapter, repository, "2.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256}); err != nil {
		t.Fatal(err)
	}
	dry, err := adapter.Collect(context.Background(), repository, host.Retention{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Removed != 1 {
		t.Errorf("a dry run reported %+v", dry)
	}
	if len(releasesPresent(t, base)) != 2 {
		t.Error("a dry run removed a release")
	}
}

// Without knowing what is live, every deletion is a guess. The other collectors
// refuse in this position and so does this one.
func TestCollectRefusesWhenNothingIsPublished(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)
	_, err := adapter.Collect(context.Background(), repository, host.Retention{})
	if err == nil {
		t.Fatal("a collection ran against a repository with no published revision")
	}
	if !strings.Contains(err.Error(), "no revision is published") {
		t.Errorf("error = %v, want the reason stated", err)
	}
}

// A directory under the release prefix that does not name a revision was put there
// by something else, and deleting what it does not recognise is not collection.
func TestCollectLeavesUnrecognisedDirectoriesAlone(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)
	if _, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(base, releasesDirectory, "not-a-tree-digest")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Collect(context.Background(), repository, host.Retention{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Error("collection deleted a directory it did not recognise")
	}
}

func TestTheRsyncHostIsACollector(t *testing.T) {
	var _ host.Collector = New(&localRunner{})
}
