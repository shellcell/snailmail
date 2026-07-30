package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

func ledgerRecord(pkg, version, tree string) state.PublicationRecord {
	return state.PublicationRecord{
		SchemaVersion: 1, Repository: "apt", Package: pkg, Version: version,
		RecordedAt: "2026-01-01T00:00:00Z", TreeSHA256: tree, BlobSHA256: []string{"aa"},
	}
}

func treeDigest(seed byte) string { return strings.Repeat(string("0123456789abcdef"[seed%16]), 64) }

// Every publication re-records every version it serves, so one tree appears in
// many ledger entries. Keeping "the last three records" would keep one revision
// three times over and delete two that are still wanted.
func TestRecentTreesAreDistinctRevisionsNotRecords(t *testing.T) {
	first, second, third := treeDigest(1), treeDigest(2), treeDigest(3)
	records := []state.PublicationRecord{
		ledgerRecord("a", "1.0.0", first),
		// One publication carrying three versions — three records, one tree.
		ledgerRecord("a", "1.0.0", second),
		ledgerRecord("b", "1.0.0", second),
		ledgerRecord("c", "1.0.0", second),
		ledgerRecord("a", "1.0.0", third),
	}
	trees := newestDistinctTrees(records, 2)
	if len(trees) != 2 {
		t.Fatalf("got %d trees, want 2 distinct revisions: %v", len(trees), trees)
	}
	kept := map[string]bool{}
	for _, tree := range trees {
		kept[tree] = true
	}
	if !kept[third] || !kept[second] {
		t.Errorf("kept %v, want the two newest revisions", trees)
	}
	if kept[first] {
		t.Error("kept the oldest revision when only two were asked for")
	}
}

// Newest by ledger order rather than by timestamp. The ledger is append-only, and
// a clock is not a reliable ordering across the machines that write to it.
func TestRecentTreesFollowLedgerOrderNotTime(t *testing.T) {
	older, newer := treeDigest(4), treeDigest(5)
	records := []state.PublicationRecord{
		ledgerRecord("a", "1.0.0", older),
		ledgerRecord("a", "2.0.0", newer),
	}
	// The later record claims an earlier time, which a clock-based ordering would
	// believe.
	records[1].RecordedAt = "2020-01-01T00:00:00Z"
	trees := newestDistinctTrees(records, 1)
	if len(trees) != 1 || trees[0] != newer {
		t.Errorf("kept %v, want the last-recorded revision %q", trees, newer)
	}
}

// Asking for none is how a caller says "keep only what the host protects on its
// own", which is the live revision and its rollback.
func TestKeepingNoneNamesNothing(t *testing.T) {
	records := []state.PublicationRecord{ledgerRecord("a", "1.0.0", treeDigest(6))}
	if trees := newestDistinctTrees(records, 0); len(trees) != 0 {
		t.Errorf("keeping zero named %v", trees)
	}
}

// The retention handed to a host is sorted, so a dry run reports the same thing
// twice and a host cannot come to depend on ledger order.
func TestTheRetentionIsOrderIndependent(t *testing.T) {
	records := []state.PublicationRecord{
		ledgerRecord("a", "1.0.0", treeDigest(9)),
		ledgerRecord("a", "2.0.0", treeDigest(3)),
		ledgerRecord("a", "3.0.0", treeDigest(7)),
	}
	trees := newestDistinctTrees(records, 3)
	for index := 1; index < len(trees); index++ {
		if trees[index-1] > trees[index] {
			t.Errorf("retention is not sorted: %v", trees)
			break
		}
	}
}

// keepOf is a retention override, which is a pointer because every integer value
// means something: zero keeps nothing beyond what the host protects, and a negative
// one is an error. Nil is the only way to say "use the repository's own policy".
func keepOf(value int) *int { return &value }

// A negative keep is a caller bug, and acting on it would mean deleting on the
// strength of a number nobody checked.
func TestCollectRefusesANegativeKeep(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi")
	if _, err := CollectWorkspace(context.Background(), CollectWorkspaceRequest{Root: root, Keep: keepOf(-1)}); err == nil {
		t.Error("a negative keep was accepted")
	}
}

// A host that keeps nothing reports so rather than being skipped, or a reader
// cannot tell "nothing to do" from "not looked at".
func TestAHostThatKeepsNothingSaysSo(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi", "deb")
	result, err := CollectWorkspace(context.Background(), CollectWorkspaceRequest{Root: root, Keep: keepOf(5)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 2 {
		t.Fatalf("reported %d repositories, want 2", len(result.Repositories))
	}
	for _, reported := range result.Repositories {
		if reported.Collectable {
			t.Errorf("%s reported as collectable; the fixture publishes to a directory", reported.Name)
		}
		if reported.Note == "" {
			t.Errorf("%s reported nothing about why it was not collected", reported.Name)
		}
	}
	if result.Applied {
		t.Error("a request without Apply reported that it applied")
	}
}

// Naming a repository that is not configured is a mistake worth reporting rather
// than an empty result that looks like success.
func TestCollectRefusesAnUnknownRepository(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi")
	_, err := CollectWorkspace(context.Background(), CollectWorkspaceRequest{Root: root, Repository: "absent"})
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("error = %v, want the unknown repository named", err)
	}
}
