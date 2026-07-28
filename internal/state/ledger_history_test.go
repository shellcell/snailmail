package state

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	full := append([]string{"-C", root,
		"-c", "user.name=snailmail-test", "-c", "user.email=test@example.invalid"}, arguments...)
	if output, err := exec.Command("git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func writeLedger(t *testing.T, root, repository, content string) {
	t.Helper()
	directory := filepath.Join(root, "publications")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, repository+".jsonl"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ledgerLine(planID, treeSHA, pkg, version string) string {
	return `{"schema_version":1,"plan_id":"` + planID + `","change_id":"pypi:` + treeSHA[:12] +
		`","repository":"pypi","package":"` + pkg + `","version":"` + version +
		`","blob_sha256":["` + treeSHA + `"],"tree_sha256":"` + treeSHA + `","recorded_at":"2026-01-01T00:00:00Z"}` + "\n"
}

// A record that only ever existed on an abandoned branch was never part of this
// line of history. Replaying every ref folded it in and then reported the
// perfectly good worktree ledger as having removed an immutable record.
func TestLedgerHistoryIgnoresAbandonedBranch(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	planID := "11" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	treeSHA := "22" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	kept := ledgerLine(planID, treeSHA, "kept", "1.0.0")
	writeLedger(t, root, "pypi", kept)
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-m", "record kept publication")

	runGit(t, root, "checkout", "-q", "-b", "abandoned")
	otherPlan := "33" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	otherTree := "44" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	writeLedger(t, root, "pypi", kept+ledgerLine(otherPlan, otherTree, "abandoned", "9.9.9"))
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-m", "record abandoned publication")

	runGit(t, root, "checkout", "-q", "-")
	writeLedger(t, root, "pypi", kept)

	records, err := LoadLedgerHistoryContext(context.Background(), root, "pypi")
	if err != nil {
		t.Fatalf("history replay rejected a workspace with an abandoned branch: %v", err)
	}
	if len(records) != 1 || records[0].Package != "kept" {
		t.Fatalf("replayed %d records, want only the reachable one: %+v", len(records), records)
	}
}

// Records committed on the current line of history are still immutable.
func TestLedgerHistoryRejectsRemovedReachableRecord(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	planID := "55" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	treeSHA := "66" + "00000000000000000000000000000000000000000000000000000000000000"[:62]
	writeLedger(t, root, "pypi", ledgerLine(planID, treeSHA, "kept", "1.0.0"))
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-m", "record publication")

	writeLedger(t, root, "pypi", "")
	if _, err := LoadLedgerHistoryContext(context.Background(), root, "pypi"); err == nil {
		t.Fatal("expected removal of a reachable immutable record to be rejected")
	}
}
