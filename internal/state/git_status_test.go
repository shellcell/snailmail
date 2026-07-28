package state

import "testing"

func TestParseGitStatusReadsRenameAndSpacedPaths(t *testing.T) {
	// Porcelain v1 -z emits a rename as the new path followed by the original
	// path in its own NUL-terminated field, and never quotes or escapes.
	status := "R  repos/new name.lock.toml\x00repos/old name.lock.toml\x00 M snailmail.toml\x00?? notes.txt\x00"
	entries, err := parseGitStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("parsed %d entries, want 3: %+v", len(entries), entries)
	}
	rename := entries[0]
	if rename.code != "R " || len(rename.paths) != 2 ||
		rename.paths[0] != "repos/new name.lock.toml" || rename.paths[1] != "repos/old name.lock.toml" {
		t.Fatalf("rename entry parsed as %+v", rename)
	}
	if entries[1].code != " M" || entries[1].paths[0] != "snailmail.toml" {
		t.Fatalf("modification entry parsed as %+v", entries[1])
	}
	if entries[2].code != "??" || entries[2].paths[0] != "notes.txt" {
		t.Fatalf("untracked entry parsed as %+v", entries[2])
	}
}

func TestValidateGitStatusRejectsRenamedAuthoritativeState(t *testing.T) {
	// The old newline parser produced the single name "a -> b", which matched no
	// allowlist entry and no authoritative path, so a renamed lock could slip
	// through as an unrecognised entry.
	status := "R  repos/renamed.lock.toml\x00repos/pypi.lock.toml\x00"
	authoritative := map[string]bool{"repos/pypi.lock.toml": true}
	if err := validateGitStatus(status, nil, authoritative); err == nil {
		t.Fatal("expected a renamed authoritative lock to be rejected")
	}
}

func TestValidateGitStatusAllowsPermittedUntrackedPath(t *testing.T) {
	status := "?? publications/pypi.jsonl\x00"
	allowed := map[string]bool{"publications/pypi.jsonl": true}
	if err := validateGitStatusAllowingUntracked(status, allowed, nil); err != nil {
		t.Fatalf("permitted untracked ledger was rejected: %v", err)
	}
	if err := validateGitStatusAllowingUntracked(status, nil, nil); err == nil {
		t.Fatal("expected an unpermitted untracked ledger to be rejected")
	}
}
