package engine

import (
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

func publication(pkg, version, at, tree string) state.PublicationRecord {
	return state.PublicationRecord{
		SchemaVersion: 1, Repository: "apt", Package: pkg, Version: version,
		RecordedAt: at, TreeSHA256: tree, BlobSHA256: []string{"aa"},
	}
}

// A publication re-records every version it serves, so a version accumulates a
// record per published tree. The date reported is the first — when it reached a
// client — because that is what the question asks, and the version's own bytes
// are pinned and never change.
func TestRolloutReportsFirstPublication(t *testing.T) {
	records := []state.PublicationRecord{
		publication("demo", "1.0.0", "2026-01-01T00:00:00Z", "tree-1"),
		publication("demo", "1.0.0", "2026-02-01T00:00:00Z", "tree-2"),
		publication("demo", "2.0.0", "2026-02-01T00:00:00Z", "tree-2"),
		publication("demo", "1.0.0", "2026-03-01T00:00:00Z", "tree-3"),
		publication("demo", "2.0.0", "2026-03-01T00:00:00Z", "tree-3"),
	}
	served := map[string]bool{"demo\x001.0.0": true, "demo\x002.0.0": true}
	releases := rolloutReleases("apt", records, served, RolloutWorkspaceRequest{})
	if len(releases) != 2 {
		t.Fatalf("got %d releases, want one per version: %+v", len(releases), releases)
	}
	first := releases[0]
	if first.Version != "1.0.0" || first.PublishedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("1.0.0 reported as published %q, want its first record", first.PublishedAt)
	}
	if first.Publications != 3 {
		t.Errorf("1.0.0 appears in %d trees, want 3", first.Publications)
	}
	// The newest tree is the one a client is served from now, so that is the one
	// reported — the first record's date with the latest record's tree.
	if first.TreeSHA256 != "tree-3" {
		t.Errorf("1.0.0 names tree %q, want the newest that served it", first.TreeSHA256)
	}
	if releases[1].Publications != 2 {
		t.Errorf("2.0.0 appears in %d trees, want 2", releases[1].Publications)
	}
}

// A version published and then withdrawn is history, not something a client can
// install, so it is left out unless asked for. The ledger keeps the record
// either way: publication is immutable even when the offer is not.
func TestRolloutSeparatesWithdrawnVersions(t *testing.T) {
	records := []state.PublicationRecord{
		publication("demo", "1.0.0", "2026-01-01T00:00:00Z", "tree-1"),
		publication("demo", "2.0.0", "2026-02-01T00:00:00Z", "tree-2"),
	}
	served := map[string]bool{"demo\x002.0.0": true}

	offered := rolloutReleases("apt", records, served, RolloutWorkspaceRequest{})
	if len(offered) != 1 || offered[0].Version != "2.0.0" {
		t.Fatalf("default view shows %+v, want only what is served", offered)
	}
	if !offered[0].Served {
		t.Error("a served version is not marked as served")
	}

	all := rolloutReleases("apt", records, served, RolloutWorkspaceRequest{IncludeWithdrawn: true})
	if len(all) != 2 {
		t.Fatalf("withdrawn view shows %d releases, want 2", len(all))
	}
	if all[0].Version != "1.0.0" || all[0].Served {
		t.Errorf("the withdrawn version is %+v, want 1.0.0 marked unserved", all[0])
	}
}

func TestRolloutNarrowsToOnePackage(t *testing.T) {
	records := []state.PublicationRecord{
		publication("demo", "1.0.0", "2026-01-01T00:00:00Z", "tree-1"),
		publication("other", "1.0.0", "2026-01-01T00:00:00Z", "tree-1"),
	}
	served := map[string]bool{"demo\x001.0.0": true, "other\x001.0.0": true}
	releases := rolloutReleases("apt", records, served, RolloutWorkspaceRequest{Package: "other"})
	if len(releases) != 1 || releases[0].Package != "other" {
		t.Fatalf("got %+v, want only the named package", releases)
	}
}
