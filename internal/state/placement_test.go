package state

import (
	"reflect"
	"strings"
	"testing"
)

func TestPromoteAndYankPlacements(t *testing.T) {
	lock := RepositoryLock{
		SchemaVersion: LockSchema,
		Repository:    "python",
		PackageVersion: []PackageVersion{{
			Package: "demo", Version: "1.2.3", State: "draft",
			Blobs: []LockedBlob{{Filename: "demo-1.2.3-py3-none-any.whl", Size: 1, SHA256: strings.Repeat("a", 64)}},
		}},
		Placement: []Placement{{Package: "demo", Version: "1.2.3", Track: "stable"}},
	}
	changed, err := PromotePlacement(&lock, "pypi", "demo", "1.2.3", "testing", "")
	if err != nil || !changed {
		t.Fatalf("promote changed=%v err=%v", changed, err)
	}
	if changed, err := PromotePlacement(&lock, "pypi", "demo", "1.2.3", "testing", ""); err != nil || changed {
		t.Fatalf("duplicate promote changed=%v err=%v", changed, err)
	}
	if !reflect.DeepEqual(lock.Placement, []Placement{
		{Package: "demo", Version: "1.2.3", Track: "stable"},
		{Package: "demo", Version: "1.2.3", Track: "testing"},
	}) {
		t.Fatalf("promoted placements %#v", lock.Placement)
	}
	removed, err := YankPlacements(&lock, "pypi", "demo", "1.2.3", "stable", "", false)
	if err != nil || removed != 1 || len(lock.PackageVersion) != 1 || len(lock.PackageVersion[0].Blobs) != 1 {
		t.Fatalf("exact yank removed=%d lock=%#v err=%v", removed, lock, err)
	}
	if removed, err := YankPlacements(&lock, "pypi", "demo", "1.2.3", "stable", "", false); err != nil || removed != 0 {
		t.Fatalf("idempotent yank removed=%d err=%v", removed, err)
	}
	removed, err = YankPlacements(&lock, "pypi", "demo", "1.2.3", "", "", true)
	if err != nil || removed != 1 || len(lock.Placement) != 0 || len(lock.PackageVersion) != 1 {
		t.Fatalf("all yank removed=%d lock=%#v err=%v", removed, lock, err)
	}
	if _, err := PromotePlacement(&lock, "pypi", "missing", "1.2.3", "stable", ""); err == nil {
		t.Fatal("promoted an unknown package version")
	}
	if _, err := YankPlacements(&lock, "pypi", "missing", "1.2.3", "", "", true); err == nil {
		t.Fatal("yanked an unknown package version")
	}
	if _, err := PromotePlacement(&lock, "pypi", "demo", "1.2.3", "../unsafe", ""); err == nil {
		t.Fatal("accepted unsafe track")
	}
}

func TestPlacementDistroValidation(t *testing.T) {
	lock := RepositoryLock{
		SchemaVersion: LockSchema, Repository: "debian",
		PackageVersion: []PackageVersion{{
			Package: "demo", Version: "1.2.3-1", State: "draft",
			Blobs: []LockedBlob{{Filename: "demo_1.2.3-1_amd64.deb", Architecture: "amd64", Size: 1, SHA256: strings.Repeat("b", 64)}},
		}},
	}
	if _, err := PromotePlacement(&lock, "deb", "demo", "1.2.3-1", "testing", "bookworm"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLock(lock, "debian", "deb"); err != nil {
		t.Fatal(err)
	}
	if _, err := PromotePlacement(&lock, "deb", "demo", "1.2.3-1", "stable", ""); err == nil {
		t.Fatal("accepted empty Debian distro")
	}
	if _, err := PromotePlacement(&lock, "pypi", "demo", "1.2.3-1", "stable", "bookworm"); err == nil {
		t.Fatal("accepted PyPI distro")
	}
}
