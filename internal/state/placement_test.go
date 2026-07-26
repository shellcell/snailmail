package state

import (
	"errors"
	"reflect"
	"strconv"
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

func TestPrunePlacementsRetainsVersionsPerCoordinate(t *testing.T) {
	lock := RepositoryLock{
		PackageVersion: []PackageVersion{
			{Package: "demo", Version: "1", Blobs: []LockedBlob{{SHA256: strings.Repeat("a", 64)}}},
			{Package: "demo", Version: "2", Blobs: []LockedBlob{{SHA256: strings.Repeat("b", 64)}}},
			{Package: "demo", Version: "10", Blobs: []LockedBlob{{SHA256: strings.Repeat("c", 64)}}},
		},
		Placement: []Placement{
			{Package: "demo", Version: "1", Track: "stable"},
			{Package: "demo", Version: "2", Track: "stable"},
			{Package: "demo", Version: "10", Track: "stable"},
			{Package: "demo", Version: "1", Track: "testing"},
			{Package: "demo", Version: "2", Track: "testing"},
		},
	}
	compare := func(left, right string) (int, error) {
		leftValue, leftErr := strconv.Atoi(left)
		rightValue, rightErr := strconv.Atoi(right)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("invalid numeric version")
		}
		return leftValue - rightValue, nil
	}
	removed, err := PrunePlacements(&lock, 1, compare)
	if err != nil || removed != 3 {
		t.Fatalf("prune removed=%d err=%v", removed, err)
	}
	want := []Placement{
		{Package: "demo", Version: "10", Track: "stable"},
		{Package: "demo", Version: "2", Track: "testing"},
	}
	if !reflect.DeepEqual(lock.Placement, want) || len(lock.PackageVersion) != 3 {
		t.Fatalf("pruned lock %#v", lock)
	}
	digests := make(map[string]string)
	for _, version := range lock.PackageVersion {
		digests[version.Version] = version.Blobs[0].SHA256
	}
	if digests["1"] != strings.Repeat("a", 64) || digests["2"] != strings.Repeat("b", 64) || digests["10"] != strings.Repeat("c", 64) {
		t.Fatalf("prune changed package blobs %#v", digests)
	}
	if removed, err := PrunePlacements(&lock, 1, compare); err != nil || removed != 0 {
		t.Fatalf("idempotent prune removed=%d err=%v", removed, err)
	}
}

func TestPrunePlacementsRetainsCutoffTiesAndRollsBackErrors(t *testing.T) {
	lock := RepositoryLock{Placement: []Placement{
		{Package: "chart", Version: "1.0.0+one", Track: "stable"},
		{Package: "chart", Version: "1.0.0+two", Track: "stable"},
		{Package: "chart", Version: "0.9.0", Track: "stable"},
	}}
	compare := func(left, right string) (int, error) {
		left = strings.Split(left, "+")[0]
		right = strings.Split(right, "+")[0]
		if left < right {
			return -1, nil
		}
		if left > right {
			return 1, nil
		}
		return 0, nil
	}
	removed, err := PrunePlacements(&lock, 1, compare)
	if err != nil || removed != 1 || len(lock.Placement) != 2 {
		t.Fatalf("tie prune removed=%d lock=%#v err=%v", removed, lock, err)
	}
	before := append([]Placement(nil), lock.Placement...)
	if _, err := PrunePlacements(&lock, 1, func(string, string) (int, error) { return 0, errors.New("comparison failed") }); err == nil {
		t.Fatal("comparator failure was ignored")
	}
	if !reflect.DeepEqual(lock.Placement, before) {
		t.Fatal("comparator failure mutated placements")
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
