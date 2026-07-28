package raw

import (
	"slices"
	"testing"
)

func order(t *testing.T, versions ...string) []string {
	t.Helper()
	sorted := slices.Clone(versions)
	slices.SortFunc(sorted, func(left, right string) int {
		result, err := CompareVersions(left, right)
		if err != nil {
			t.Fatal(err)
		}
		return result
	})
	return sorted
}

func TestSemverVersionsUseSemverPrecedence(t *testing.T) {
	got := order(t, "1.0.0", "0.2.0", "1.0.0-rc1", "0.1.2")
	want := []string{"0.1.2", "0.2.0", "1.0.0-rc1", "1.0.0"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The fallback exists so date schemes and four-component versions, which real
// projects ship and SemVer rejects, are still orderable.
func TestNonSemverVersionsUseNumericOrder(t *testing.T) {
	if got, want := order(t, "20240220", "20240115", "20231101"),
		[]string{"20231101", "20240115", "20240220"}; !slices.Equal(got, want) {
		t.Fatalf("dates: got %v, want %v", got, want)
	}
	// Numeric, so 10 sorts above 4 rather than lexically below it.
	if got, want := order(t, "1.2.3.10", "1.2.3.4", "1.2.3.2"),
		[]string{"1.2.3.2", "1.2.3.4", "1.2.3.10"}; !slices.Equal(got, want) {
		t.Fatalf("four-component: got %v, want %v", got, want)
	}
	// A missing segment is lower, so a release sorts above its own prefix.
	if got, want := order(t, "1.2.1.0", "1.2.1"), []string{"1.2.1", "1.2.1.0"}; !slices.Equal(got, want) {
		t.Fatalf("prefix: got %v, want %v", got, want)
	}
}

func TestComparisonIsATotalOrder(t *testing.T) {
	versions := []string{"1.0.0", "0.9.9", "20240115", "1.2.3.4", "1.0.0-rc1", "2024.1"}
	for _, left := range versions {
		for _, right := range versions {
			forward, err := CompareVersions(left, right)
			if err != nil {
				t.Fatal(err)
			}
			backward, err := CompareVersions(right, left)
			if err != nil {
				t.Fatal(err)
			}
			if forward != -backward {
				t.Errorf("comparing %q and %q is not antisymmetric (%d, %d)", left, right, forward, backward)
			}
			if left == right && forward != 0 {
				t.Errorf("%q does not equal itself (%d)", left, forward)
			}
		}
	}
	// Sorting must be stable regardless of input order, or prune would retain a
	// different cohort depending on how the lock happened to be written.
	first := order(t, versions...)
	slices.Reverse(versions)
	if second := order(t, versions...); !slices.Equal(first, second) {
		t.Fatalf("ordering depends on input order: %v then %v", first, second)
	}
}

// Documented consequence of accepting both schemes: a package that mixes them
// has a defined order that is not obvious. Pinning it here means a change to
// that behaviour is a deliberate edit rather than a surprise.
func TestSemverSortsBelowNonSemver(t *testing.T) {
	got, err := CompareVersions("1.0.0", "20240115")
	if err != nil {
		t.Fatal(err)
	}
	if got >= 0 {
		t.Fatalf("comparing 1.0.0 with 20240115 gave %d, want SemVer to sort lower", got)
	}
}
