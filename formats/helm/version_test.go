package helm

import "testing"

func TestCompareVersionsUsesSemverPrecedence(t *testing.T) {
	for _, test := range []struct{ newer, older string }{
		{"1.10.0", "1.9.0"},
		{"1.0.0", "1.0.0-rc.1"},
	} {
		comparison, err := CompareVersions(test.newer, test.older)
		if err != nil || comparison <= 0 {
			t.Fatalf("CompareVersions(%q, %q)=%d, %v", test.newer, test.older, comparison, err)
		}
	}
	if comparison, err := CompareVersions("1.0.0+one", "1.0.0+two"); err != nil || comparison != 0 {
		t.Fatalf("build metadata changed precedence: %d, %v", comparison, err)
	}
	if _, err := CompareVersions("invalid", "1.0.0"); err == nil {
		t.Fatal("accepted invalid semantic version")
	}
}
