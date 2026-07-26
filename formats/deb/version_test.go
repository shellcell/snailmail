package deb

import "testing"

func TestCompareVersionsUsesDebianPrecedence(t *testing.T) {
	for _, test := range []struct{ newer, older string }{
		{"1.10-1", "1.9-1"},
		{"2:1.0-1", "1:99.0-1"},
		{"+2:1.0-1", "1:99.0-1"},
		{"1:1.0:git-2", "1:1.0:git-1"},
		{"1.0-1", "1.0~rc1-1"},
		{"1.0-2", "1.0-1"},
		{"1.0+git1-1", "1.0-1"},
	} {
		comparison, err := CompareVersions(test.newer, test.older)
		if err != nil || comparison <= 0 {
			t.Fatalf("CompareVersions(%q, %q)=%d, %v", test.newer, test.older, comparison, err)
		}
	}
	for _, equivalent := range [][2]string{{"1.0", "1.0-0"}, {"1.01-1", "1.1-1"}} {
		comparison, err := CompareVersions(equivalent[0], equivalent[1])
		if err != nil || comparison != 0 {
			t.Fatalf("CompareVersions(%q, %q)=%d, %v", equivalent[0], equivalent[1], comparison, err)
		}
	}
	if _, err := CompareVersions("invalid", "1.0"); err == nil {
		t.Fatal("accepted invalid Debian version")
	}
	if _, err := CompareVersions("1:1.0-1:bad", "1:1.0-1"); err == nil {
		t.Fatal("accepted colon in Debian revision")
	}
}
