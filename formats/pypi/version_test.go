package pypi

import "testing"

func TestCompareVersionsUsesPEP440Precedence(t *testing.T) {
	for _, test := range []struct{ newer, older string }{
		{"1.10", "1.9"},
		{"1!1.0", "2.0"},
		{"1.0", "1.0rc1"},
		{"1.0rc1", "1.0b1"},
		{"1.0.post1", "1.0"},
		{"1.0.dev1", "1.0.dev0"},
		{"1.0+2", "1.0+alpha"},
	} {
		comparison, err := CompareVersions(test.newer, test.older)
		if err != nil || comparison <= 0 {
			t.Fatalf("CompareVersions(%q, %q)=%d, %v", test.newer, test.older, comparison, err)
		}
	}
	for _, equivalent := range [][2]string{{"1.0", "1.0.0"}, {"1.0RC1", "1.0rc1"}, {"1.0-1", "1.0.post1"}} {
		comparison, err := CompareVersions(equivalent[0], equivalent[1])
		if err != nil || comparison != 0 {
			t.Fatalf("CompareVersions(%q, %q)=%d, %v", equivalent[0], equivalent[1], comparison, err)
		}
	}
	if comparison, err := CompareVersions("1.0.dev1", "1.0a1"); err != nil || comparison >= 0 {
		t.Fatalf("development release ordering=%d, %v", comparison, err)
	}
	if _, err := CompareVersions("not-a-version", "1.0"); err == nil {
		t.Fatal("accepted invalid PEP 440 version")
	}
}
