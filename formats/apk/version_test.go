package apk

import (
	"os"
	"strings"
	"testing"
)

// testdata/version.txt is what real apk answers, generated with
// `apk version -t <left> <right>` in an Alpine container. Comparing against a
// reimplementation would only prove the two agree; comparing against apk proves
// this orders packages the way the client installing them does.
func TestCompareVersionsAgreesWithApk(t *testing.T) {
	content, err := os.ReadFile("testdata/version.txt")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("unusable golden line %q", line)
		}
		want := map[string]int{"<": -1, "=": 0, ">": 1}[fields[2]]
		got, err := CompareVersions(fields[0], fields[1])
		if err != nil {
			t.Errorf("CompareVersions(%q, %q): %v", fields[0], fields[1], err)
			continue
		}
		if got != want {
			t.Errorf("CompareVersions(%q, %q) = %d, apk says %s", fields[0], fields[1], got, fields[2])
		}
		checked++
	}
	if checked < 15 {
		t.Fatalf("only %d comparisons were checked", checked)
	}
	t.Logf("agreed with apk on %d comparisons", checked)
}

func TestParseVersionRejectsMalformedVersions(t *testing.T) {
	for _, value := range []string{"", "-r1", "abc", "1.0_nonsense1", "1.0-r", "1.0-rx", "1..0"} {
		if _, err := parseVersion(value); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}
