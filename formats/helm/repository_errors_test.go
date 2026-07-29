package helm

import (
	"strings"
	"testing"
)

// A rejected index is something an operator has to fix, and "invalid Helm
// repository chart entry" — which is what all of these used to say — tells them
// nothing about which of eleven checks fired. Each cause must name itself.
func TestChartEntryErrorsNameTheirCause(t *testing.T) {
	sound := indexChartVersion{
		Name: "demo", Version: "1.2.3",
		Digest: strings.Repeat("a", 64), URLs: []string{"https://example.test/demo-1.2.3.tgz"},
	}
	if err := validateChartEntry("demo", sound); err != nil {
		t.Fatalf("a sound entry was rejected: %v", err)
	}

	for name, broken := range map[string]struct {
		key   string
		entry indexChartVersion
		want  string
	}{
		"no name":           {"", sound, "no name"},
		"name too long":     {strings.Repeat("a", 256), sound, "over the 255 limit"},
		"name not a chart":  {"Demo Chart", sound, "not a valid chart name"},
		"indexed elsewhere": {"other", sound, "indexed under"},
		"version not semver": {"demo", indexChartVersion{
			Name: "demo", Version: "not-a-version", Digest: sound.Digest, URLs: sound.URLs}, "not semver"},
		"digest not sha256": {"demo", indexChartVersion{
			Name: "demo", Version: "1.2.3", Digest: "abcd", URLs: sound.URLs}, "not a SHA-256"},
		"digest uppercase": {"demo", indexChartVersion{
			Name: "demo", Version: "1.2.3", Digest: strings.Repeat("A", 64), URLs: sound.URLs}, "uppercase digest"},
		"no url": {"demo", indexChartVersion{
			Name: "demo", Version: "1.2.3", Digest: sound.Digest}, "no download URL"},
		"too many urls": {"demo", indexChartVersion{
			Name: "demo", Version: "1.2.3", Digest: sound.Digest,
			URLs: []string{"https://a.test/x.tgz", "https://b.test/x.tgz", "https://c.test/x.tgz", "https://d.test/x.tgz"}}, "over the limit of 3"},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateChartEntry(broken.key, broken.entry)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if !strings.Contains(err.Error(), broken.want) {
				t.Errorf("error %q does not say %q", err, broken.want)
			}
		})
	}
}

// The URL rules are the ones that stop an index pointing somewhere other than
// where it appears to, so each refusal has to be legible on its own.
func TestChartURLErrorsNameTheirCause(t *testing.T) {
	if err := validateChartURL("https://example.test/charts/demo-1.2.3.tgz"); err != nil {
		t.Fatalf("a sound URL was rejected: %v", err)
	}
	if err := validateChartURL("charts/demo-1.2.3.tgz"); err != nil {
		t.Fatalf("a relative URL was rejected: %v", err)
	}
	for rawURL, want := range map[string]string{
		"": "empty",
		"https://" + strings.Repeat("a", 4096) + "/x.tgz": "over the 4096 limit",
		"https://user:pw@example.test/x.tgz":              "carries credentials",
		"https://example.test/x.tgz?a=b":                  "query or fragment",
		"https://example.test/x.tgz#frag":                 "query or fragment",
		"https://example.test/a\\b.tgz":                   "backslash",
		"https://example.test/a%2fb.tgz":                  "percent-encodes",
		"https://example.test/a%2e%2e/b.tgz":              "percent-encodes",
		"http://example.test/x.tgz":                       "not https",
		"https:///x.tgz":                                  "no host",
		"https://example.test/../x.tgz":                   "traverses",
	} {
		err := validateChartURL(rawURL)
		if err == nil {
			t.Errorf("accepted %q", rawURL)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error for %q is %q, which does not say %q", rawURL, err, want)
		}
	}
}
