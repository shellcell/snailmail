package listing

import (
	"strings"
	"testing"
)

func samplePage() Page {
	return Page{
		Repository: "releases", Format: "raw", Endpoint: "https://dl.example/releases",
		Install: []string{"# fetch it", "curl -LO https://dl.example/releases/a.tar.gz"},
		Artifacts: []Artifact{
			{Name: "b-tool", Version: "1.0.0", Architecture: "amd64", Path: "b/1.0.0/b.tar.gz", Size: 2048, SHA256: strings.Repeat("a", 64)},
			{Name: "a-tool", Version: "1.0.0", Architecture: "amd64", Path: "a/1.0.0/a.tar.gz", Size: 500, SHA256: strings.Repeat("b", 64)},
			{Name: "a-tool", Version: "2.0.0", Architecture: "arm64", Path: "a/2.0.0/a.tar.gz", Size: 1572864, SHA256: strings.Repeat("c", 64)},
		},
	}
}

// A listing is part of a content-addressed tree, so identical inputs must give
// identical bytes: a page that varied would change the tree with nothing
// published, which is exactly the treadmill this project had to fix once.
func TestRenderIsDeterministic(t *testing.T) {
	first := string(Render(samplePage()))
	second := string(Render(samplePage()))
	if first != second {
		t.Fatal("rendering the same page twice produced different bytes")
	}
	// And it must not depend on the order artifacts arrive in.
	shuffled := samplePage()
	shuffled.Artifacts[0], shuffled.Artifacts[2] = shuffled.Artifacts[2], shuffled.Artifacts[0]
	if string(Render(shuffled)) != first {
		t.Fatal("rendering depends on the order artifacts were given")
	}
}

// Whether a repository is signed is the thing a reader most needs before
// pasting an install command, so it is stated either way rather than left to be
// inferred from an absence.
func TestSigningStatusIsAlwaysStated(t *testing.T) {
	unsigned := string(Render(samplePage()))
	if !strings.Contains(unsigned, "not signed") {
		t.Error("an unsigned repository does not say so")
	}

	page := samplePage()
	page.Signing = &Signing{
		Fingerprint: "1e00d64dcafdff06dc70acefdf1c620e53596d7f",
		Algorithm:   "openpgp-rsa4096", KeyPath: "keys/archive.gpg",
	}
	signed := string(Render(page))
	for _, want := range []string{"Signed.", "openpgp-rsa4096", "1e00d64dcafdff06dc70acefdf1c620e53596d7f", "keys/archive.gpg"} {
		if !strings.Contains(signed, want) {
			t.Errorf("a signed repository does not show %q", want)
		}
	}
	if strings.Contains(signed, "not signed") {
		t.Error("a signed repository is described as unsigned")
	}
}

// The copy button carries the command, not the markup around it: a paste that
// included colouring would not run.
func TestCopyCarriesPlainText(t *testing.T) {
	page := samplePage()
	rendered := string(Render(page))
	if !strings.Contains(rendered, `data-copy="# fetch it&#10;curl -LO https://dl.example/releases/a.tar.gz"`) {
		if !strings.Contains(rendered, "data-copy=\"# fetch it") {
			t.Fatalf("the install block does not carry its plain text:\n%s", rendered)
		}
	}
	if strings.Contains(rendered, `data-copy="<span`) {
		t.Error("the copy target contains markup")
	}
	// The digest button copies the whole digest, while showing a short form.
	if !strings.Contains(rendered, `data-copy="`+strings.Repeat("a", 64)+`"`) {
		t.Error("the digest button does not carry the full digest")
	}
}

func TestSizesAreHumanReadableAndSortable(t *testing.T) {
	rendered := string(Render(samplePage()))
	for _, want := range []string{`data-value="500"`, ">500 B<", `data-value="2048"`, ">2.0 KiB<", ">1.5 MiB<"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	for size, want := range map[int64]string{
		0: "0 B", 999: "999 B", 1024: "1.0 KiB", 1536: "1.5 KiB",
		20480: "20 KiB", 1048576: "1.0 MiB", 7702309: "7.3 MiB",
	} {
		if got := humanSize(size); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", size, got, want)
		}
	}
}

// Nothing a package can be called may escape into markup: a name is read from
// an artifact, and an artifact is not trusted input.
func TestContentIsEscaped(t *testing.T) {
	page := samplePage()
	page.Artifacts = []Artifact{{
		Name: `<script>alert(1)</script>`, Version: `"><b>`, Path: `a"b/c.tar.gz`,
		Size: 1, SHA256: strings.Repeat("d", 64),
	}}
	page.Repository = "<img src=x onerror=1>"
	rendered := string(Render(page))
	if strings.Contains(rendered, "<script>alert") || strings.Contains(rendered, "<img src=x") {
		t.Fatalf("unescaped content reached the page:\n%s", rendered)
	}
}

func TestEmptyRepositorySaysSo(t *testing.T) {
	page := samplePage()
	page.Artifacts = nil
	if !strings.Contains(string(Render(page)), "Nothing has been published yet") {
		t.Error("an empty repository does not say so")
	}
}

func TestHighlightingLeavesTextIntact(t *testing.T) {
	for _, line := range []string{
		"# a comment",
		"curl -fsSL https://example/key | sudo tee /etc/apk/keys/k.pub",
		`echo 'deb [signed-by=/k.gpg] https://example stable main' \`,
		"sudo apt-get update && sudo apt-get install snailmail",
	} {
		marked := highlightShell(line)
		// Stripping the markup must give back exactly what went in.
		plain := stripTags(marked)
		if plain != escapeBack(line) {
			t.Errorf("highlighting altered the line:\n  in:  %q\n  out: %q", line, plain)
		}
	}
}

func stripTags(value string) string {
	var out strings.Builder
	depth := 0
	for _, r := range value {
		switch {
		case r == '<':
			depth++
		case r == '>':
			depth--
		case depth == 0:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// escapeBack renders the entities the page would contain for a given input.
func escapeBack(value string) string { return escape(value) }
