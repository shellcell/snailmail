package listing

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// A digest is on the page so it can be compared against what was downloaded.
// A truncated one cannot be compared against anything, which would make the
// column decoration rather than evidence.
func TestDigestIsShownInFull(t *testing.T) {
	page := samplePage()
	page.Artifacts = []Artifact{{Name: "a", Version: "1", Path: "a.tar.gz", Size: 1, SHA256: strings.Repeat("a", 64)}}
	rendered := string(Render(page))
	if !strings.Contains(rendered, "<code>"+strings.Repeat("a", 64)+"</code>") {
		t.Fatal("the full digest is not shown")
	}
	if !strings.Contains(rendered, `data-copy="`+strings.Repeat("a", 64)+`">Copy</button>`) {
		t.Fatal("the digest has no labelled copy button")
	}
}

// The date an artifact was published is a different fact from the time the page
// was generated, and substituting one for the other would be a quiet lie.
func TestPublishedDateIsPerArtifact(t *testing.T) {
	page := samplePage()
	page.Artifacts = []Artifact{
		{Name: "dated", Version: "1", Path: "a.tar.gz", Size: 1, SHA256: strings.Repeat("a", 64),
			Published: time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)},
		{Name: "undated", Version: "1", Path: "b.tar.gz", Size: 1, SHA256: strings.Repeat("b", 64)},
	}
	rendered := string(Render(page))
	if !strings.Contains(rendered, `<time datetime="2026-03-04T05:00:00Z">2026-03-04</time>`) {
		t.Fatal("a recorded publication date is not shown")
	}
	if !strings.Contains(rendered, `<span class="unknown">unknown</span>`) {
		t.Fatal("an artifact locked before dates were recorded should say so, not borrow another date")
	}
	// It sorts by the instant, not by the text.
	stamp := strconv.FormatInt(time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC).Unix(), 10)
	if !strings.Contains(rendered, `data-value="`+stamp+`"`) {
		t.Fatal("the published column does not carry a sortable value")
	}
}

// A link is only worth offering where the repository knows its own URL; a
// copied relative path would send someone nowhere.
func TestCopyLinkNeedsAnEndpoint(t *testing.T) {
	page := samplePage()
	if !strings.Contains(string(Render(page)), `data-copy="https://dl.example/releases/a/1.0.0/a.tar.gz">Copy link</button>`) {
		t.Fatal("no absolute link is offered for a repository that knows its URL")
	}
	page.Endpoint = ""
	rendered := string(Render(page))
	if strings.Contains(rendered, "Copy link") {
		t.Fatal("a link was offered for a repository with no URL to build one from")
	}
	if strings.Contains(rendered, "<nav>") {
		t.Fatal("a repository with no URL cannot know it has a parent page")
	}
}

// Every repository page is one directory of a site, and a reader who lands on
// one should be able to get to the others.
func TestRepositoryPageLinksToTheSite(t *testing.T) {
	page := samplePage()
	if !strings.Contains(string(Render(page)), `<nav><a href="../">`) {
		t.Fatal("no link back to the site")
	}
	// Except where the repository is the site: there is nothing above it.
	page.Endpoint = "https://releases.example/"
	if strings.Contains(string(Render(page)), "<nav>") {
		t.Fatal("linked above the root of its own host")
	}
}

// The overview exists to show gaps as much as versions: a release that reached
// one repository and not another is the thing worth seeing.
func TestSiteMatrixShowsGaps(t *testing.T) {
	page := SitePage{
		Title: "shellcell",
		Repositories: []SiteRepository{
			{Name: "yum", Format: "rpm", Signed: true},
			{Name: "apt", Format: "deb", Signed: true},
			{Name: "releases", Format: "raw"},
		},
		Tools: []SiteTool{
			{Name: "snailmail", Latest: map[string]string{"apt": "0.0.3-1", "releases": "0.0.3"}},
		},
	}
	rendered := string(RenderSite(page))
	if strings.Count(rendered, `class="absent"`) != 1 {
		t.Fatal("the repository that does not carry the package is not shown as a gap")
	}
	if !strings.Contains(rendered, `<a href="apt/">0.0.3-1</a>`) {
		t.Fatal("the version published to apt is missing or does not link there")
	}
	if !strings.Contains(rendered, `<span class="badge unsigned">unsigned</span>`) {
		t.Fatal("an unsigned repository is not marked as one")
	}
	// Columns are ordered by name rather than by the order they arrived in, so
	// the same workspace always renders the same page.
	if strings.Index(rendered, `href="apt/"`) > strings.Index(rendered, `href="yum/"`) {
		t.Fatal("repositories are not in a stable order")
	}
	if string(RenderSite(page)) != rendered {
		t.Fatal("rendering the same overview twice produced different bytes")
	}
}

// A listing is published inside a content-addressed tree, so it must be a
// function of what was published and nothing else. A generation timestamp on
// the page would rewrite that tree on every build and deploy a change that
// contained no change — which this project has already had to fix once.
func TestListingCarriesNoBuildTimestamp(t *testing.T) {
	for _, rendered := range []string{string(Render(samplePage())), string(RenderSite(SitePage{Title: "x"}))} {
		for _, marker := range []string{"generated", "Generated"} {
			if strings.Contains(rendered, marker) {
				t.Fatalf("the page reports when it was built, which makes the tree change without a publication: %s", marker)
			}
		}
	}
}
