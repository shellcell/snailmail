package listing

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func manyArtifacts(count int) []Artifact {
	artifacts := make([]Artifact, 0, count)
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for index := range count {
		artifacts = append(artifacts, Artifact{
			Name:    fmt.Sprintf("package-%04d", index),
			Version: "1.0.0",
			Path:    fmt.Sprintf("pool/main/p/package-%04d_1.0.0_amd64.deb", index),
			SHA256:  "add4eb51b88b3d944acafb66aead0bc33537595397f15be287d25504ec1dbeb8",
			Size:    1234567,
			// Later index means more recently published.
			Published: base.Add(time.Duration(index) * time.Hour),
		})
	}
	return artifacts
}

// The reason the window exists. A rendered row costs about 610 bytes, so a real
// Debian suite produced a 38 MB page — regenerated and re-uploaded on every
// publication, and unusable in a browser when it got there.
func TestALargeRepositoryStillProducesAPageABrowserCanOpen(t *testing.T) {
	rendered := Render(Page{Repository: "apt", Format: "deb", Artifacts: manyArtifacts(63440)})
	if len(rendered) > 1<<20 {
		t.Errorf("page is %.1f MB, want something a browser can open", float64(len(rendered))/1e6)
	}
	// And it says so, rather than looking like a repository with 500 artifacts in it.
	if !strings.Contains(string(rendered), "63440") {
		t.Error("the page does not report the true total")
	}
	if !strings.Contains(string(rendered), "Showing the 500 most recently") {
		t.Error("the page does not say it is a window")
	}
}

// A visitor who cannot find a package needs to know the page is a summary before
// concluding the package is not published. That belongs above the fold, not only
// in the footer.
func TestTheWindowIsStatedWhereItIsRead(t *testing.T) {
	rendered := string(Render(Page{Repository: "apt", Format: "deb", Artifacts: manyArtifacts(600)}))
	notice := strings.Index(rendered, "windowed")
	footer := strings.Index(rendered, "<footer>")
	if notice < 0 || footer < 0 || notice > footer {
		t.Error("the window notice is not above the footer")
	}
}

// Selection is by publication time, so the page shows what is current rather than
// whatever sorts first alphabetically — which for a Debian suite would be a screen
// of packages beginning with a digit.
func TestTheWindowKeepsTheMostRecentlyPublished(t *testing.T) {
	rendered := string(Render(Page{
		Repository: "apt", Format: "deb", Window: 3, Artifacts: manyArtifacts(10),
	}))
	for _, recent := range []string{"package-0009", "package-0008", "package-0007"} {
		if !strings.Contains(rendered, recent) {
			t.Errorf("%s was published most recently but is not on the page", recent)
		}
	}
	if strings.Contains(rendered, "package-0000") {
		t.Error("the oldest artifact displaced a newer one")
	}
}

// A repository smaller than the window renders whole, with no notice — which is
// every repository today and must not gain a caption about being truncated.
func TestASmallRepositoryIsNotWindowed(t *testing.T) {
	rendered := string(Render(Page{Repository: "tools", Format: "raw", Artifacts: manyArtifacts(12)}))
	if strings.Contains(rendered, "Showing the") {
		t.Error("a page that fits was reported as a window")
	}
	for index := range 12 {
		if !strings.Contains(rendered, fmt.Sprintf("package-%04d", index)) {
			t.Errorf("package-%04d is missing from a page that should render whole", index)
		}
	}
}

// The footer counts the repository, not the page. A total that shrank to the window
// would misreport what is published.
func TestTheFooterCountsTheRepositoryNotThePage(t *testing.T) {
	rendered := string(Render(Page{Repository: "apt", Format: "deb", Window: 5, Artifacts: manyArtifacts(900)}))
	if !strings.Contains(rendered, "<footer>900 artifacts.") {
		t.Error("the footer does not report the repository's true size")
	}
}

// Artifacts locked before publication time was recorded have a zero time. They are
// the oldest thing in the repository and sort last, rather than sorting first and
// filling the window with the least current rows.
func TestArtifactsWithNoRecordedTimeDoNotFillTheWindow(t *testing.T) {
	artifacts := manyArtifacts(4)
	for index := range 6 {
		artifacts = append(artifacts, Artifact{
			Name: fmt.Sprintf("ancient-%d", index), Version: "0.1.0",
			Path: fmt.Sprintf("pool/main/a/ancient-%d_0.1.0_amd64.deb", index),
		})
	}
	rendered := string(Render(Page{Repository: "apt", Format: "deb", Window: 4, Artifacts: artifacts}))
	if strings.Contains(rendered, "ancient-") {
		t.Error("artifacts with no recorded publication time displaced ones that have it")
	}
}
