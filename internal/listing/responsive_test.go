package listing

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func filledPage() Page {
	return Page{
		Repository: "apt", Format: "deb", Endpoint: "https://packages.example/apt",
		Artifacts: []Artifact{{
			Name: "snail-demo", Version: "1.0.0", Architecture: "amd64",
			Path: "pool/main/s/snail-demo_1.0.0_amd64.deb", Size: 1200000,
			SHA256:    strings.Repeat("a", 64),
			Published: time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC),
		}},
	}
}

// On a narrow screen each row becomes a card, and a card without field names is a
// column of unexplained values. Every cell carries its own label, which is also
// what let the old approach — hiding columns by position — be removed.
func TestEveryCellIsLabelledForTheCardLayout(t *testing.T) {
	rendered := string(Render(filledPage()))
	body := rendered[strings.Index(rendered, "<tbody>"):strings.Index(rendered, "</tbody>")]
	cells := regexp.MustCompile(`<td\b[^>]*>`).FindAllString(body, -1)
	if len(cells) == 0 {
		t.Fatal("no cells rendered")
	}
	for _, cell := range cells {
		if !strings.Contains(cell, "data-label=") {
			t.Errorf("cell has no label for the card layout: %s", cell)
		}
	}
}

// Hiding columns on a narrow screen dropped the architecture and the digest, which
// are two of the things someone checking a package on a phone is there for.
func TestNoColumnIsHiddenByPosition(t *testing.T) {
	if strings.Contains(pageStyle, "nth-child") {
		t.Error("a column is still hidden by position on narrow screens")
	}
}

// A 64-character digest held on one line is wider than the page. With the other
// columns it came to 999px inside a 952px content box, so the table overflowed and
// the scroll container hid the overflow rather than fixing it.
func TestTheDigestDoesNotForceTheTableWide(t *testing.T) {
	if strings.Contains(pageStyle, "td.digest { white-space: nowrap; }") {
		t.Error("the digest is held on one line, which pushes the table past the page")
	}
	if !strings.Contains(pageStyle, "td.digest { max-width:") {
		t.Error("the digest column is unbounded")
	}
	if !strings.Contains(pageStyle, "word-break: break-all") {
		t.Error("the digest cannot wrap, so bounding its column would clip it")
	}
	// Still shown in full, which is the reason it is on the page at all.
	rendered := string(Render(filledPage()))
	if !strings.Contains(rendered, "<code>"+strings.Repeat("a", 64)+"</code>") {
		t.Error("the digest is no longer shown in full")
	}
}

// Sorting was a click handler on a th: reachable with a mouse, and invisible to a
// keyboard or a screen reader.
func TestSortingIsReachableWithoutAMouse(t *testing.T) {
	rendered := string(Render(filledPage()))
	if strings.Count(rendered, `class="sort"`) != 5 {
		t.Errorf("expected a sort button per sortable column, found %d", strings.Count(rendered, `class="sort"`))
	}
	if !strings.Contains(rendered, `<th scope="col"`) {
		t.Error("headers are not scoped, so a screen reader cannot associate them with cells")
	}
	if !strings.Contains(pageScript, "aria-sort") {
		t.Error("the sort direction is drawn but never announced")
	}
}

// The filter is markup the script reveals. Shipped visible, it would be a control
// that ignores a reader with no JavaScript.
func TestTheFilterIsHiddenUntilTheScriptEnablesIt(t *testing.T) {
	rendered := string(Render(filledPage()))
	if !strings.Contains(rendered, `<div class="filter" hidden>`) {
		t.Error("the filter is not hidden in the markup")
	}
	if !strings.Contains(pageScript, "panel.hidden = false") {
		t.Error("nothing reveals the filter")
	}
	// And the page is complete without it: the rows are in the HTML either way.
	if !strings.Contains(rendered, "snail-demo") {
		t.Error("the listing depends on the script to show its rows")
	}
}

// The site matrix is two-dimensional — a cell means something by its row and its
// column together — so the card layout must not reach it. It scrolls sideways
// instead, which is the honest affordance for a table that is genuinely wide.
func TestTheCardLayoutDoesNotReachTheMatrix(t *testing.T) {
	narrow := pageStyle[strings.Index(pageStyle, "max-width: 46rem"):]
	if strings.Contains(narrow, "\n  table,") || strings.Contains(narrow, "\n  tr {") {
		t.Error("the card layout applies to every table, including the site matrix")
	}
	if !strings.Contains(narrow, "#artifacts tr {") {
		t.Error("the card layout is not scoped to the artifact list")
	}
}

// A page read on a phone is read with a thumb.
func TestTouchTargetsAreSizedForFingers(t *testing.T) {
	if !strings.Contains(pageStyle, "pointer: coarse") {
		t.Error("no touch-sized targets are declared")
	}
	if !strings.Contains(pageStyle, "env(safe-area-inset-left)") {
		t.Error("a notched phone in landscape will put content under the bezel")
	}
}
