package formats

import (
	"strings"
	"testing"
)

const releaseDirectory = ".snailmail/releases/" +
	"1111111111111111111111111111111111111111111111111111111111111111/"

func pypiRewriter(t *testing.T) RootRewriter {
	t.Helper()
	rewriter, ok := RootRewriterFor("pypi")
	if !ok {
		t.Fatal("pypi has no root rewriter")
	}
	return rewriter
}

// The bytes this produces are already live. A repository published before the
// rewrite moved out of the S3 adapter has a root that a host recomputes and
// compares byte for byte, so a change here does not fail loudly — it reports a
// correctly published repository as corrupt.
func TestPyPIRootRewriteIsByteCompatible(t *testing.T) {
	const root = `<!DOCTYPE html><html><body><a href="demo/">demo</a></body></html>`
	rewritten, err := pypiRewriter(t).RewriteRoot([]byte(root), releaseDirectory, "snailmail plan=p change=c")
	if err != nil {
		t.Fatal(err)
	}
	want := `<!DOCTYPE html><html><body><a href="../` + releaseDirectory + `simple/demo/">demo</a></body></html>` +
		"\n<!-- snailmail plan=p change=c -->\n"
	if string(rewritten) != want {
		t.Errorf("rewrote to:\n%q\nwant:\n%q", rewritten, want)
	}
}

// A simple index links relative to the directory holding it, and it is itself in
// simple/. Reaching the release directory therefore means climbing out first —
// a rewrite that omitted the ../ would resolve to simple/.snailmail/... and every
// link would 404.
func TestPyPIRootRewriteClimbsOutOfSimple(t *testing.T) {
	rewritten, err := pypiRewriter(t).RewriteRoot(
		[]byte(`<a href="demo/">demo</a>`), releaseDirectory, "x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rewritten), `href="../.snailmail/`) {
		t.Errorf("links do not climb out of simple/: %s", rewritten)
	}
	if strings.Contains(string(rewritten), `href=".snailmail/`) {
		t.Errorf("a link resolves inside simple/: %s", rewritten)
	}
}

// The host recomputes the root it expects and compares it against what it
// published, so the same inputs have to give the same bytes every time.
func TestRootRewriteIsDeterministic(t *testing.T) {
	rewriter := pypiRewriter(t)
	const root = `<a href="a/">a</a><a href="b/">b</a><a href="c/">c</a>`
	first, err := rewriter.RewriteRoot([]byte(root), releaseDirectory, "snailmail tree=t")
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		again, err := rewriter.RewriteRoot([]byte(root), releaseDirectory, "snailmail tree=t")
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("the same root rewrote to different bytes")
		}
	}
}

// Every link has to move. One left behind would resolve against the canonical
// tree, which is the previous revision, so a client would install stale bytes
// from a repository that reported itself as published.
func TestPyPIRootRewriteMovesEveryLink(t *testing.T) {
	rewritten, err := pypiRewriter(t).RewriteRoot(
		[]byte(`<a href="a/">a</a><a href="b/">b</a>`), releaseDirectory, "x")
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(rewritten), `href="../`+releaseDirectory); count != 2 {
		t.Errorf("%d of 2 links were rebound: %s", count, rewritten)
	}
}

// A root naming nothing would publish a repository serving nothing, so it is
// refused rather than published empty.
func TestRootRewriteRefusesARootWithNoReferences(t *testing.T) {
	if _, err := pypiRewriter(t).RewriteRoot(
		[]byte(`<!DOCTYPE html><html><body>no projects</body></html>`), releaseDirectory, "x"); err == nil {
		t.Error("a root with no links was rewritten")
	}
}

// The capability is deliberately narrow. rpm and Helm publish every non-root
// file at a path whose bytes are fixed — repodata is content-addressed, a chart
// is stored under its digest — so a revision is written alongside the live one
// and committed by switching the root, with nothing rewritten.
//
// For rpm that is not merely simpler: repodata/repomd.xml.asc is a detached
// signature over repomd.xml, so rebinding that document would leave a repository
// whose signature does not verify.
func TestOnlyFormatsThatNeedRebindingDeclareIt(t *testing.T) {
	if _, ok := RootRewriterFor("pypi"); !ok {
		t.Error("pypi rewrites simple/<project>/index.html between revisions and must rebind")
	}
	for _, format := range []string{"rpm", "helm", "deb", "apk", "raw"} {
		if _, ok := RootRewriterFor(format); ok {
			t.Errorf("%q declares a rebind it does not need", format)
		}
	}
	if _, ok := RootRewriterFor("nonexistent"); ok {
		t.Error("an unknown format reported a rewriter")
	}
}
