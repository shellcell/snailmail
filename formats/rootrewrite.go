package formats

import (
	"errors"
	"strings"
)

// RootRewriter is implemented by a format that cannot be published to an object
// store by writing its tree and then switching its root.
//
// An object store has no ordered multi-object commit, so a revision goes live by
// putting one object. That is enough on its own when every other published path
// holds bytes determined by the path itself — content-addressed, or fixed for a
// given version — because then a new revision's files cannot disturb the live
// one and the root can simply be switched. rpm and Helm are both in that
// position: repodata is <sha256>-<kind>.xml.gz, a chart is stored under its own
// digest, and the builders refuse to let different bytes occupy one path.
//
// PyPI is not. simple/<project>/index.html sits at a fixed path and gains a line
// whenever a version is added, so writing the new revision would change what the
// live one serves. Such a format has to be staged in a directory of its own and
// its root rebound to point inside it, which is what this does.
//
// It is a narrow capability, not the general mechanism: rewriting a document a
// format signs would invalidate the signature, so a format that both signs its
// root and needs rebinding cannot be served this way at all.
//
// The result must be a pure function of its inputs. A host recomputes the root
// it expects and compares it byte for byte against the one published, so a
// rewrite that varied — by map order, by time — would report a correctly
// published revision as corrupt.
type RootRewriter interface {
	// RewriteRoot rebinds the root document's references to resolve under
	// releaseDirectory, which is given relative to the repository root and ends
	// in a separator.
	//
	// annotation is recorded in the document in a form the format's own clients
	// ignore, because the host reads its publication binding back out of the
	// bytes it published. What the annotation says is the host's business; how a
	// comment is spelled is the format's.
	RewriteRoot(content []byte, releaseDirectory, annotation string) ([]byte, error)
}

// RootRewriterFor returns the rewriter for a format, if it has one. A format
// without one publishes through more than one path and cannot be made live by a
// single write, which is a different limitation and reported separately.
func RootRewriterFor(format string) (RootRewriter, bool) {
	selected, err := For(format)
	if err != nil {
		return nil, false
	}
	rewriter, ok := selected.(RootRewriter)
	return rewriter, ok
}

// ErrNoRootReferences reports a root document with nothing to rebind. It is an
// error rather than a document left alone: a root that names nothing would
// publish a repository that serves nothing, and doing that silently is worse
// than refusing.
var ErrNoRootReferences = errors.New("root document has no references to rebind")

// RewriteRoot rebinds a simple index.
//
// The index lives at simple/index.html and its links are relative to the
// directory holding it, so reaching the release directory means climbing out of
// simple/ first and then descending into the copy of simple/ inside it.
func (pypiFormat) RewriteRoot(content []byte, releaseDirectory, annotation string) ([]byte, error) {
	text := string(content)
	if !strings.Contains(text, `<a href="`) {
		return nil, ErrNoRootReferences
	}
	prefix := `href="../` + releaseDirectory + `simple/`
	return []byte(strings.ReplaceAll(text, `href="`, prefix) +
		"\n<!-- " + annotation + " -->\n"), nil
}
