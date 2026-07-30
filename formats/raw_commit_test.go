package formats

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

// A real digest, because the builder validates them — which is right of it, and
// means a fixture has to describe bytes that could exist.
func rawBlob(name, version, filename, content string) domain.Blob {
	digest := sha256.Sum256([]byte(content))
	return domain.Blob{
		Filename: filename, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		Facts: domain.PackageFacts{Name: name, Version: version},
	}
}

// What qualifies a format for an object store is that one path makes a revision
// live and every other path the host writes canonically holds bytes fixed by that
// path. Established by building twice rather than by reading the builder: the
// second build adds a version, and anything rewritten underneath a path it already
// occupied cannot be written alongside a live revision.
//
// snailmail's own generated files are excluded, because they are rewritten for
// every format — index.html is the browsable listing that AppendListing adds to all
// six — and a host publishing without a staging directory keeps them out of the
// canonical namespace for exactly that reason.
func TestRawPublishesOneMutablePathBesidesItsOwn(t *testing.T) {
	format, err := For("raw")
	if err != nil {
		t.Fatal(err)
	}
	options := BuildOptions{Repository: Repository{Name: "tools"}, GeneratedAt: time.Unix(1_700_000_000, 0).UTC()}
	first, err := format.Build([]domain.Blob{
		rawBlob("tool", "1.0.0", "tool_1.0.0_linux_amd64.tar.gz", "first payload"),
	}, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := format.Build([]domain.Blob{
		rawBlob("tool", "1.0.0", "tool_1.0.0_linux_amd64.tar.gz", "first payload"),
		rawBlob("tool", "2.0.0", "tool_2.0.0_linux_amd64.tar.gz", "second payload"),
	}, options)
	if err != nil {
		t.Fatal(err)
	}

	before := make(map[string]string)
	for _, file := range first.Files {
		before[file.Path] = string(file.Content) + file.SHA256
	}
	var mutable []string
	for _, file := range second.Files {
		if file.Path == "index.html" {
			continue
		}
		previous, existed := before[file.Path]
		if existed && previous != string(file.Content)+file.SHA256 {
			mutable = append(mutable, file.Path)
		}
	}
	if len(mutable) != 1 || mutable[0] != "SHA256SUMS" {
		t.Errorf("paths rewritten between revisions: %v, want only SHA256SUMS", mutable)
	}
	// And that path is exactly what the format declares as its commit path, so the
	// declaration matches the measurement rather than restating an assumption.
	paths := format.CommitPaths(Repository{Name: "tools"})
	if len(paths) != 1 || paths[0] != "SHA256SUMS" {
		t.Errorf("commit paths %v, want the one mutable path", paths)
	}
}

// index.html is snailmail's own browsable listing, appended to every format's tree.
// Raw counted it as a commit path, which made raw look like a multi-path format and
// kept it off object storage. No other format counts it, and nothing resolves
// through it.
func TestNoFormatCountsTheBrowsableListingAsACommitPath(t *testing.T) {
	for _, format := range []string{"pypi", "deb", "rpm", "apk", "helm", "raw"} {
		selected, err := For(format)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range selected.CommitPaths(Repository{Suite: "stable", Architectures: []string{"amd64"}}) {
			if path == "index.html" {
				t.Errorf("%s counts snailmail's own listing as a commit path", format)
			}
		}
	}
}
