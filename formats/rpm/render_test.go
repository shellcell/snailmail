package rpm

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

func realBlob(t *testing.T) domain.Blob {
	t.Helper()
	content := loadRealPackage(t)
	facts, err := Inspect(realPackage, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return domain.Blob{
		Filename: realPackage, Size: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]), Facts: facts,
	}
}

func buildRepository(t *testing.T, blobs ...domain.Blob) domain.RepositoryArtifact {
	t.Helper()
	artifact, err := Build(blobs, BuildOptions{GeneratedAt: time.Unix(1700000000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func fileNamed(artifact domain.RepositoryArtifact, suffix string) (domain.File, bool) {
	for _, file := range artifact.Files {
		if strings.HasSuffix(file.Path, suffix) {
			return file, true
		}
	}
	return domain.File{}, false
}

func gunzip(t *testing.T, content []byte) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(expanded)
}

// repomd.xml is the only document a client reads by name; everything else is
// reached through it, so each index it declares must exist and hash to what it
// says. A mismatch here is what dnf reports as a corrupt repository.
func TestRepomdDeclaresIndexesThatExistAndMatch(t *testing.T) {
	artifact := buildRepository(t, realBlob(t))
	repomd, found := fileNamed(artifact, "repodata/repomd.xml")
	if !found {
		t.Fatal("repomd.xml was not generated")
	}
	document := string(repomd.Content)
	for _, kind := range []string{"primary", "filelists", "other"} {
		if !strings.Contains(document, `<data type="`+kind+`">`) {
			t.Errorf("repomd.xml does not declare %s", kind)
		}
	}
	declared := 0
	for _, file := range artifact.Files {
		if !strings.HasPrefix(file.Path, "repodata/") || strings.HasSuffix(file.Path, "repomd.xml") {
			continue
		}
		declared++
		if !strings.Contains(document, file.Path) {
			t.Errorf("%s exists but repomd.xml does not declare it", file.Path)
		}
		digest := sha256.Sum256(file.Content)
		if !strings.Contains(document, hex.EncodeToString(digest[:])) {
			t.Errorf("repomd.xml does not carry the checksum of %s", file.Path)
		}
	}
	if declared != 3 {
		t.Fatalf("%d indexes were generated, want 3", declared)
	}
}

func TestPrimaryDescribesThePackage(t *testing.T) {
	blob := realBlob(t)
	artifact := buildRepository(t, blob)
	primary, found := fileNamed(artifact, "-primary.xml.gz")
	if !found {
		t.Fatal("primary index was not generated")
	}
	document := gunzip(t, primary.Content)
	for _, want := range []string{
		"<name>snail-demo</name>",
		"<arch>noarch</arch>",
		`<version epoch="0" ver="1.2.3" rel="4"/>`,
		`<location href="Packages/` + realPackage + `"/>`,
		blob.SHA256,
		"<rpm:license>MIT</rpm:license>",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("primary index is missing %q", want)
		}
	}
	// rpmlib() entries constrain rpm itself rather than naming a package, and a
	// repository offering them as requirements is one dnf refuses to resolve.
	if strings.Contains(document, "rpmlib(") {
		t.Error("primary index carries rpmlib() requirements")
	}
	if !strings.Contains(document, `name="bash"`) {
		t.Error("primary index dropped the real requirement")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	blob := realBlob(t)
	first := buildRepository(t, blob)
	second := buildRepository(t, blob)
	if len(first.Files) != len(second.Files) {
		t.Fatalf("file counts differ: %d and %d", len(first.Files), len(second.Files))
	}
	for index := range first.Files {
		if first.Files[index].Path != second.Files[index].Path ||
			!bytes.Equal(first.Files[index].Content, second.Files[index].Content) {
			t.Fatalf("%s differs between builds", first.Files[index].Path)
		}
	}
}

func TestBuildRejectsDifferentBytesAtOnePath(t *testing.T) {
	blob := realBlob(t)
	other := blob
	other.SHA256 = strings.Repeat("a", 64)
	if _, err := Build([]domain.Blob{blob, other}, BuildOptions{GeneratedAt: time.Unix(1, 0).UTC()}); err == nil {
		t.Fatal("a colliding path was accepted")
	}
}

func TestBuildRendersAnEmptyRepository(t *testing.T) {
	artifact := buildRepository(t)
	if _, found := fileNamed(artifact, "repodata/repomd.xml"); !found {
		t.Fatal("an empty repository has no repomd.xml")
	}
	primary, found := fileNamed(artifact, "-primary.xml.gz")
	if !found {
		t.Fatal("an empty repository has no primary index")
	}
	if !strings.Contains(gunzip(t, primary.Content), `packages="0"`) {
		t.Error("an empty primary index does not say it is empty")
	}
}
