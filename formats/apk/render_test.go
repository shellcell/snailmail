package apk

import (
	"archive/tar"
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

func buildIndex(t *testing.T, blobs ...domain.Blob) domain.RepositoryArtifact {
	t.Helper()
	artifact, err := Build(blobs, BuildOptions{
		GeneratedAt: time.Unix(1700000000, 0).UTC(), Architectures: []string{"x86_64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

// readIndex unwraps APKINDEX.tar.gz the way apk does.
func readIndex(t *testing.T, artifact domain.RepositoryArtifact) string {
	t.Helper()
	for _, file := range artifact.Files {
		if !strings.HasSuffix(file.Path, IndexFilename) {
			continue
		}
		reader, err := gzip.NewReader(bytes.NewReader(file.Content))
		if err != nil {
			t.Fatal(err)
		}
		archive := tar.NewReader(reader)
		for {
			header, err := archive.Next()
			if err != nil {
				t.Fatalf("APKINDEX is not in the archive: %v", err)
			}
			if header.Name != "APKINDEX" {
				continue
			}
			body, err := io.ReadAll(archive)
			if err != nil {
				t.Fatal(err)
			}
			return string(body)
		}
	}
	t.Fatal("no index was generated")
	return ""
}

// The expected block is exactly what `apk index` wrote for this package, field
// for field. Matching a reimplementation would prove nothing; matching apk's
// own output is what says a client will read this.
func TestIndexMatchesWhatApkGenerates(t *testing.T) {
	index := readIndex(t, buildIndex(t, realBlob(t)))
	for _, want := range []string{
		"C:Q1EdGFduziftFxVmEaf+YyUEOyr4o=",
		"P:snail-demo",
		"V:1.2.3-r4",
		"A:noarch",
		"S:1411",
		"I:6",
		"T:Deterministic test package",
		"U:https://example.invalid/snail-demo",
		"L:MIT",
		"o:snail-demo",
		"t:1785301961",
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index is missing %q\n--- got ---\n%s", want, index)
		}
	}
}

// A package with no C: is one apk refuses, so an index must never be built
// without it rather than emitting a blank field a client will reject.
func TestBuildRefusesAPackageWithNoControlChecksum(t *testing.T) {
	blob := realBlob(t)
	delete(blob.Facts.Fields, "checksum")
	if _, err := Build([]domain.Blob{blob}, BuildOptions{GeneratedAt: time.Unix(1, 0).UTC(), Architectures: []string{"x86_64"}}); err == nil {
		t.Fatal("a package with no control checksum was accepted")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	blob := realBlob(t)
	first := buildIndex(t, blob)
	second := buildIndex(t, blob)
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
	other.SHA256 = strings.Repeat("b", 64)
	if _, err := Build([]domain.Blob{blob, other}, BuildOptions{GeneratedAt: time.Unix(1, 0).UTC(), Architectures: []string{"x86_64"}}); err == nil {
		t.Fatal("a colliding path was accepted")
	}
}

// A newline in a description would otherwise start a field of its own.
func TestIndexFieldsCannotBeForged(t *testing.T) {
	blob := realBlob(t)
	blob.Facts.Fields["description"] = "harmless\nP:impostor"
	index := readIndex(t, buildIndex(t, blob))
	if strings.Contains(index, "\nP:impostor") {
		t.Fatalf("a newline in a value forged a field:\n%s", index)
	}
}

func TestBuildRendersAnEmptyRepository(t *testing.T) {
	if index := readIndex(t, buildIndex(t)); index != "" {
		t.Fatalf("an empty repository has a non-empty index: %q", index)
	}
}
