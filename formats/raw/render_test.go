package raw

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

func blobFor(name, version, filename, content string) domain.Blob {
	digest := sha256.Sum256([]byte(content))
	return domain.Blob{
		Filename: filename, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		Facts: domain.PackageFacts{Name: name, Version: version},
	}
}

func buildFor(t *testing.T, blobs ...domain.Blob) domain.RepositoryArtifact {
	t.Helper()
	artifact, err := Build(blobs, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func fileNamed(artifact domain.RepositoryArtifact, path string) (domain.File, bool) {
	for _, file := range artifact.Files {
		if file.Path == path {
			return file, true
		}
	}
	return domain.File{}, false
}

// Identity lives in the path, which is what lets a published tree be verified
// without the flags that were used at ingest.
func TestBuildPutsIdentityInThePath(t *testing.T) {
	artifact := buildFor(t,
		blobFor("ttysvg", "0.1.2", "build-final.tar.gz", "bytes"),
	)
	if _, found := fileNamed(artifact, "ttysvg/0.1.2/build-final.tar.gz"); !found {
		var paths []string
		for _, file := range artifact.Files {
			paths = append(paths, file.Path)
		}
		t.Fatalf("artifact is not at its identity path; got %v", paths)
	}
}

func TestBuildEmitsChecksumsForEveryArtifact(t *testing.T) {
	artifact := buildFor(t,
		blobFor("tool", "1.0.0", "tool_1.0.0_linux_amd64.tar.gz", "one"),
		blobFor("tool", "1.0.0", "tool_1.0.0_darwin_arm64.tar.gz", "two"),
	)
	checksums, found := fileNamed(artifact, "SHA256SUMS")
	if !found {
		t.Fatal("SHA256SUMS was not generated")
	}
	lines := strings.Split(strings.TrimSuffix(string(checksums.Content), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("SHA256SUMS has %d lines, want 2:\n%s", len(lines), checksums.Content)
	}
	for _, line := range lines {
		digest, path, ok := strings.Cut(line, "  ")
		if !ok || len(digest) != 64 || !strings.HasPrefix(path, "tool/1.0.0/") {
			t.Fatalf("unusable sha256sum line %q", line)
		}
	}
}

func TestBuildIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	first := blobFor("alpha", "1.0.0", "alpha_1.0.0_linux_amd64.tar.gz", "a")
	second := blobFor("beta", "2.0.0", "beta_2.0.0_linux_amd64.tar.gz", "b")
	forward := buildFor(t, first, second)
	backward := buildFor(t, second, first)
	if len(forward.Files) != len(backward.Files) {
		t.Fatalf("file counts differ: %d and %d", len(forward.Files), len(backward.Files))
	}
	for index := range forward.Files {
		if forward.Files[index].Path != backward.Files[index].Path ||
			string(forward.Files[index].Content) != string(backward.Files[index].Content) {
			t.Fatalf("build depends on input order at %q", forward.Files[index].Path)
		}
	}
}

// Two artifacts claiming one path with different bytes is the collision that
// would silently replace a published file.
func TestBuildRejectsDifferentBytesAtOnePath(t *testing.T) {
	_, err := Build([]domain.Blob{
		blobFor("tool", "1.0.0", "tool.tar.gz", "one"),
		blobFor("tool", "1.0.0", "tool.tar.gz", "two"),
	}, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err == nil {
		t.Fatal("a colliding path was accepted")
	}
}

func TestBuildDeduplicatesIdenticalArtifacts(t *testing.T) {
	blob := blobFor("tool", "1.0.0", "tool.tar.gz", "one")
	artifact := buildFor(t, blob, blob)
	count := 0
	for _, file := range artifact.Files {
		if strings.HasPrefix(file.Path, "tool/") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("identical artifacts produced %d files, want 1", count)
	}
}

func TestBuildRendersAnEmptyRepository(t *testing.T) {
	artifact := buildFor(t)
	checksums, found := fileNamed(artifact, "SHA256SUMS")
	if !found {
		t.Fatal("an empty repository has no SHA256SUMS")
	}
	if len(checksums.Content) != 0 {
		t.Fatalf("empty repository checksums are not empty: %q", checksums.Content)
	}
	// The browsable page is rendered once for every format by the adapter, not
	// here; what raw owns is the checksum file a client verifies against.
}

// A name or version that escaped into a path would let an artifact be written
// outside the tree.
func TestBuildRejectsUnusableIdentity(t *testing.T) {
	for name, blob := range map[string]domain.Blob{
		"traversing name":    blobFor("../escape", "1.0.0", "tool.tar.gz", "x"),
		"traversing version": blobFor("tool", "../1.0.0", "tool.tar.gz", "x"),
		"empty name":         blobFor("", "1.0.0", "tool.tar.gz", "x"),
		"reserved filename":  blobFor("tool", "1.0.0", "SHA256SUMS", "x"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Build([]domain.Blob{blob}, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()}); err == nil {
				t.Fatal("unusable identity was accepted")
			}
		})
	}
}
