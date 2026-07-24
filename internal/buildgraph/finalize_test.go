package buildgraph

import (
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

func TestFinalizeIsDeterministicAndSortsFiles(t *testing.T) {
	input := domain.RepositoryArtifact{
		Format: "test/v1",
		Files: []domain.File{
			{Path: "z", Content: []byte("last")},
			{Path: "a", Content: []byte("first")},
		},
	}
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	first, firstManifest, err := Finalize(input, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	second, secondManifest, err := Finalize(input, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if firstManifest.TreeSHA256 != secondManifest.TreeSHA256 || string(first.Files[len(first.Files)-1].Content) != string(second.Files[len(second.Files)-1].Content) {
		t.Fatal("finalization was not deterministic")
	}
	if firstManifest.Files[0].Path != "a" || firstManifest.Files[1].Path != "z" {
		t.Fatalf("files were not sorted: %#v", firstManifest.Files)
	}
}

func TestFinalizeRejectsReservedAndDuplicatePaths(t *testing.T) {
	generatedAt := time.Unix(0, 0).UTC()
	for name, files := range map[string][]domain.File{
		"reserved":  {{Path: ManifestFilename, Content: []byte("x")}},
		"duplicate": {{Path: "same", Content: []byte("x")}, {Path: "same", Content: []byte("y")}},
		"escaping":  {{Path: "../outside", Content: []byte("x")}},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Finalize(domain.RepositoryArtifact{Format: "test/v1", Files: files}, generatedAt)
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("expected invalid path to fail")
			}
		})
	}
}
