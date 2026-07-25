package helm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestBuildRendersDeterministicIndex(t *testing.T) {
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	newer := chartBlob(t, "snail-demo", "2.0.0")
	older := chartBlob(t, "snail-demo", "1.2.3")
	artifact, err := Build([]domain.Blob{older, newer}, BuildOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	index := generatedContent(artifact, "index.yaml")
	for _, expected := range []string{
		"apiVersion: v1\n",
		`  "snail-demo":`,
		`    created: "2026-07-23T01:02:03Z"`,
		`    digest: "` + newer.SHA256 + `"`,
		`    - "charts/` + newer.SHA256 + `/snail-demo-2.0.0.tgz"`,
		`generated: "2026-07-23T01:02:03Z"`,
	} {
		if !strings.Contains(index, expected) {
			t.Fatalf("index is missing %q:\n%s", expected, index)
		}
	}
	if strings.Index(index, `version: "2.0.0"`) > strings.Index(index, `version: "1.2.3"`) {
		t.Fatal("chart versions are not sorted newest first")
	}
	second, err := Build([]domain.Blob{newer, older}, BuildOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(findContent(artifact, "index.yaml"), findContent(second, "index.yaml")) {
		t.Fatal("index output depends on input order")
	}
}

func TestBuildRejectsDifferentBytesForSameChartVersion(t *testing.T) {
	first := chartBlob(t, "snail-demo", "1.2.3")
	second := first
	second.SHA256 = strings.Repeat("b", sha256.Size*2)
	_, err := Build([]domain.Blob{first, second}, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err == nil {
		t.Fatal("expected duplicate chart version with different bytes to fail")
	}
}

func TestBuildRendersEmptyRepository(t *testing.T) {
	artifact, err := Build(nil, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if index := generatedContent(artifact, "index.yaml"); !strings.Contains(index, "entries:\n") || len(artifact.VerificationCases) != 0 {
		t.Fatalf("empty Helm artifact %#v", artifact)
	}
}

func TestBuildDeduplicatesIdenticalChartInputs(t *testing.T) {
	chart := chartBlob(t, "snail-demo", "1.2.3")
	artifact, err := Build([]domain.Blob{chart, chart}, BuildOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.VerificationCases) != 1 || strings.Count(generatedContent(artifact, "index.yaml"), `version: "1.2.3"`) != 1 {
		t.Fatal("identical chart input was not deduplicated")
	}
}

func chartBlob(t *testing.T, name, version string) domain.Blob {
	t.Helper()
	content, filename, err := testutil.HelmChart(name, version)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := Inspect(filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return domain.Blob{Filename: filename, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Facts: facts}
}

func generatedContent(artifact domain.RepositoryArtifact, name string) string {
	return string(findContent(artifact, name))
}

func findContent(artifact domain.RepositoryArtifact, name string) []byte {
	for _, file := range artifact.Files {
		if file.Path == name {
			return file.Content
		}
	}
	return nil
}
