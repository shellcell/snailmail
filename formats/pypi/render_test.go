package pypi

import (
	"reflect"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/domain"
)

func TestBuildProducesDeterministicPEP503Pages(t *testing.T) {
	digest := strings.Repeat("a", 64)
	blobs := []domain.Blob{{
		Filename: "demo_pkg-1.2.3-py3-none-any.whl",
		Size:     42,
		SHA256:   digest,
		Facts: domain.PackageFacts{
			Name:           "Demo.Pkg",
			Version:        "1.2.3",
			RequiresPython: ">=3.8",
		},
	}}
	artifact, err := Build(blobs)
	if err != nil {
		t.Fatal(err)
	}

	wantRoot := `<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>Simple index</title>
  </head>
  <body>
    <a href="demo-pkg/">demo-pkg</a><br>
  </body>
</html>
`
	wantProject := `<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>demo-pkg</title>
  </head>
  <body>
    <a href="../../packages/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/demo_pkg-1.2.3-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" data-requires-python="&gt;=3.8">demo_pkg-1.2.3-py3-none-any.whl</a><br>
  </body>
</html>
`
	if got := generatedContent(artifact, "simple/index.html"); got != wantRoot {
		t.Fatalf("root page mismatch:\n%s", got)
	}
	if got := generatedContent(artifact, "simple/demo-pkg/index.html"); got != wantProject {
		t.Fatalf("project page mismatch:\n%s", got)
	}

	reversed, err := Build([]domain.Blob{blobs[0], blobs[0]})
	if err != nil {
		t.Fatal(err)
	}
	singleAgain, err := Build(blobs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reversed, singleAgain) {
		t.Fatal("duplicate identical inputs changed deterministic output")
	}
}

func TestBuildRejectsInvalidDigest(t *testing.T) {
	_, err := Build([]domain.Blob{{
		Filename: "pkg.whl",
		SHA256:   "not-a-digest",
		Facts:    domain.PackageFacts{Name: "pkg", Version: "1"},
	}})
	if err == nil {
		t.Fatal("expected invalid digest to fail")
	}
}

func TestBuildRendersEmptyRepository(t *testing.T) {
	artifact, err := Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if generatedContent(artifact, "simple/index.html") == "" || len(artifact.VerificationCases) != 0 {
		t.Fatalf("empty PyPI artifact %#v", artifact)
	}
}

func generatedContent(artifact domain.RepositoryArtifact, name string) string {
	for _, file := range artifact.Files {
		if file.Path == name {
			return string(file.Content)
		}
	}
	return ""
}
