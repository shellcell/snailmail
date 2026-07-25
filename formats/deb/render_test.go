package deb

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestBuildRendersPackagesAndRelease(t *testing.T) {
	blob := testBlob(t, "snail-demo", "1.2.3-1", "all")
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	artifact, err := Build([]domain.Blob{blob}, BuildOptions{
		Suite:         "stable",
		Component:     "main",
		Architectures: []string{"arm64", "amd64"},
		GeneratedAt:   generatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	packages := generatedContent(artifact, "dists/stable/main/binary-amd64/Packages")
	for _, expected := range []string{
		"Package: snail-demo\n",
		"Version: 1.2.3-1\n",
		"Architecture: all\n",
		"Filename: pool/main/s/snail-demo/snail-demo_1.2.3-1_all.deb\n",
		"SHA256: " + blob.SHA256 + "\n",
	} {
		if !strings.Contains(packages, expected) {
			t.Fatalf("Packages is missing %q:\n%s", expected, packages)
		}
	}
	if generatedContent(artifact, "dists/stable/main/binary-arm64/Packages") != packages {
		t.Fatal("Architecture: all package was not rendered identically for every target")
	}
	if len(artifact.VerificationCases) != 2 {
		t.Fatalf("Architecture: all produced %d verification cases, want 2", len(artifact.VerificationCases))
	}
	release := generatedContent(artifact, "dists/stable/Release")
	for _, expected := range []string{
		"Suite: stable\n",
		"Date: Thu, 23 Jul 2026 01:02:03 UTC\n",
		"Architectures: amd64 arm64\n",
		"SHA256:\n",
		"main/binary-amd64/Packages.gz",
	} {
		if !strings.Contains(release, expected) {
			t.Fatalf("Release is missing %q:\n%s", expected, release)
		}
	}
	second, err := Build([]domain.Blob{blob}, BuildOptions{Suite: "stable", Component: "main", Architectures: []string{"amd64", "arm64"}, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(findContent(artifact, "dists/stable/main/binary-amd64/Packages.gz"), findContent(second, "dists/stable/main/binary-amd64/Packages.gz")) {
		t.Fatal("compressed Packages output is not deterministic")
	}
}

func TestBuildRejectsDifferentBytesForSameIdentity(t *testing.T) {
	first := testBlob(t, "snail-demo", "1.2.3-1", "amd64")
	second := first
	second.Filename = "alternate.deb"
	second.MD5 = strings.Repeat("b", md5.Size*2)
	second.SHA1 = strings.Repeat("b", sha1.Size*2)
	second.SHA256 = strings.Repeat("b", sha256.Size*2)
	_, err := Build([]domain.Blob{first, second}, BuildOptions{
		Suite: "stable", Component: "main", Architectures: []string{"amd64"}, GeneratedAt: time.Unix(0, 0).UTC(),
	})
	if err == nil {
		t.Fatal("expected duplicate package identity with different bytes to fail")
	}
}

func TestBuildRendersEmptyRepository(t *testing.T) {
	artifact, err := Build(nil, BuildOptions{
		Suite: "stable", Component: "main", Architectures: []string{"amd64"}, GeneratedAt: time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := generatedContent(artifact, "dists/stable/main/binary-amd64/Packages"); got != "" {
		t.Fatalf("empty Packages = %q", got)
	}
	if generatedContent(artifact, "dists/stable/Release") == "" || len(artifact.VerificationCases) != 0 {
		t.Fatalf("empty Debian artifact %#v", artifact)
	}
}

func TestBuildRejectsArchitectureWithoutVerifierPlatform(t *testing.T) {
	blob := testBlob(t, "snail-demo", "1.2.3-1", "all")
	_, err := Build([]domain.Blob{blob}, BuildOptions{
		Suite: "stable", Component: "main", Architectures: []string{"riscv64"}, GeneratedAt: time.Unix(0, 0).UTC(),
	})
	if err == nil {
		t.Fatal("expected unsupported verification architecture to fail")
	}
}

func testBlob(t *testing.T, name, version, architecture string) domain.Blob {
	t.Helper()
	content, filename, err := testutil.Deb(name, version, architecture, nil)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := Inspect(filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	md5Value := md5.Sum(content)
	sha1Value := sha1.Sum(content)
	sha256Value := sha256.Sum256(content)
	return domain.Blob{
		Filename: filename,
		Size:     int64(len(content)),
		MD5:      hex.EncodeToString(md5Value[:]),
		SHA1:     hex.EncodeToString(sha1Value[:]),
		SHA256:   hex.EncodeToString(sha256Value[:]),
		Facts:    facts,
	}
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
