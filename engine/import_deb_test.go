package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

func debImportWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "deb-import"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "apt", Format: "deb", HostType: "local", Output: "public/apt",
		Suite: "bookworm", Component: "main", Architectures: []string{"amd64"},
		Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishedSuite serves a Release naming a Packages, the Packages itself, and the
// pool artifacts — the chain an import has to walk.
func publishedSuite(t *testing.T, versions ...string) *adoptMemoryFetcher {
	t.Helper()
	responses := make(map[string]source.Response)
	var packages strings.Builder
	for _, version := range versions {
		artifact, err := testutil.WriteDeb(t.TempDir(), "demo", version, "amd64", nil)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		poolPath := fmt.Sprintf("pool/main/d/demo/demo_%s_amd64.deb", version)
		fmt.Fprintf(&packages, "Package: demo\nVersion: %s\nArchitecture: amd64\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
			version, poolPath, len(content), hex.EncodeToString(sum[:]))
		responses["https://deb.example/debian/"+poolPath] = source.Response{StatusCode: 200, Body: content}
	}
	packagesBody := []byte(packages.String())
	packagesSum := sha256.Sum256(packagesBody)
	release := fmt.Sprintf(
		"Suite: bookworm\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages\n",
		hex.EncodeToString(packagesSum[:]), len(packagesBody))
	responses["https://deb.example/debian/dists/bookworm/Release"] = source.Response{
		StatusCode: 200, Body: []byte(release),
	}
	responses["https://deb.example/debian/dists/bookworm/main/binary-amd64/Packages"] = source.Response{
		StatusCode: 200, Body: packagesBody,
	}
	return &adoptMemoryFetcher{responses: responses}
}

func debImportRequest(root string, fetcher source.Fetcher) ImportRepositoryRequest {
	return ImportRepositoryRequest{
		Root: root, Repository: "apt", URL: "https://deb.example/debian",
		Suite: "bookworm", PublicOrigin: true, Fetcher: fetcher,
	}
}

func TestDebImportWalksTheChain(t *testing.T) {
	root := debImportWorkspace(t)
	result, err := ImportRepository(context.Background(), debImportRequest(root, publishedSuite(t, "1.0.0", "2.0.0")))
	if err != nil {
		t.Fatal(err)
	}
	if result.Listed != 2 || len(result.Imported) != 2 {
		t.Fatalf("listed %d imported %d: %+v", result.Listed, len(result.Imported), result)
	}
}

// This is what ProvenanceIndexChain claims, and recording the level without
// performing the check would make the lock say something untrue. A Packages whose
// bytes disagree with what Release states for it is refused outright — not
// skipped per artifact, because nothing in it can be trusted.
func TestDebImportRefusesAPackagesThatReleaseDoesNotVouchFor(t *testing.T) {
	root := debImportWorkspace(t)
	fetcher := publishedSuite(t, "1.0.0")
	tampered := fetcher.responses["https://deb.example/debian/dists/bookworm/main/binary-amd64/Packages"]
	// One byte changed, which is what a mirror rewriting an index looks like.
	fetcher.responses["https://deb.example/debian/dists/bookworm/main/binary-amd64/Packages"] =
		source.Response{StatusCode: 200, Body: append(tampered.Body, '\n')}
	_, err := ImportRepository(context.Background(), debImportRequest(root, fetcher))
	if err == nil {
		t.Fatal("a Packages that Release does not vouch for was read")
	}
	if !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("error = %v, want the chain break named", err)
	}
}

// The level recorded has to be the one actually established: Release vouches for
// Packages, so this is index-chain rather than the index-stated a PyPI page gets.
func TestDebImportRecordsIndexChainProvenance(t *testing.T) {
	root := debImportWorkspace(t)
	if _, err := ImportRepository(context.Background(), debImportRequest(root, publishedSuite(t, "1.0.0"))); err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["apt"])
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.PackageVersion) == 0 {
		t.Fatal("nothing was locked")
	}
	for _, blob := range lock.PackageVersion[0].Blobs {
		if got := state.DigestProvenanceOf(blob); got != state.ProvenanceIndexChain {
			t.Errorf("recorded %q, want %q", got, state.ProvenanceIndexChain)
		}
	}
}

// A Debian repository serves several suites, and reading the wrong one imports
// somebody else's distribution. Saying so beats picking one.
func TestDebImportAsksWhichSuite(t *testing.T) {
	root := debImportWorkspace(t)
	request := debImportRequest(root, publishedSuite(t, "1.0.0"))
	request.Suite = ""
	_, err := ImportRepository(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "suite") {
		t.Errorf("error = %v, want a request for the suite", err)
	}
}
