package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

func rpmImportWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "yum-import"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "yum", Format: "rpm", HostType: "local", Output: "public/yum",
		Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishedYum serves repomd.xml, the gzipped primary.xml it vouches for, and the
// package — the chain an import has to walk. The rpm is the real fixture, because
// import inspects the artifact to derive its architecture.
func publishedYum(t *testing.T) *adoptMemoryFetcher {
	t.Helper()
	content, err := os.ReadFile("../formats/rpm/testdata/snail-demo-1.2.3-4.noarch.rpm")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	location := "Packages/s/snail-demo-1.2.3-4.noarch.rpm"
	primary := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
  <package type="rpm">
    <name>snail-demo</name>
    <arch>noarch</arch>
    <version epoch="0" ver="1.2.3" rel="4"/>
    <checksum type="sha256" pkgid="YES">%s</checksum>
    <location href="%s"/>
    <size package="%d"/>
  </package>
</metadata>`, hex.EncodeToString(sum[:]), location, len(content)))

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(primary); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	primarySum := sha256.Sum256(compressed.Bytes())
	primaryLocation := "repodata/abc-primary.xml.gz"

	repomd := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>
  <data type="primary">
    <checksum type="sha256">%s</checksum>
    <location href="%s"/>
    <size>%d</size>
  </data>
</repomd>`, hex.EncodeToString(primarySum[:]), primaryLocation, compressed.Len())

	return &adoptMemoryFetcher{responses: map[string]source.Response{
		"https://yum.example/repo/repodata/repomd.xml": {StatusCode: 200, Body: []byte(repomd)},
		"https://yum.example/repo/" + primaryLocation:  {StatusCode: 200, Body: compressed.Bytes()},
		"https://yum.example/repo/" + location:         {StatusCode: 200, Body: content},
	}}
}

func rpmImportRequest(root string, fetcher source.Fetcher) ImportRepositoryRequest {
	return ImportRepositoryRequest{
		Root: root, Repository: "yum", URL: "https://yum.example/repo",
		PublicOrigin: true, Fetcher: fetcher,
	}
}

func TestYumImportWalksTheChain(t *testing.T) {
	root := rpmImportWorkspace(t)
	result, err := ImportRepository(context.Background(), rpmImportRequest(root, publishedYum(t)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Listed != 1 || len(result.Imported) != 1 {
		t.Fatalf("listed %d imported %d: %+v", result.Listed, len(result.Imported), result)
	}
}

// What repomd says about primary has to hold before anything primary says about a
// package is worth recording. Recording index-chain without performing this check
// would put a claim in the lock that nothing established.
func TestYumImportRefusesAPrimaryThatRepomdDoesNotVouchFor(t *testing.T) {
	root := rpmImportWorkspace(t)
	fetcher := publishedYum(t)
	const address = "https://yum.example/repo/repodata/abc-primary.xml.gz"
	fetcher.responses[address] = source.Response{
		StatusCode: 200, Body: append(fetcher.responses[address].Body, 0x00),
	}
	_, err := ImportRepository(context.Background(), rpmImportRequest(root, fetcher))
	if err == nil {
		t.Fatal("a primary that repomd does not vouch for was read")
	}
	// The size disagrees first here, which is the same break reported earlier; either
	// half of the statement failing is the chain failing.
	if !strings.Contains(err.Error(), "SHA-256") && !strings.Contains(err.Error(), "bytes") {
		t.Errorf("error = %v, want the chain break named", err)
	}
}

// repomd can state sha1 or md5 for its indexes. Importing anyway would mean
// claiming a chain that was never checked, so this stops rather than silently
// dropping to a weaker provenance the operator did not ask for.
func TestYumImportRefusesAPrimaryWithNoSHA256(t *testing.T) {
	root := rpmImportWorkspace(t)
	fetcher := publishedYum(t)
	fetcher.responses["https://yum.example/repo/repodata/repomd.xml"] = source.Response{
		StatusCode: 200, Body: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <checksum type="sha1">da39a3ee5e6b4b0d3255bfef95601890afd80709</checksum>
    <location href="repodata/abc-primary.xml.gz"/>
  </data>
</repomd>`),
	}
	_, err := ImportRepository(context.Background(), rpmImportRequest(root, fetcher))
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("error = %v, want the missing SHA-256 named", err)
	}
}

// A repository with no primary index names no packages, which is a different
// failure from one that names none — and worth its own sentence.
func TestYumImportSaysWhenNothingNamesThePackages(t *testing.T) {
	root := rpmImportWorkspace(t)
	fetcher := publishedYum(t)
	fetcher.responses["https://yum.example/repo/repodata/repomd.xml"] = source.Response{
		StatusCode: 200, Body: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision></repomd>`),
	}
	_, err := ImportRepository(context.Background(), rpmImportRequest(root, fetcher))
	if err == nil || !strings.Contains(err.Error(), "primary") {
		t.Errorf("error = %v, want the missing primary index named", err)
	}
}

func TestYumImportRecordsIndexChainProvenance(t *testing.T) {
	root := rpmImportWorkspace(t)
	if _, err := ImportRepository(context.Background(), rpmImportRequest(root, publishedYum(t))); err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["yum"])
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
