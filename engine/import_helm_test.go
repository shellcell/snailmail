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

func helmImportWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "helm-import"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "charts", Format: "helm", HostType: "local",
		Output: "public/charts", Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishedCharts serves an index.yaml and its charts, the way an existing Helm
// repository does. mirrors controls how many URLs each entry lists.
func publishedCharts(t *testing.T, mirrors int, versions ...string) *adoptMemoryFetcher {
	t.Helper()
	responses := make(map[string]source.Response)
	var entries strings.Builder
	entries.WriteString("apiVersion: v1\nentries:\n  demo:\n")
	for _, version := range versions {
		chart, err := testutil.WriteHelmChart(t.TempDir(), "demo", version)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(chart)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		digest := hex.EncodeToString(sum[:])
		fmt.Fprintf(&entries, "  - name: demo\n    version: %s\n    digest: %s\n    urls:\n", version, digest)
		for mirror := range mirrors {
			address := fmt.Sprintf("https://charts.example/m%d/demo-%s.tgz", mirror, version)
			fmt.Fprintf(&entries, "    - %s\n", address)
			// Only the last mirror serves, so a reader that stopped at the first
			// listed URL would import nothing.
			if mirror == mirrors-1 {
				responses[address] = source.Response{StatusCode: 200, Body: content}
			}
		}
	}
	responses["https://charts.example/index.yaml"] = source.Response{
		StatusCode: 200, Body: []byte(entries.String()), ContentType: "application/x-yaml",
	}
	return &adoptMemoryFetcher{responses: responses}
}

func helmImportRequest(root string, fetcher source.Fetcher) ImportRepositoryRequest {
	return ImportRepositoryRequest{
		Root: root, Repository: "charts", URL: "https://charts.example/",
		PublicOrigin: true, Fetcher: fetcher,
	}
}

// One index covers every chart, so unlike PyPI there is nothing to narrow by and
// importing a Helm repository imports the repository.
func TestHelmImportTakesEveryChartWithoutAProject(t *testing.T) {
	root := helmImportWorkspace(t)
	fetcher := publishedCharts(t, 1, "1.0.0", "2.0.0")
	result, err := ImportRepository(context.Background(), helmImportRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if result.Listed != 2 || len(result.Imported) != 2 {
		t.Fatalf("listed %d imported %d: %+v", result.Listed, len(result.Imported), result)
	}
	for _, imported := range result.Imported {
		if imported.Package != "demo" {
			t.Errorf("imported %+v, want the chart named demo", imported)
		}
		if !strings.HasSuffix(imported.Filename, ".tgz") {
			t.Errorf("imported %q, want a packaged chart filename", imported.Filename)
		}
	}
}

// A Helm index entry may list several mirrors of one chart. The origin recorded is
// the URL that actually served, because that is where a later check or refetch has
// to go — recording the first listed would record somewhere that may never have
// worked.
func TestHelmImportRecordsTheMirrorThatServed(t *testing.T) {
	root := helmImportWorkspace(t)
	// Three URLs, only the third of which serves.
	fetcher := publishedCharts(t, 3, "1.0.0")
	result, err := ImportRepository(context.Background(), helmImportRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 {
		t.Fatalf("imported %+v, want the chart from its working mirror", result.Imported)
	}
	if !strings.Contains(result.Imported[0].Origin, "/m2/") {
		t.Errorf("recorded origin %q, want the mirror that served", result.Imported[0].Origin)
	}
}

// index.yaml states each chart's digest and nothing signs the index, so an
// imported chart reaches the same level a simple index does — and the lock says so
// rather than leaving a reader to infer it.
func TestHelmImportRecordsIndexStatedProvenance(t *testing.T) {
	root := helmImportWorkspace(t)
	fetcher := publishedCharts(t, 1, "1.0.0")
	if _, err := ImportRepository(context.Background(), helmImportRequest(root, fetcher)); err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["charts"])
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.PackageVersion) != 1 {
		t.Fatalf("lock holds %d versions", len(lock.PackageVersion))
	}
	for _, blob := range lock.PackageVersion[0].Blobs {
		if got := state.DigestProvenanceOf(blob); got != state.ProvenanceIndexStated {
			t.Errorf("recorded provenance %q, want %q", got, state.ProvenanceIndexStated)
		}
	}
}

// A chart whose bytes disagree with the digest the index published is a fact about
// that repository, reported alongside the charts that were sound.
func TestHelmImportReportsAChartThatDoesNotMatchItsDigest(t *testing.T) {
	root := helmImportWorkspace(t)
	fetcher := publishedCharts(t, 1, "1.0.0", "2.0.0")
	for address, response := range fetcher.responses {
		if strings.HasSuffix(address, "demo-2.0.0.tgz") {
			fetcher.responses[address] = source.Response{StatusCode: 200, Body: append(response.Body, 'x')}
		}
	}
	result, err := ImportRepository(context.Background(), helmImportRequest(root, fetcher))
	if err != nil {
		t.Fatalf("one bad chart abandoned the import: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Version != "1.0.0" {
		t.Errorf("imported %+v, want the sound chart", result.Imported)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Filename, "2.0.0") {
		t.Errorf("skipped %+v, want the corrupt chart named", result.Skipped)
	}
}

// A production Helm index can list the same chart and version twice — grafana's
// lists 3574 versions of which 2 are duplicated. Refusing the whole document over
// that made every real repository unreadable; the ambiguous pair is skipped and
// named instead, because two entries claiming one identity cannot both be it.
func TestHelmImportSkipsAmbiguousEntriesAndReadsTheRest(t *testing.T) {
	root := helmImportWorkspace(t)
	fetcher := publishedCharts(t, 1, "1.0.0", "2.0.0")
	// Repeat one entry with a different digest, which is what makes it ambiguous
	// rather than merely repeated.
	index := fetcher.responses["https://charts.example/index.yaml"]
	doubled := string(index.Body) +
		"  - name: demo\n    version: 2.0.0\n    digest: " + strings.Repeat("f", 64) +
		"\n    urls:\n    - https://charts.example/m0/demo-2.0.0.tgz\n"
	fetcher.responses["https://charts.example/index.yaml"] = source.Response{
		StatusCode: 200, Body: []byte(doubled), ContentType: "application/x-yaml",
	}
	result, err := ImportRepository(context.Background(), helmImportRequest(root, fetcher))
	if err != nil {
		t.Fatalf("a duplicate entry abandoned the whole index: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Version != "1.0.0" {
		t.Errorf("imported %+v, want the unambiguous chart", result.Imported)
	}
	ambiguous := 0
	for _, skipped := range result.Skipped {
		if strings.Contains(skipped.Reason, "more than once") {
			ambiguous++
		}
	}
	// Both entries of the repeated identity are named, not just the second.
	if ambiguous != 2 {
		t.Errorf("reported %d ambiguous entries, want both copies: %+v", ambiguous, result.Skipped)
	}
}

// Ambiguity is a fact about the repository rather than about how much of it was
// asked for, so a limited import still reports it. A limit that hid it would
// report a clean index that is not one.
func TestAmbiguityIsReportedEvenUnderALimit(t *testing.T) {
	root := helmImportWorkspace(t)
	fetcher := publishedCharts(t, 1, "1.0.0", "2.0.0")
	index := fetcher.responses["https://charts.example/index.yaml"]
	doubled := string(index.Body) +
		"  - name: demo\n    version: 2.0.0\n    digest: " + strings.Repeat("f", 64) +
		"\n    urls:\n    - https://charts.example/m0/demo-2.0.0.tgz\n"
	fetcher.responses["https://charts.example/index.yaml"] = source.Response{
		StatusCode: 200, Body: []byte(doubled), ContentType: "application/x-yaml",
	}
	request := helmImportRequest(root, fetcher)
	request.Limit = 1
	result, err := ImportRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, skipped := range result.Skipped {
		if strings.Contains(skipped.Reason, "more than once") {
			return
		}
	}
	t.Errorf("a limited import hid the ambiguity: %+v", result.Skipped)
}
