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

	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

// importWorkspace is a configured PyPI repository with nothing in it, which is
// where someone adopting an existing repository starts.
func importWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "import-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "local",
		Output: "public/python", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishedProject serves a simple project page and its artifacts, the way an
// existing PyPI repository does.
func publishedProject(t *testing.T, versions ...string) (*adoptMemoryFetcher, map[string]string) {
	t.Helper()
	responses := make(map[string]source.Response)
	digests := make(map[string]string)
	var links strings.Builder
	for _, version := range versions {
		artifact, err := testutil.WriteWheel(t.TempDir(), "demo", version, ">=3.8")
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		digest := hex.EncodeToString(sum[:])
		filename := fmt.Sprintf("demo-%s-py3-none-any.whl", version)
		digests[filename] = digest
		address := "https://packages.example/simple/demo/" + filename
		responses[address] = source.Response{StatusCode: 200, Body: content, ContentType: "application/octet-stream"}
		fmt.Fprintf(&links, `<a href="%s#sha256=%s">%s</a><br>`, filename, digest, filename)
	}
	page := "<!DOCTYPE html><html><head><title>Links for demo</title></head><body><h1>Links for demo</h1>" +
		links.String() + "</body></html>"
	responses["https://packages.example/simple/demo/"] = source.Response{
		StatusCode: 200, Body: []byte(page), ContentType: "text/html",
	}
	return &adoptMemoryFetcher{responses: responses}, digests
}

func importRequest(root string, fetcher source.Fetcher) ImportRepositoryRequest {
	return ImportRepositoryRequest{
		Root: root, Repository: "python", URL: "https://packages.example/",
		Project: "demo", PublicOrigin: true, Fetcher: fetcher,
	}
}

// The point of the feature: an existing repository becomes a workspace without
// re-adopting every artifact by hand.
func TestImportRecordsEveryArtifactAnIndexNames(t *testing.T) {
	root := importWorkspace(t)
	fetcher, digests := publishedProject(t, "1.0.0", "2.0.0")
	result, err := ImportRepository(context.Background(), importRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if result.Listed != 2 || len(result.Imported) != 2 {
		t.Fatalf("listed %d and imported %d, want 2 of each: %+v", result.Listed, len(result.Imported), result)
	}
	if len(result.Skipped) != 0 {
		t.Errorf("skipped %+v", result.Skipped)
	}
	for _, imported := range result.Imported {
		if digests[imported.Filename] != imported.SHA256 {
			t.Errorf("%s recorded digest %s, want the one the index published", imported.Filename, imported.SHA256)
		}
		// The origin is what makes an imported artifact refetchable, and it is the
		// URL it actually came from rather than the index it was named in.
		if !strings.HasSuffix(imported.Origin, imported.Filename) {
			t.Errorf("%s recorded origin %q", imported.Filename, imported.Origin)
		}
	}
}

// snailmail's guarantee is that a locked artifact is pinned to a digest stated in
// advance. An index that publishes none cannot support that, and computing one
// from the bytes it served would record a pin proving only that a download was
// self-consistent.
func TestImportSkipsArtifactsWithNoPublishedDigest(t *testing.T) {
	root := importWorkspace(t)
	artifact, err := testutil.WriteWheel(t.TempDir(), "demo", "1.0.0", ">=3.8")
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	page := `<!DOCTYPE html><html><body><a href="demo-1.0.0-py3-none-any.whl">demo-1.0.0-py3-none-any.whl</a></body></html>`
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{
		"https://packages.example/simple/demo/":                            {StatusCode: 200, Body: []byte(page), ContentType: "text/html"},
		"https://packages.example/simple/demo/demo-1.0.0-py3-none-any.whl": {StatusCode: 200, Body: content},
	}}
	result, err := ImportRepository(context.Background(), importRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 0 {
		t.Errorf("imported %+v, want nothing without a published digest", result.Imported)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "SHA-256") {
		t.Errorf("skipped %+v, want one artifact with the digest as the reason", result.Skipped)
	}
}

// One bad artifact does not abandon the rest. The repository being imported is
// someone else's, and a file whose bytes disagree with its published digest is a
// fact about it worth reporting alongside everything that worked.
func TestImportReportsOneFailureAndKeepsTheRest(t *testing.T) {
	root := importWorkspace(t)
	fetcher, _ := publishedProject(t, "1.0.0", "2.0.0")
	// Corrupt one artifact so its bytes no longer match the digest the index
	// published, which is what a tampered or truncated mirror looks like.
	for address, response := range fetcher.responses {
		if strings.HasSuffix(address, "demo-2.0.0-py3-none-any.whl") {
			fetcher.responses[address] = source.Response{StatusCode: 200, Body: append(response.Body, 'x')}
		}
	}
	result, err := ImportRepository(context.Background(), importRequest(root, fetcher))
	if err != nil {
		t.Fatalf("import abandoned everything because one artifact failed: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Version != "1.0.0" {
		t.Errorf("imported %+v, want the sound artifact", result.Imported)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("skipped %+v, want the corrupt one", result.Skipped)
	}
	if !strings.Contains(result.Skipped[0].Filename, "2.0.0") {
		t.Errorf("skipped %+v, want the corrupt artifact named", result.Skipped)
	}
}

// A dry run has to report what a real import would do and record nothing, or it is
// no use for looking at someone else's repository before taking it on.
func TestImportDryRunRecordsNothing(t *testing.T) {
	root := importWorkspace(t)
	fetcher, _ := publishedProject(t, "1.0.0", "2.0.0")
	request := importRequest(root, fetcher)
	request.DryRun = true
	dry, err := ImportRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || len(dry.Imported) != 2 {
		t.Fatalf("dry run reported %+v", dry)
	}
	lockAfterDryRun, err := os.ReadFile(root + "/repos/python.lock.toml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lockAfterDryRun), "demo") {
		t.Error("a dry run wrote to the lock")
	}
	// And the real thing imports what the dry run reported.
	request.DryRun = false
	wet, err := ImportRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(wet.Imported) != len(dry.Imported) {
		t.Errorf("dry run said %d, import recorded %d", len(dry.Imported), len(wet.Imported))
	}
}

// An import records one origin URL per artifact into a lock that is committed and
// reviewed, so it asks the same confirmation adopt does rather than quietly
// persisting whatever was passed.
func TestImportRequiresConfirmationThatOriginsArePublic(t *testing.T) {
	root := importWorkspace(t)
	fetcher, _ := publishedProject(t, "1.0.0")
	request := importRequest(root, fetcher)
	request.PublicOrigin = false
	if _, err := ImportRepository(context.Background(), request); err == nil {
		t.Error("an import ran without confirming its origins are public")
	}
}

// A page naming a different project is a server serving one project's content at
// another's URL, and following it would import someone else's artifacts under the
// name that was asked for.
//
// Checkable only for a PEP 691 JSON page, which carries the project name. The
// legacy HTML page does not, so ParseSimpleProject returns an empty name for it and
// this check cannot apply — a limitation of the format rather than of the check.
func TestImportRefusesAPageNamingAnotherProject(t *testing.T) {
	root := importWorkspace(t)
	page := `{"meta":{"api-version":"1.0"},"name":"other","files":[]}`
	fetcher := &adoptMemoryFetcher{responses: map[string]source.Response{
		"https://packages.example/simple/demo/": {
			StatusCode: 200, Body: []byte(page), ContentType: "application/vnd.pypi.simple.v1+json",
		},
	}}
	_, err := ImportRepository(context.Background(), importRequest(root, fetcher))
	if err == nil || !strings.Contains(err.Error(), "other") {
		t.Errorf("error = %v, want the mismatched project named", err)
	}
}

// A format whose index is not read yet says so, rather than importing nothing and
// reporting success.
func TestImportNamesAFormatItCannotRead(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "import-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "tools", Format: "raw", HostType: "local",
		Output: "public/tools", Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	fetcher, _ := publishedProject(t, "1.0.0")
	request := importRequest(root, fetcher)
	request.Repository = "tools"
	_, err := ImportRepository(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "raw") {
		t.Errorf("error = %v, want the unreadable format named", err)
	}
}

// A simple index lists projects rather than their files, so an import that was not
// told which project has nothing to enumerate. Saying so beats fetching an index
// and reporting zero artifacts.
func TestImportAsksWhichProject(t *testing.T) {
	root := importWorkspace(t)
	fetcher, _ := publishedProject(t, "1.0.0")
	request := importRequest(root, fetcher)
	request.Project = ""
	_, err := ImportRepository(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "project") {
		t.Errorf("error = %v, want a request for the project", err)
	}
}
