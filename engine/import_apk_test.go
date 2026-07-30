package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/source"
)

func apkImportWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "apk-import"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "alpine", Format: "apk", HostType: "local", Output: "public/alpine",
		Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishedAlpine serves APKINDEX.tar.gz and the package it names. The index states
// a C: checksum, as Alpine's does, and it is deliberately not a digest of the file —
// which is the whole reason this import records a computed pin.
func publishedAlpine(t *testing.T) *adoptMemoryFetcher {
	t.Helper()
	content, err := os.ReadFile("../formats/apk/testdata/snail-demo-1.2.3-r4.apk")
	if err != nil {
		t.Fatal(err)
	}
	entries := "C:Q1YCZ4e/kV0Uaynh14//zvTTyN7x8=\nP:snail-demo\nV:1.2.3-r4\nA:x86_64\nS:1024\n\n"
	var archive bytes.Buffer
	compressor := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressor)
	if err := writer.WriteHeader(&tar.Header{Name: "APKINDEX", Mode: 0o644, Size: int64(len(entries))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(entries)); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	compressor.Close()
	return &adoptMemoryFetcher{responses: map[string]source.Response{
		"https://alpine.example/main/x86_64/APKINDEX.tar.gz":         {StatusCode: 200, Body: archive.Bytes()},
		"https://alpine.example/main/x86_64/snail-demo-1.2.3-r4.apk": {StatusCode: 200, Body: content},
	}}
}

func apkImportRequest(root string, fetcher source.Fetcher) ImportRepositoryRequest {
	return ImportRepositoryRequest{
		Root: root, Repository: "alpine", URL: "https://alpine.example/main/x86_64",
		PublicOrigin: true, Fetcher: fetcher,
	}
}

// Alpine is the one format whose index cannot pin a file, so it is also the one
// case where a digest is recorded that nobody stated in advance. That has to be
// possible — otherwise import cannot read Alpine at all — and it has to be labelled.
func TestAlpineImportRecordsAComputedPin(t *testing.T) {
	root := apkImportWorkspace(t)
	result, err := ImportRepository(context.Background(), apkImportRequest(root, publishedAlpine(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 {
		t.Fatalf("imported %+v skipped %+v", result.Imported, result.Skipped)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["alpine"])
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range lock.PackageVersion[0].Blobs {
		if got := state.DigestProvenanceOf(blob); got != state.ProvenanceComputed {
			t.Errorf("recorded %q, want %q — a computed pin must not be labelled as anything stronger", got, state.ProvenanceComputed)
		}
		// And the digest recorded is of the bytes that arrived, not of anything the
		// index said, because the index said nothing about the file.
		if blob.SHA256 == "" {
			t.Error("no digest was recorded")
		}
	}
}

// The floor is what makes a computed pin safe to allow by default: a workspace that
// will not accept unauthenticated bytes says so once, and Alpine then imports
// nothing rather than quietly recording pins that prove only a download happened.
func TestAProvenanceFloorRefusesWhatTheIndexCannotEstablish(t *testing.T) {
	root := apkImportWorkspace(t)
	request := apkImportRequest(root, publishedAlpine(t))
	request.MinimumProvenance = state.ProvenanceIndexStated
	result, err := ImportRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 0 {
		t.Fatalf("imported %+v under a floor Alpine cannot meet", result.Imported)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "computed") {
		t.Fatalf("skipped %+v, want the provenance named as the reason", result.Skipped)
	}
	// The floor names what was required, so the operator can tell a refusal from a
	// broken index without re-running anything.
	if !strings.Contains(result.Skipped[0].Reason, string(state.ProvenanceIndexStated)) {
		t.Errorf("reason %q does not say what was required", result.Skipped[0].Reason)
	}
}

// A floor must not refuse what does meet it. Debian establishes index-chain, which
// is stronger than index-stated, so a workspace asking for the latter still imports.
func TestAProvenanceFloorAdmitsAStrongerChain(t *testing.T) {
	root := debImportWorkspace(t)
	request := debImportRequest(root, publishedSuite(t, "1.0.0"))
	request.MinimumProvenance = state.ProvenanceIndexStated
	result, err := ImportRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 {
		t.Errorf("a chain stronger than the floor was refused: imported %+v skipped %+v",
			result.Imported, result.Skipped)
	}
}

// adopt's contract is that a locked artifact is pinned to a digest stated in
// advance. The Alpine exception must therefore be exactly that — an exception a
// caller asks for by name — rather than a hole that swallows a forgotten digest.
func TestAdoptStillRequiresADigestUnlessComputedIsAsked(t *testing.T) {
	root := apkImportWorkspace(t)
	fetcher := publishedAlpine(t)
	const address = "https://alpine.example/main/x86_64/snail-demo-1.2.3-r4.apk"
	base := AdoptArtifactRequest{
		Root: root, Repository: "alpine", URL: address,
		Filename: "snail-demo-1.2.3-r4.apk", PublicOrigin: true, Fetcher: fetcher,
	}
	// No digest and no declared provenance is the forgotten-digest case.
	if _, err := AdoptArtifact(context.Background(), base); err == nil {
		t.Error("adopt accepted an artifact with no digest and no stated provenance")
	}
	// Naming a level that claims the index stated something does not excuse it.
	stated := base
	stated.Provenance = state.ProvenanceIndexStated
	if _, err := AdoptArtifact(context.Background(), stated); err == nil {
		t.Error("adopt accepted a missing digest under a provenance that claims one was stated")
	}
	// Declaring it computed is the one way through.
	computed := base
	computed.Provenance = state.ProvenanceComputed
	adopted, err := AdoptArtifact(context.Background(), computed)
	if err != nil {
		t.Fatalf("adopt refused an explicitly computed pin: %v", err)
	}
	if adopted.SHA256 == "" {
		t.Error("adopt recorded no digest for a computed pin")
	}
}
