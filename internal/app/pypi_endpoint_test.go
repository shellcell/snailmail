package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestVerifyPyPIClientEndpointInstallsFromSelectedHost(t *testing.T) {
	if err := exec.Command("python3", "-m", "pip", "--version").Run(); err != nil {
		t.Skip("python3 with pip is unavailable")
	}
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "snail-demo", "1.2.3", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ScanPyPI(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	artifact, err := pypi.Build(snapshot.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	artifact, _, err = buildgraph.Finalize(artifact, time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := Materialize(context.Background(), repository, artifact, snapshot.Sources); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(release)))
	defer server.Close()
	manifest, installed, err := VerifyPyPIClientEndpoint(context.Background(), repository, server.URL, "python3")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TreeSHA256 == "" || installed != 1 {
		t.Fatalf("unexpected endpoint verification tree=%q installed=%d", manifest.TreeSHA256, installed)
	}
}
