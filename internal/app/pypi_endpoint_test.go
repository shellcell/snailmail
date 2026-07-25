package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/host"
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

func TestVerifyPyPIClientEndpointUsesBasicCredentialWithoutLeakingIt(t *testing.T) {
	if err := exec.Command("python3", "-m", "pip", "--version").Run(); err != nil {
		t.Skip("python3 with pip is unavailable")
	}
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "private-demo", "1.0.0", ""); err != nil {
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
	artifact, _, err = buildgraph.Finalize(artifact, time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC))
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
	files := http.FileServer(http.Dir(release))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "reader" || password != "topsecret" {
			writer.Header().Set("WWW-Authenticate", `Basic realm="packages"`)
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		files.ServeHTTP(writer, request)
	}))
	defer server.Close()
	credential := &testBasicCredential{username: "reader", password: "topsecret"}
	_, installed, err := VerifyPyPIClientEndpointAccess(context.Background(), repository, host.ClientAccess{Endpoint: server.URL, Credential: credential}, "python3")
	if err != nil || installed != 1 || !credential.destroyed {
		t.Fatalf("private verification installed=%d destroyed=%t err=%v", installed, credential.destroyed, err)
	}
	bad := &testBasicCredential{username: "reader", password: "do-not-leak"}
	_, _, err = VerifyPyPIClientEndpointAccess(context.Background(), repository, host.ClientAccess{Endpoint: server.URL, Credential: bad}, "python3")
	if err == nil || strings.Contains(err.Error(), "do-not-leak") || !bad.destroyed {
		t.Fatalf("private credential failure leaked or retained secret: %v", err)
	}
}

func TestVerifyPyPIClientEndpointRejectsDifferentDirectoryRoute(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "route-demo", "1.0.0", ""); err != nil {
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
	artifact, _, err = buildgraph.Finalize(artifact, time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC))
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
	files := http.FileServer(http.Dir(release))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/simple/" {
			_, _ = writer.Write([]byte(`<a href="attacker/">attacker</a>`))
			return
		}
		files.ServeHTTP(writer, request)
	}))
	defer server.Close()
	if _, _, err := VerifyPyPIClientEndpoint(context.Background(), repository, server.URL, "python3"); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("directory-route mismatch was accepted: %v", err)
	}
}

func TestCredentialRedactionHandlesOverlappingValues(t *testing.T) {
	redacted := redactCredential("reader-secret reader", "reader", "reader-secret")
	if strings.Contains(redacted, "reader") || strings.Contains(redacted, "secret") {
		t.Fatalf("overlapping credential leaked: %q", redacted)
	}
}

func TestPrivatePyPIEndpointRequiresHTTPSOutsideLoopback(t *testing.T) {
	credential := &testBasicCredential{username: "reader", password: "topsecret"}
	_, _, err := VerifyPyPIClientEndpointAccess(context.Background(), t.TempDir(), host.ClientAccess{
		Endpoint: "http://packages.example/python", Credential: credential,
	}, "python3")
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") || !credential.destroyed {
		t.Fatalf("plaintext private endpoint result destroyed=%t err=%v", credential.destroyed, err)
	}
}

type testBasicCredential struct {
	username  string
	password  string
	destroyed bool
}

func (credential *testBasicCredential) Basic(context.Context) (string, string, error) {
	return credential.username, credential.password, nil
}

func (credential *testBasicCredential) Destroy() {
	credential.destroyed = true
	credential.username = ""
	credential.password = ""
}
