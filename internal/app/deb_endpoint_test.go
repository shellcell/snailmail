package app

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/testutil"
)

// debianVerificationImage is the pinned image the engine defaults to. It is
// repeated rather than imported because internal/app must not depend on engine.
const debianVerificationImage = "docker.io/library/debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"

// hostDebianArchitecture is the Debian name for the architecture this test runs
// on. Building for the host avoids asking the runtime to resolve a
// manifest-list digest under a foreign --platform, which it refuses.
func hostDebianArchitecture(t *testing.T) string {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		t.Skipf("no Debian architecture mapping for %s", runtime.GOARCH)
		return ""
	}
}

// buildDebRepository renders a real Debian repository from one package and
// returns its directory.
func buildDebRepository(t *testing.T, architecture string) string {
	t.Helper()
	source, err := testutil.WriteDeb(t.TempDir(), "snail-demo", "1.2.3", architecture, nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := deb.Inspect(filepath.Base(source), bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	md5Digest, sha1Digest, sha256Digest := md5.Sum(content), sha1.Sum(content), sha256.Sum256(content)
	blob := domain.Blob{
		Filename: filepath.Base(source), Size: int64(len(content)),
		MD5:    hex.EncodeToString(md5Digest[:]),
		SHA1:   hex.EncodeToString(sha1Digest[:]),
		SHA256: hex.EncodeToString(sha256Digest[:]),
		Facts:  facts,
	}
	artifact, err := deb.Build([]domain.Blob{blob}, deb.BuildOptions{
		Suite: "stable", Component: "main", Architectures: []string{architecture},
		GeneratedAt: time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if err := Materialize(context.Background(), output, mustFinalize(t, artifact), map[string]string{blob.SHA256: source}); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(output)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// The endpoint verifier must refuse anything a package client should not be
// pointed at, before it starts a container or fetches anything.
func TestDebEndpointVerificationRejectsUnusableEndpoints(t *testing.T) {
	repository := buildDebRepository(t, "amd64")
	for name, endpoint := range map[string]string{
		"plaintext non-loopback": "http://packages.example.com/apt",
		"credentials in URL":     "https://user:pass@packages.example.com/apt",
		"query string":           "https://packages.example.com/apt?token=x",
		"not a URL":              "::::",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyDebClientEndpointAccess(context.Background(), repository,
				host.ClientAccess{Endpoint: endpoint}, "docker", debianVerificationImage, 4<<30)
			if err == nil {
				t.Fatalf("endpoint %q was accepted", endpoint)
			}
		})
	}
}

// A host serving different bytes than were reviewed must fail before any client
// runs, because the client would otherwise install from the wrong tree.
func TestDebEndpointVerificationDetectsServedDrift(t *testing.T) {
	repository := buildDebRepository(t, "amd64")
	server := httptest.NewServer(http.FileServer(http.Dir(repository)))
	defer server.Close()

	tampered := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/Release") {
			_, _ = writer.Write([]byte("not the reviewed Release\n"))
			return
		}
		http.FileServer(http.Dir(repository)).ServeHTTP(writer, request)
	}))
	defer tampered.Close()

	_, _, err := VerifyDebClientEndpointAccess(context.Background(), repository,
		host.ClientAccess{Endpoint: tampered.URL}, "docker", debianVerificationImage, 4<<30)
	if err == nil {
		t.Fatal("a host serving a different Release was accepted")
	}
	if !strings.Contains(err.Error(), "do not match the reviewed tree") {
		t.Fatalf("error = %v, want a served-bytes mismatch", err)
	}
}

// The end-to-end proof: apt reads the repository over HTTP from the address the
// host serves, resolves the package, and installs it. This is what separates a
// correct tree from an installable one.
func TestDebEndpointVerificationInstallsOverHTTP(t *testing.T) {
	// A loopback endpoint needs the container to share the host's network
	// namespace. On macOS the runtime is a Linux VM, so --network=host joins the
	// VM rather than the host and the server here is unreachable. The path this
	// proves is Linux-only in practice, which is also where it runs in CI.
	if runtime.GOOS != "linux" {
		t.Skip("loopback endpoint verification needs a container sharing the host network namespace")
	}
	runner := containerRunner(t)
	repository := buildDebRepository(t, hostDebianArchitecture(t))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.FileServer(http.Dir(repository))}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	// Loopback: the verifier gives the container host networking to reach it.
	endpoint := "http://" + listener.Addr().String()
	manifest, installed, err := VerifyDebClientEndpointAccess(context.Background(), repository,
		host.ClientAccess{Endpoint: endpoint}, runner, debianVerificationImage, 4<<30)
	if err != nil {
		t.Fatalf("apt could not install from the served repository: %v", err)
	}
	if manifest.Format != deb.FormatID {
		t.Fatalf("format = %q", manifest.Format)
	}
	if installed == 0 {
		t.Fatal("no verification case ran")
	}
}

// containerRunner finds a runtime. The image itself is pulled by --pull=missing
// during the run, so a runner that has never seen it still exercises the path.
func containerRunner(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("no container runner is available")
	return ""
}

func mustFinalize(t *testing.T, artifact domain.RepositoryArtifact) domain.RepositoryArtifact {
	t.Helper()
	finalized, _, err := buildgraph.Finalize(artifact, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}
