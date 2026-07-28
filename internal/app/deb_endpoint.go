package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
)

// VerifyDebClientEndpointAccess installs from a Debian repository the host is
// actually serving, using apt against the endpoint rather than a mounted
// directory.
//
// This is the difference between "the tree we built is correct" and "the tree
// the host serves is installable", which is the guarantee publication rests on:
// relative paths inside Packages, the suite layout under dists/, and the
// keyring apt is told to trust all have to survive the host's URL handling.
func VerifyDebClientEndpointAccess(ctx context.Context, root string, access host.ClientAccess, runner, image string, maxWorkspaceBytes int64) (buildgraph.RepositoryManifest, int, error) {
	if access.Credential != nil {
		defer access.Credential.Destroy()
	}
	endpoint, err := validateClientEndpoint(access.Endpoint)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	// A private Debian repository would need apt credentials inside the
	// container; nothing issues them yet, so refuse rather than silently
	// verifying an unauthenticated view.
	if access.Credential != nil {
		return buildgraph.RepositoryManifest{}, 0, errors.New("Debian endpoint verification does not support private read credentials")
	}
	manifest, blobs, err := verifyRepository(root)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	if manifest.Format != deb.FormatID {
		return buildgraph.RepositoryManifest{}, 0, fmt.Errorf("repository format is %q, not %q", manifest.Format, deb.FormatID)
	}
	if len(access.Routes) == 0 {
		access.Routes, err = defaultClientRoutes(access.Endpoint, manifest.Files)
		if err != nil {
			return buildgraph.RepositoryManifest{}, 0, err
		}
	}
	if err := awaitHostedBytes(ctx, access, "", "", false); err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	if runner == "" {
		runner = "podman"
	}
	runner, err = exec.LookPath(runner)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, fmt.Errorf("find container runner: %w", err)
	}
	if !digestPinnedImage(image) {
		return buildgraph.RepositoryManifest{}, 0, errors.New("a digest-pinned Debian verification image is required")
	}
	workspaceBytes, err := debWorkspaceSize(blobs, maxWorkspaceBytes)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}

	// apt needs the keyring as a local file, and the image ships no fetch tool,
	// so it is retrieved here. Doing so also proves the published keyring is
	// reachable and intact at the endpoint, which a mounted copy would not.
	trust, cleanup, err := fetchEndpointTrust(ctx, endpoint, manifest)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	defer cleanup()

	verificationCases := manifest.VerificationCases
	if len(verificationCases) == 0 {
		for _, architecture := range manifest.Install.Architectures {
			verificationCases = append(verificationCases, domain.VerificationCase{Architecture: architecture})
		}
	}
	// A loopback endpoint is the host's loopback, not the container's, so it is
	// only reachable with host networking. A public endpoint uses the runner's
	// default network and stays isolated from the host.
	hostNetwork := isLoopbackHost(endpoint.Hostname())
	for _, verification := range verificationCases {
		if err := verifyDebEndpointCase(ctx, runner, image, access.Endpoint, trust, hostNetwork, workspaceBytes, manifest, verification); err != nil {
			return buildgraph.RepositoryManifest{}, 0, err
		}
	}
	return manifest, len(manifest.VerificationCases), nil
}

// endpointTrust is what apt needs on local disk to trust the endpoint.
type endpointTrust struct {
	// keyringDirectory holds the repository's public keyring, empty when the
	// repository is unsigned.
	keyringDirectory string
	// keyringName is the file inside that directory.
	keyringName string
	// caBundle is a host PEM bundle apt uses to validate HTTPS, empty for a
	// plaintext loopback endpoint.
	caBundle string
}

// fetchEndpointTrust downloads the published signing keyring and locates a CA
// bundle, returning what has to be mounted into the verification container.
func fetchEndpointTrust(ctx context.Context, endpoint *url.URL, manifest buildgraph.RepositoryManifest) (endpointTrust, func(), error) {
	trust := endpointTrust{}
	noop := func() {}
	if endpoint.Scheme == "https" {
		trust.caBundle = systemCABundle()
		if trust.caBundle == "" {
			return endpointTrust{}, noop, errors.New(
				"Debian endpoint verification over HTTPS needs a system CA bundle to mount, because the pinned image ships none")
		}
	}
	keyPath := manifest.Install.SigningKeyPath
	if keyPath == "" {
		return trust, noop, nil
	}
	expected := ""
	for _, file := range manifest.Files {
		if file.Path == keyPath {
			expected = file.SHA256
			break
		}
	}
	if expected == "" {
		return endpointTrust{}, noop, fmt.Errorf("signing keyring %q is absent from the repository manifest", keyPath)
	}
	address, err := url.JoinPath(strings.TrimSuffix(endpoint.String(), "/")+"/", keyPath)
	if err != nil {
		return endpointTrust{}, noop, err
	}
	content, err := fetchBoundedBytes(ctx, address, maxKeyringSize)
	if err != nil {
		return endpointTrust{}, noop, fmt.Errorf("fetch published signing keyring: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expected {
		return endpointTrust{}, noop, errors.New("published signing keyring does not match the verified repository")
	}
	directory, err := os.MkdirTemp("", ".snailmail-deb-trust-*")
	if err != nil {
		return endpointTrust{}, noop, err
	}
	// The container reads this directory, so it must be traversable.
	if err := os.Chmod(directory, 0o755); err != nil {
		_ = os.RemoveAll(directory)
		return endpointTrust{}, noop, err
	}
	trust.keyringDirectory = directory
	trust.keyringName = filepath.Base(keyPath)
	if err := os.WriteFile(filepath.Join(directory, trust.keyringName), content, 0o644); err != nil {
		_ = os.RemoveAll(directory)
		return endpointTrust{}, noop, err
	}
	return trust, func() { _ = os.RemoveAll(directory) }, nil
}

const maxKeyringSize = 1 << 20

func fetchBoundedBytes(ctx context.Context, address string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("repository verification does not follow redirects")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", address, response.StatusCode)
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", address, maximum)
	}
	return content, nil
}

// systemCABundle finds a PEM bundle apt can validate HTTPS against. macOS keeps
// trust in the keychain rather than a file, so this is empty there and the
// caller reports the requirement rather than failing inside apt.
func systemCABundle() string {
	for _, candidate := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	} {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func verifyDebEndpointCase(ctx context.Context, runner, image, endpoint string, trust endpointTrust, hostNetwork bool, workspaceBytes int64, manifest buildgraph.RepositoryManifest, verification domain.VerificationCase) error {
	platform, err := debOCIPlatform(verification.Architecture)
	if err != nil {
		return err
	}
	caseCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	memoryBytes := workspaceBytes + 512<<20
	reference, platformFlag, err := platformImage(caseCtx, runner, image, platform)
	if err != nil {
		return err
	}
	arguments := []string{
		"run", "--rm", "--pull=missing",
		"--read-only", "--memory=" + strconv.FormatInt(memoryBytes, 10), "--cpus=2", "--pids-limit=256",
		"--ulimit", "fsize=536870912:536870912", "--ulimit", "nofile=1024:1024",
		"--security-opt", "no-new-privileges",
		"--env", "DEBIAN_FRONTEND=noninteractive",
		"--env", "SNAILMAIL_ENDPOINT=" + strings.TrimSuffix(endpoint, "/"),
		"--env", "SNAILMAIL_SUITE=" + manifest.Install.Suite,
		"--env", "SNAILMAIL_COMPONENT=" + manifest.Install.Component,
		"--env", "SNAILMAIL_ARCHITECTURE=" + verification.Architecture,
		"--env", "SNAILMAIL_PACKAGE=" + verification.Package,
		"--env", "SNAILMAIL_VERSION=" + verification.Version,
		"--env", "SNAILMAIL_KEYRING=" + trust.keyringName,
		"--tmpfs", "/tmp:rw,size=64m,mode=1777",
		// exec is explicit because runtimes mount tmpfs noexec by default and the
		// chroot below runs apt-get and dpkg-query out of this mount.
		"--tmpfs", "/target:rw,exec,size=" + strconv.FormatInt(workspaceBytes, 10) + ",mode=0755",
	}
	if hostNetwork {
		arguments = append(arguments, "--network=host")
	}
	if trust.keyringDirectory != "" {
		arguments = append(arguments, "--volume", trust.keyringDirectory+":/snailmail-trust:ro,Z")
	}
	if trust.caBundle != "" {
		arguments = append(arguments, "--volume", trust.caBundle+":/snailmail-ca.crt:ro")
	}
	if platformFlag {
		arguments = append(arguments, "--platform", platform)
	}
	arguments = append(arguments, reference, "sh", "-euc", debEndpointScript)

	command := exec.CommandContext(caseCtx, runner, arguments...)
	command.Env = runnerEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Debian endpoint verification for %s=%s/%s: %w\n%s",
			verification.Package, verification.Version, verification.Architecture, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// The chroot mirrors the mounted-directory case so both prove the same thing;
// only the source line and the trust material differ.
const debEndpointScript = `
for directory in bin etc lib lib64 sbin usr var; do
    test -e "/$directory" && cp -a "/$directory" /target/
done
mkdir -p /target/dev /target/proc /target/sys /target/tmp
chmod 1777 /target/tmp
: >/target/dev/null
rm -rf /target/etc/apt/sources.list.d/* /target/etc/apt/sources.list
mkdir -p /target/var/lib/apt/lists/partial /target/var/cache/apt/archives/partial
if test -f /snailmail-ca.crt; then
    mkdir -p /target/etc/ssl/certs
    cp /snailmail-ca.crt /target/etc/ssl/certs/ca-certificates.crt
fi
if test -n "$SNAILMAIL_KEYRING"; then
    mkdir -p /target/etc/apt/keyrings
    cp "/snailmail-trust/$SNAILMAIL_KEYRING" /target/etc/apt/keyrings/snailmail.gpg
    printf 'deb [signed-by=/etc/apt/keyrings/snailmail.gpg arch=%s] %s %s %s\n' \
        "$SNAILMAIL_ARCHITECTURE" "$SNAILMAIL_ENDPOINT" "$SNAILMAIL_SUITE" "$SNAILMAIL_COMPONENT" >/target/etc/apt/sources.list
else
    printf 'deb [trusted=yes arch=%s] %s %s %s\n' \
        "$SNAILMAIL_ARCHITECTURE" "$SNAILMAIL_ENDPOINT" "$SNAILMAIL_SUITE" "$SNAILMAIL_COMPONENT" >/target/etc/apt/sources.list
fi
chroot /target apt-get -o APT::Sandbox::User=root -o Acquire::Languages=none update
if test -n "$SNAILMAIL_PACKAGE"; then
    chroot /target apt-get -o APT::Sandbox::User=root install -y --reinstall --no-install-recommends "$SNAILMAIL_PACKAGE=$SNAILMAIL_VERSION"
    status=$(chroot /target dpkg-query -W -f='${Status} ${Version}' "$SNAILMAIL_PACKAGE")
    test "$status" = "install ok installed $SNAILMAIL_VERSION"
fi
`
