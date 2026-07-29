package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/domain"
)

// VerifyAPKClient checks an Alpine repository by having apk install from it.
//
// The index carries a control-stream checksum for every package, and apk
// refuses anything whose bytes disagree with it. Structural verification cannot
// reach that: it would need to recompute a hash over a gzip member boundary,
// which is precisely the thing most likely to be wrong. The client settles it.
func VerifyAPKClient(ctx context.Context, repository, runner, image string, scope VersionScope) (buildgraph.RepositoryManifest, int, error) {
	release, err := filepath.Abs(repository)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, fmt.Errorf("resolve repository: %w", err)
	}
	release, err = filepath.EvalSymlinks(release)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, fmt.Errorf("resolve repository release: %w", err)
	}
	manifest, _, err := verifyRepository(release)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	snapshot, err := snapshotRepository(ctx, release, manifest)
	if err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	defer os.RemoveAll(snapshot)
	manifest, _, err = verifyRepository(snapshot)
	if err != nil {
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
		return buildgraph.RepositoryManifest{}, 0, errors.New("a digest-pinned Alpine verification image is required")
	}
	verificationCases := scope.selection(manifest.VerificationCases, apkCompare)
	if err := verifyCases(ctx, verificationCases, func(caseCtx context.Context, verification domain.VerificationCase) error {
		return verifyAPKCase(caseCtx, runner, image, snapshot, verification)
	}); err != nil {
		return buildgraph.RepositoryManifest{}, 0, err
	}
	return manifest, len(verificationCases), nil
}

func verifyAPKCase(ctx context.Context, runner, image, snapshot string, verification domain.VerificationCase) error {
	caseCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	platform, err := apkOCIPlatform(verification.Architecture)
	if err != nil {
		return err
	}
	reference, platformFlag := image, false
	if platform != "" {
		reference, platformFlag, err = platformImage(caseCtx, runner, image, platform)
		if err != nil {
			return err
		}
	}
	arguments := []string{"run", "--rm", "--pull=missing", "--network=none"}
	if platformFlag {
		arguments = append(arguments, "--platform", platform)
	}
	arguments = append(arguments,
		"--memory=1g", "--cpus=2", "--pids-limit=256",
		"--ulimit", "fsize=536870912:536870912", "--ulimit", "nofile=1024:1024",
		"--security-opt", "no-new-privileges",
		"--volume", snapshot+":/target/repo:ro,Z",
		"--env", "SNAILMAIL_PACKAGE="+verification.Package,
		"--env", "SNAILMAIL_VERSION="+verification.Version,
		"--tmpfs", "/tmp:rw,exec,size=64m,mode=1777",
		reference,
		"sh", "-euc", apkVerificationScript,
	)
	command := exec.CommandContext(caseCtx, runner, arguments...)
	command.Env = runnerEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		if registryUnavailable(output) {
			return fmt.Errorf("%w: %s", ErrVerificationImageUnavailable, strings.TrimSpace(string(output)))
		}
		if foreignPlatformUnsupported(output) {
			return fmt.Errorf("%w: verifying %s needs QEMU and binfmt_misc registered for it",
				ErrForeignPlatformUnsupported, verification.Architecture)
		}
		return fmt.Errorf("Alpine client verification for %s=%s/%s: %w\n%s",
			verification.Package, verification.Version, verification.Architecture, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// apkOCIPlatform maps an Alpine architecture to the platform a client must run
// as. noarch runs anywhere, so it asks for nothing.
func apkOCIPlatform(architecture string) (string, error) {
	switch architecture {
	case "", "noarch":
		return "", nil
	case "x86_64":
		return "linux/amd64", nil
	case "aarch64":
		return "linux/arm64", nil
	case "armv7":
		return "linux/arm/v7", nil
	case "x86":
		return "linux/386", nil
	case "ppc64le":
		return "linux/ppc64le", nil
	case "s390x":
		return "linux/s390x", nil
	default:
		return "", fmt.Errorf("no OCI platform mapping for Alpine architecture %q", architecture)
	}
}

// apkVerificationScript installs from the built tree alone. --allow-untrusted
// because signing an APKINDEX is not implemented yet, and --repositories-file
// so the distribution's own repositories cannot satisfy the request instead.
const apkVerificationScript = `
echo /target/repo > /tmp/repositories
test -n "$SNAILMAIL_PACKAGE"
# The request is pinned to the version under verification. Asking for the bare
# name installs whatever is newest, which silently verifies the wrong package as
# soon as the repository carries more than one version of it.
apk --repositories-file /tmp/repositories --allow-untrusted --no-cache \
    add "${SNAILMAIL_PACKAGE}=${SNAILMAIL_VERSION}" >/dev/null
# The installed version must be the one the index advertised, or apk resolved
# something other than what was published. "apk info -v" with a package name
# prints its description rather than its version; with no name it lists every
# installed package as name-version, which is the form to match exactly.
expected="${SNAILMAIL_PACKAGE}-${SNAILMAIL_VERSION}"
apk info -v | grep -qx "$expected" || {
    echo "index advertised $expected, which is not installed:" >&2
    apk info -v | grep "^${SNAILMAIL_PACKAGE}-" >&2 || true
    exit 1
}
`
