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

// VerifyRPMClient checks a yum repository by having dnf install from it.
//
// Structural verification proves the indexes describe the packages that are
// there. It cannot prove dnf agrees: a checksum in the wrong element, a
// namespace it does not recognise, or a location it resolves differently all
// produce a tree that looks correct and refuses to install. Only the client
// settles that.
func VerifyRPMClient(ctx context.Context, repository, runner, image string) (buildgraph.RepositoryManifest, int, error) {
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
	// The client reads a snapshot rather than the release directory, so a
	// publication switching underneath it cannot change what was verified.
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
		return buildgraph.RepositoryManifest{}, 0, errors.New("a digest-pinned RPM verification image is required")
	}
	installed := 0
	for _, verification := range manifest.VerificationCases {
		if err := verifyRPMCase(ctx, runner, image, snapshot, verification); err != nil {
			return buildgraph.RepositoryManifest{}, 0, err
		}
		installed++
	}
	return manifest, installed, nil
}

func verifyRPMCase(ctx context.Context, runner, image, snapshot string, verification domain.VerificationCase) error {
	caseCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	platform, err := rpmOCIPlatform(verification.Architecture)
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
		"--memory=2g", "--cpus=2", "--pids-limit=256",
		"--ulimit", "fsize=536870912:536870912", "--ulimit", "nofile=4096:4096",
		"--security-opt", "no-new-privileges",
		"--volume", snapshot+":/target/repo:ro,Z",
		"--env", "SNAILMAIL_PACKAGE="+verification.Package,
		"--env", "SNAILMAIL_VERSION="+verification.Version,
		// exec is explicit because runtimes mount tmpfs noexec by default and
		// dnf runs scriptlets out of its working directories.
		"--tmpfs", "/tmp:rw,exec,size=256m,mode=1777",
		"--tmpfs", "/var/cache/dnf:rw,exec,size=512m,mode=0755",
		reference,
		"sh", "-euc", rpmVerificationScript,
	)
	command := exec.CommandContext(caseCtx, runner, arguments...)
	command.Env = runnerEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		if foreignPlatformUnsupported(output) {
			return fmt.Errorf("%w: verifying %s needs QEMU and binfmt_misc registered for it",
				ErrForeignPlatformUnsupported, verification.Architecture)
		}
		return fmt.Errorf("RPM client verification for %s=%s/%s: %w\n%s",
			verification.Package, verification.Version, verification.Architecture, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// rpmOCIPlatform maps an RPM architecture to the platform a client must run as.
// noarch runs anywhere, so it asks for nothing and the host decides.
func rpmOCIPlatform(architecture string) (string, error) {
	switch architecture {
	case "", "noarch":
		return "", nil
	case "x86_64":
		return "linux/amd64", nil
	case "aarch64":
		return "linux/arm64", nil
	case "ppc64le":
		return "linux/ppc64le", nil
	case "s390x":
		return "linux/s390x", nil
	case "i686":
		return "linux/386", nil
	default:
		return "", fmt.Errorf("no OCI platform mapping for RPM architecture %q", architecture)
	}
}

// rpmVerificationScript configures the built tree as the only repository and
// installs from it. Every other repository is disabled so the package can only
// come from the tree under test, and gpgcheck is off because signing a yum
// repository is not implemented yet — which is exactly what the knowledge
// bundle records.
const rpmVerificationScript = `
cat > /etc/yum.repos.d/snailmail.repo <<'REPO'
[snailmail]
name=snailmail repository under verification
baseurl=file:///target/repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
REPO
dnf --quiet --disablerepo='*' --enablerepo=snailmail makecache >/dev/null
test -n "$SNAILMAIL_PACKAGE"
dnf --quiet --disablerepo='*' --enablerepo=snailmail install -y "$SNAILMAIL_PACKAGE" >/dev/null
# The installed version must be the one the index advertised, or the client
# resolved something other than what was published.
installed=$(rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' "$SNAILMAIL_PACKAGE")
expected="$SNAILMAIL_VERSION"
case "$installed" in
    "(none):"*) installed=${installed#(none):} ;;
esac
test "$installed" = "$expected" || {
    echo "installed $installed, index advertised $expected" >&2
    exit 1
}
`
