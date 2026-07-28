package engine

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/testutil"
)

// Verifying a repository built for another architecture is the case a
// digest-pinned multi-platform reference used to make impossible.
func TestVerifyDebInstallsForForeignArchitecture(t *testing.T) {
	runner := availableContainerRunner(t)
	foreign := "amd64"
	if runtime.GOARCH == "amd64" {
		foreign = "arm64"
	}
	input := t.TempDir()
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.3-1", foreign, nil); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildDeb(context.Background(), BuildDebRequest{
		Input: input, Output: output, Suite: "stable", Component: "main", Architectures: []string{foreign},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyDeb(context.Background(), VerifyDebRequest{Repository: output, Runner: runner})
	if errors.Is(err, app.ErrPlatformUnresolved) {
		// Selecting a foreign manifest out of a pinned index needs the registry;
		// without it nothing was checked, so there is nothing to report.
		t.Skipf("cannot resolve the %s image: %v", foreign, err)
	}
	if errors.Is(err, app.ErrForeignPlatformUnsupported) {
		// Resolving the image is not enough: executing it needs QEMU and
		// binfmt_misc, which Docker Desktop registers and a plain Linux runner
		// does not. That is a property of the host, not of the repository.
		t.Skipf("host cannot execute %s containers: %v", foreign, err)
	}
	if err != nil {
		t.Fatalf("verifying a %s repository from %s failed: %v", foreign, runtime.GOARCH, err)
	}
	if result.InstalledCases != 1 {
		t.Fatalf("verified %d cases, want 1", result.InstalledCases)
	}
}
