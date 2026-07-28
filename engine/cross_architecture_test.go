package engine

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

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
	if err != nil {
		t.Fatalf("verifying a %s repository from %s failed: %v", foreign, runtime.GOARCH, err)
	}
	if result.InstalledCases != 1 {
		t.Fatalf("verified %d cases, want 1", result.InstalledCases)
	}
}
