package engine

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/testutil"
)

func TestBuildPyPIIsByteDeterministic(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	firstOutput := filepath.Join(t.TempDir(), "repository")
	secondOutput := filepath.Join(t.TempDir(), "repository")
	first, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: firstOutput, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: secondOutput, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if first.TreeSHA256 != second.TreeSHA256 {
		t.Fatalf("tree digests differ: %s != %s", first.TreeSHA256, second.TreeSHA256)
	}
	firstFiles := readTree(t, firstOutput)
	secondFiles := readTree(t, secondOutput)
	if !reflect.DeepEqual(firstFiles, secondFiles) {
		t.Fatal("clean builds were not byte-identical")
	}
	if first.ProjectCount != 1 || first.DistributionCount != 1 {
		t.Fatalf("unexpected build result: %#v", first)
	}

	verified, err := VerifyPyPI(context.Background(), VerifyPyPIRequest{Repository: firstOutput, StructuralOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if verified.TreeSHA256 != first.TreeSHA256 {
		t.Fatal("verification returned a different tree digest")
	}
	info, err := os.Lstat(firstOutput)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("repository output is not an atomic release symlink")
	}
	previousRelease, err := filepath.EvalSymlinks(firstOutput)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: firstOutput, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	currentRelease, err := filepath.EvalSymlinks(firstOutput)
	if err != nil {
		t.Fatal(err)
	}
	if previousRelease == currentRelease {
		t.Fatal("rebuild did not switch to a new immutable release")
	}
	if rebuilt.TreeSHA256 != first.TreeSHA256 {
		t.Fatal("rebuild changed the deterministic tree digest")
	}
	if _, err := os.Stat(previousRelease); err != nil {
		t.Fatalf("previous release is not retained: %v", err)
	}
}

func TestVerifyAcceptsPhaseTwoRepositoryManifest(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ""); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(output, buildgraph.ManifestFilename)
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var manifest buildgraph.RepositoryManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SchemaVersion = 1
	content, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRepository(output); err != nil {
		t.Fatalf("phase-two repository could not be observed after upgrade: %v", err)
	}
}

func TestVerifyPyPIInstallsWithPip(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	if err := exec.Command(python, "-m", "pip", "--version").Run(); err != nil {
		t.Skip("pip is unavailable")
	}
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Support-Pkg", "2.0.0", ">=3.8"); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.WriteWheelWithDependencies(input, "Demo-Pkg", "1.2.3", ">=3.8", []string{"Support-Pkg == 2.0.0"}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyPyPI(context.Background(), VerifyPyPIRequest{Repository: output, Python: python})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstalledCases != 2 {
		t.Fatalf("installed %d cases, want 2", result.InstalledCases)
	}
}

func TestVerifyPyPIFailsWhenDependencyIsMissing(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	input := t.TempDir()
	if _, err := testutil.WriteWheelWithDependencies(input, "Demo-Pkg", "1.2.3", "", []string{"Missing-Pkg == 9.9.9"}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPyPI(context.Background(), VerifyPyPIRequest{Repository: output, Python: python}); err == nil {
		t.Fatal("expected missing dependency to fail client verification")
	}
}

func TestVerifyPyPIRejectsModifiedOutput(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ""); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(output, "simple", "index.html")
	if err := os.WriteFile(index, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPyPI(context.Background(), VerifyPyPIRequest{Repository: output, StructuralOnly: true}); err == nil {
		t.Fatal("expected modified output to fail verification")
	}
}

func TestVerifyPyPIRejectsManifestThatWaivesClientCases(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ""); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(output)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(release, buildgraph.ManifestFilename)
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest buildgraph.RepositoryManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.VerificationCases = nil
	content, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(manifestPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPyPI(context.Background(), VerifyPyPIRequest{Repository: output, StructuralOnly: true}); err == nil {
		t.Fatal("expected forged verification metadata to fail")
	}
}

func TestBuildPyPIRefusesUnmanagedOutput(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ""); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, "keep.txt"), []byte("user data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, buildgraph.ManifestFilename), []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPyPI(context.Background(), BuildPyPIRequest{Input: input, Output: output}); err == nil {
		t.Fatal("expected unmanaged output replacement to fail")
	}
}

func TestBuildDebIsByteDeterministic(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.3-1", "amd64", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.4-1", "amd64", nil); err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	firstOutput := filepath.Join(t.TempDir(), "repository")
	secondOutput := filepath.Join(t.TempDir(), "repository")
	request := BuildDebRequest{
		Input:         input,
		Suite:         "stable",
		Component:     "main",
		Architectures: []string{"amd64"},
		GeneratedAt:   generatedAt,
	}
	request.Output = firstOutput
	first, err := BuildDeb(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Output = secondOutput
	second, err := BuildDeb(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.TreeSHA256 != second.TreeSHA256 || !reflect.DeepEqual(readTree(t, firstOutput), readTree(t, secondOutput)) {
		t.Fatal("Debian repository builds were not byte-identical")
	}
	if first.PackageCount != 1 || first.DistributionCount != 2 {
		t.Fatalf("unexpected Debian build result: %#v", first)
	}
	verified, err := VerifyDeb(context.Background(), VerifyDebRequest{Repository: firstOutput, StructuralOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if verified.TreeSHA256 != first.TreeSHA256 {
		t.Fatal("Debian verification returned a different tree digest")
	}
}

func TestVerifyDebInstallsWithApt(t *testing.T) {
	runner := availableContainerRunner(t)
	architecture := hostDebianArchitecture(t)
	input := t.TempDir()
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.3-1", architecture, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.4-1", architecture, nil); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildDeb(context.Background(), BuildDebRequest{
		Input: input, Output: output, Suite: "stable", Component: "main", Architectures: []string{architecture},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyDeb(context.Background(), VerifyDebRequest{Repository: output, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstalledCases != 2 {
		t.Fatalf("verified %d Debian cases, want 2", result.InstalledCases)
	}
}

func TestVerifyDebRejectsModifiedIndex(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.3-1", "amd64", nil); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildDeb(context.Background(), BuildDebRequest{
		Input: input, Output: output, Suite: "stable", Component: "main", Architectures: []string{"amd64"},
	}); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(output)
	if err != nil {
		t.Fatal(err)
	}
	packages := filepath.Join(release, "dists", "stable", "main", "binary-amd64", "Packages")
	if err := os.WriteFile(packages, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeb(context.Background(), VerifyDebRequest{Repository: output, StructuralOnly: true}); err == nil {
		t.Fatal("expected modified Debian index to fail verification")
	}
}

func TestBuildHelmIsByteDeterministic(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, "snail-demo", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	firstOutput := filepath.Join(t.TempDir(), "repository")
	secondOutput := filepath.Join(t.TempDir(), "repository")
	first, err := BuildHelm(context.Background(), BuildHelmRequest{Input: input, Output: firstOutput, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildHelm(context.Background(), BuildHelmRequest{Input: input, Output: secondOutput, GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if first.TreeSHA256 != second.TreeSHA256 || !reflect.DeepEqual(readTree(t, firstOutput), readTree(t, secondOutput)) {
		t.Fatal("Helm repository builds were not byte-identical")
	}
	if first.PackageCount != 1 || first.DistributionCount != 1 {
		t.Fatalf("unexpected Helm build result: %#v", first)
	}
	verified, err := VerifyHelm(context.Background(), VerifyHelmRequest{Repository: firstOutput, StructuralOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if verified.TreeSHA256 != first.TreeSHA256 {
		t.Fatal("Helm verification returned a different tree digest")
	}
}

func TestVerifyHelmWithClient(t *testing.T) {
	runner := availableContainerRunner(t)
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, "snail-demo", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildHelm(context.Background(), BuildHelmRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyHelm(context.Background(), VerifyHelmRequest{Repository: output, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstalledCases != 1 {
		t.Fatalf("verified %d Helm cases, want 1", result.InstalledCases)
	}
}

func TestVerifyHelmRejectsModifiedIndex(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, "snail-demo", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	if _, err := BuildHelm(context.Background(), BuildHelmRequest{Input: input, Output: output}); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "index.yaml"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHelm(context.Background(), VerifyHelmRequest{Repository: output, StructuralOnly: true}); err == nil {
		t.Fatal("expected modified Helm index to fail verification")
	}
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = string(content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// availableContainerRunner finds a container runtime. Requiring podman
// specifically, and requiring the image to be present already, meant these
// tests skipped on any machine with only docker — which is most CI, and is why
// a noexec tmpfs broke this path unnoticed. --pull=missing fetches the image.
func availableContainerRunner(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("no container runner is available")
	return ""
}

// hostDebianArchitecture is the Debian name for the architecture these tests
// run on.
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
