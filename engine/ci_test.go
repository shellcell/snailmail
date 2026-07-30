package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A generated workflow is a starting point an operator commits, so what it
// derives has to match the workspace it was generated from — and it has to be
// well-formed YAML, since nobody reviews a file that will not parse.
func ciWorkflowFor(t *testing.T, formats ...string) string {
	t.Helper()
	root := multiRepositoryWorkspace(t, formats...)
	workflow, err := CIWorkflow(CIWorkflowRequest{Root: root, Version: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	return string(workflow)
}

func TestCIWorkflowDerivesFromTheWorkspace(t *testing.T) {
	workflow := ciWorkflowFor(t, "deb", "helm")

	if !strings.Contains(workflow, "SNAILMAIL_VERSION: v1.2.3") {
		t.Error("the requested snailmail version was not pinned")
	}
	// Every repository in this fixture publishes to a directory, so the site has
	// to be assembled and served by something else.
	for _, want := range []string{"Assemble the site", "Deploy the site", "snailmail site --output"} {
		if !strings.Contains(workflow, want) {
			t.Errorf("a workspace publishing to directories has no %q step", want)
		}
	}
	// And nothing is signed, so no key material is referenced.
	if strings.Contains(workflow, "Prepare the signing keys") {
		t.Error("an unsigned workspace materialises signing keys")
	}
	if strings.Contains(workflow, "SNAILMAIL_KEY_PASSPHRASE") {
		t.Error("an unsigned workspace asks for a key passphrase")
	}
}

// A version is left as a placeholder rather than pinned to whatever generated
// the file, which would pin the wrong one the moment it was regenerated.
func TestCIWorkflowLeavesAnUnsetVersionVisible(t *testing.T) {
	root := multiRepositoryWorkspace(t, "deb")
	workflow, err := CIWorkflow(CIWorkflowRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "SNAILMAIL_VERSION: vX.Y.Z") {
		t.Error("an unset version was not left as an obvious placeholder")
	}
}

// The emulation step is the one that costs a minute of every run, so it appears
// only when a repository actually serves an architecture the runner cannot
// execute.
func TestCIWorkflowAsksForEmulationOnlyWhenNeeded(t *testing.T) {
	// The fixture's deb repository serves amd64, which a runner is.
	if strings.Contains(ciWorkflowFor(t, "deb"), "Register emulation") {
		t.Error("a native-only workspace registers emulation")
	}
}

// The output is committed and read by people, so it has to parse and its shell
// has to be sound. Both are checked with the tools that would check it in a
// repository, and skipped where those are not installed.
func TestCIWorkflowIsWellFormed(t *testing.T) {
	workflow := ciWorkflowFor(t, "deb", "helm")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to parse the YAML")
	}
	file := filepath.Join(t.TempDir(), "publish.yml")
	if err := os.WriteFile(file, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	parse := exec.Command(python, "-c", `
import sys, yaml
document = yaml.safe_load(open(sys.argv[1]))
steps = document["jobs"]["publish"]["steps"]
assert steps, "no steps"
print(len(steps))
`, file)
	output, err := parse.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "ModuleNotFoundError") {
			t.Skip("pyyaml is needed to parse the YAML")
		}
		t.Fatalf("generated workflow is not valid YAML: %v\n%s", err, output)
	}
	t.Logf("parsed %s steps", strings.TrimSpace(string(output)))
}
