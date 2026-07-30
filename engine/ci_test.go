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
	return ciTemplateFor(t, "github", formats...)
}

func ciTemplateFor(t *testing.T, provider string, formats ...string) string {
	t.Helper()
	root := multiRepositoryWorkspace(t, formats...)
	workflow, err := CIWorkflow(CIWorkflowRequest{Root: root, Version: "v1.2.3", Provider: provider})
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
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to parse the YAML")
	}
	// Each provider's document is shaped differently, so each is checked against
	// the shape its CI system actually requires rather than merely for parsing.
	for provider, assertion := range map[string]string{
		"github": `
steps = document["jobs"]["publish"]["steps"]
assert steps, "no steps"
print(len(steps))
`,
		"gitlab": `
assert document["stages"], "no stages"
publish = document["publish"]
assert publish["script"], "no script"
# GitLab serves the artifact of a job that has to be called "pages", and jobs do
# not share a filesystem, so the built trees have to be declared as an artifact
# by the job that built them.
pages = document["pages"]
assert pages["artifacts"]["paths"] == ["public"], pages["artifacts"]
assert publish["artifacts"]["paths"], "the pages job is given nothing to serve"
assert publish["stage"] in document["stages"]
assert pages["stage"] in document["stages"]
print(len(publish["script"]))
`,
	} {
		t.Run(provider, func(t *testing.T) {
			template := ciTemplateFor(t, provider, "deb", "helm")
			file := filepath.Join(t.TempDir(), "pipeline.yml")
			if err := os.WriteFile(file, []byte(template), 0o644); err != nil {
				t.Fatal(err)
			}
			parse := exec.Command(python, "-c", "import sys, yaml\ndocument = yaml.safe_load(open(sys.argv[1]))"+assertion, file)
			output, err := parse.CombinedOutput()
			if err != nil {
				if strings.Contains(string(output), "ModuleNotFoundError") {
					t.Skip("pyyaml is needed to parse the YAML")
				}
				t.Fatalf("generated %s template is malformed: %v\n%s", provider, err, output)
			}
			t.Logf("%s: parsed %s steps", provider, strings.TrimSpace(string(output)))
		})
	}
}

// The two templates describe one workspace, so they must agree about it. A
// difference here would mean an operator moving between CI systems gets a
// pipeline that signs different repositories or emulates different
// architectures.
func TestBothTemplatesDeriveTheSameWorkspace(t *testing.T) {
	root := multiRepositoryWorkspace(t, "deb", "helm")
	var rendered []string
	for _, provider := range []string{"github", "gitlab"} {
		template, err := CIWorkflow(CIWorkflowRequest{Root: root, Version: "v1.2.3", Provider: provider})
		if err != nil {
			t.Fatal(err)
		}
		rendered = append(rendered, string(template))
	}
	for _, repository := range []string{"deb", "helm"} {
		for index, template := range rendered {
			if !strings.Contains(template, repository) {
				t.Errorf("template %d does not mention repository %q", index, repository)
			}
		}
	}
	// Neither is signed in this fixture, so neither may ask for key material.
	for index, template := range rendered {
		if strings.Contains(template, "SNAILMAIL_KEY_") {
			t.Errorf("template %d materialises keys for an unsigned workspace", index)
		}
	}
}

func TestCITemplateRefusesAnUnknownProvider(t *testing.T) {
	root := multiRepositoryWorkspace(t, "deb")
	_, err := CIWorkflow(CIWorkflowRequest{Root: root, Provider: "jenkins"})
	if err == nil || !strings.Contains(err.Error(), "jenkins") {
		t.Errorf("error = %v, want the unsupported provider named", err)
	}
}

// The GitLab site job assembles into the directory GitLab serves, and the
// repositories are published wherever the manifest says. When those are already
// the same directory, clearing it would delete what apply just built.
func TestGitLabPagesDoesNotClearTheDirectoryItPublishesFrom(t *testing.T) {
	if script := gitlabPagesJob("public", []string{"raw"}); strings.Contains(script, "rm -rf public") {
		t.Error("a workspace publishing into public/ has its published tree deleted before it is served")
	}
	// And when they differ, the copy has to happen.
	script := gitlabPagesJob("docs", []string{"raw"})
	if !strings.Contains(script, "rm -rf public") || !strings.Contains(script, "docs/*/") {
		t.Errorf("a workspace publishing into docs/ does not copy across:\n%s", script)
	}
}
