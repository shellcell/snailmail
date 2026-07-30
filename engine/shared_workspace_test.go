package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

// The recommended topology is one workspace for an organisation, and it rests on a
// claim that is cheap to check and expensive to be wrong about: work in one
// repository does not touch another's file. If it did, two teams sharing a
// workspace would conflict on every publication and the recommendation would be
// backwards.
func sharedWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{
		Root: root, Name: "one-org", ForgeRepository: "acme/state",
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"team-a", "team-b"} {
		if err := SetupRepository(SetupRepositoryRequest{
			Root: root, Name: name, Format: "raw", HostType: "local",
			Output: "public/" + name, Visibility: "public", AllowUnsigned: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestOneTeamsWorkDoesNotTouchAnothersFile(t *testing.T) {
	root := sharedWorkspace(t)
	other := filepath.Join(root, "repos", "team-b.lock.toml")
	before, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(filepath.Join(root, "snailmail.toml"))
	if err != nil {
		t.Fatal(err)
	}

	input := t.TempDir()
	artifact := filepath.Join(input, "tool_1.0.0_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddArtifacts(AddArtifactsRequest{
		Root: root, Repository: "team-a", Artifacts: []string{artifact},
	}); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("publishing to one repository rewrote another's lock, so two teams would conflict on every change")
	}
	// The manifest is the one shared file, and it must not change either — it
	// records configuration, not publications. If adding an artifact rewrote it,
	// every publication would contend on it however the locks are arranged.
	manifestAfter, err := os.ReadFile(filepath.Join(root, "snailmail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifestBefore) != string(manifestAfter) {
		t.Error("adding an artifact rewrote snailmail.toml, so every team would contend on the one shared file")
	}
	// And the work that was asked for did happen, so this is not passing because
	// nothing was written anywhere.
	own, err := os.ReadFile(filepath.Join(root, "repos", "team-a.lock.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(own) == 0 || string(own) == string(before) {
		t.Error("the artifact was not recorded in its own repository's lock")
	}
}

// Each repository carries its own gate, which is what lets one workspace hold
// teams with different review requirements rather than imposing the strictest on
// everyone.
func TestEachRepositoryCarriesItsOwnGate(t *testing.T) {
	root := sharedWorkspace(t)
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "team-c", Format: "raw", HostType: "local",
		Output: "public/team-c", Visibility: "public", AllowUnsigned: true,
		Gate: "pr",
	}); err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Repositories["team-c"].Gate; got != "pr" {
		t.Errorf("team-c gate = %q, want the one it was configured with", got)
	}
	if manifest.Repositories["team-a"].Gate == "pr" {
		t.Error("configuring one repository's gate changed another's")
	}
}
