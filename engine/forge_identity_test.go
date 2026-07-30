package engine

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/internal/state"
)

func workspaceNamingAForge(t *testing.T, provider, repository, host string) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{
		Root: root, Name: "forge-identity",
		Forge: provider, ForgeRepository: repository, ForgeHost: host,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// The plan pins the forge the way it already pins the forge repository. The whole
// manifest is digested too, so this is defence in depth rather than the only
// guard — but it is only defence at all if the payload carries the values. A
// payload that dropped them would compare two empty strings and pass whatever the
// manifest said.
func TestThePlanCarriesTheForgeItWasPlannedAgainst(t *testing.T) {
	root := workspaceNamingAForge(t, forge.ProviderGitHub, "acme/state", "github.acme.example")
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "raw", Format: "raw", HostType: "local",
		Output: "public/raw", Visibility: "public", AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", "-A").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	commit := exec.Command("git", "-C", root, "commit", "-m", "workspace")
	commit.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	planned, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.LoadPlan(planned.Output)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Payload.Forge != forge.ProviderGitHub {
		t.Errorf("the plan recorded forge %q, want %q", plan.Payload.Forge, forge.ProviderGitHub)
	}
	if plan.Payload.ForgeRepository != "acme/state" {
		t.Errorf("the plan recorded repository %q", plan.Payload.ForgeRepository)
	}
	if plan.Payload.ForgeHost != "github.acme.example" {
		t.Errorf("the plan recorded host %q", plan.Payload.ForgeHost)
	}
}

// An Enterprise or self-hosted instance is the case the host field exists for,
// and it has to survive a round trip through the manifest file rather than only
// through the struct.
func TestAForgeHostSurvivesTheManifest(t *testing.T) {
	root := workspaceNamingAForge(t, forge.ProviderGitea, "acme/state", "git.acme.example")
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatalf("a self-hosted forge failed to reload: %v", err)
	}
	if manifest.Workspace.ForgeHost != "git.acme.example" {
		t.Errorf("host round-tripped as %q", manifest.Workspace.ForgeHost)
	}
}

// A workspace initialized without any forge is the common case and the one every
// existing workspace is in.
func TestInitWithoutAForgeStillWorks(t *testing.T) {
	root := workspaceNamingAForge(t, "", "", "")
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Workspace.Forge != "" || manifest.Workspace.ForgeHost != "" {
		t.Errorf("init invented a forge: %+v", manifest.Workspace)
	}
}

// A misconfiguration has to be refused when the workspace is created, not when a
// publication is being authorized months later.
func TestInitRefusesAForgeItCannotUse(t *testing.T) {
	for name, request := range map[string]InitWorkspaceRequest{
		"unknown forge":              {Forge: "gitbucket", ForgeRepository: "acme/state"},
		"nested on github":           {Forge: forge.ProviderGitHub, ForgeRepository: "acme/team/state"},
		"self-hosted, no host":       {Forge: forge.ProviderForgejo, ForgeRepository: "acme/state"},
		"forge with nothing to read": {Forge: forge.ProviderGitLab},
		"unusable host": {Forge: forge.ProviderGitHub, ForgeRepository: "acme/state",
			ForgeHost: "git.acme.example/api"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
				t.Fatalf("git init: %v: %s", err, output)
			}
			request.Root, request.Name = root, "forge-identity"
			if err := InitWorkspace(request); err == nil {
				t.Fatal("the workspace was created with a forge it cannot use")
			}
		})
	}
}

// GitLab's nested groups are the shape GitHub cannot address, and the reason
// selecting a provider by the shape of its reference was wrong.
func TestAGitLabWorkspaceAcceptsANestedGroup(t *testing.T) {
	root := workspaceNamingAForge(t, forge.ProviderGitLab, "acme/platform/tools/state", "")
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatalf("a nested GitLab group was refused: %v", err)
	}
	if !strings.Contains(manifest.Workspace.ForgeRepository, "/platform/") {
		t.Errorf("the nested reference round-tripped as %q", manifest.Workspace.ForgeRepository)
	}
}
