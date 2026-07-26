package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/engine"
	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

func TestBuildAndVerifyOutputUsesProductIcons(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "Demo-Pkg", "1.2.3", ""); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"build", "pypi", "--input", input, "--output", output}, &stdout, &stderr); err != nil {
		t.Fatalf("build failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	if err := run(context.Background(), []string{"verify", "pypi", "--repo", output, "--structural-only"}, &stdout, &stderr); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())
}

func TestUsageUsesSnailIcon(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "🐌") {
		t.Fatalf("usage did not include snail icon: %q", output.String())
	}
}

func TestKeysRotateRequiresExplicitTransitionArguments(t *testing.T) {
	for name, arguments := range map[string][]string{
		"repository":   {"keys", "rotate"},
		"successor":    {"keys", "rotate", "debian"},
		"confirmation": {"keys", "rotate", "debian", "--advance"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(context.Background(), arguments, &stdout, &stderr); err == nil {
				t.Fatalf("rotation arguments unexpectedly accepted: %v", arguments)
			}
		})
	}
}

func TestPlacementCommandsRequireUnambiguousCoordinates(t *testing.T) {
	for name, arguments := range map[string][]string{
		"promote coordinates": {"promote", "python", "demo"},
		"yank selector":       {"yank", "python", "demo", "1.2.3"},
		"yank one selector":   {"yank", "--track", "stable", "--all", "python", "demo", "1.2.3"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(context.Background(), arguments, &stdout, &stderr); err == nil {
				t.Fatalf("placement arguments unexpectedly accepted: %v", arguments)
			}
		})
	}
}

func TestPruneRequiresPositiveRetention(t *testing.T) {
	for _, arguments := range [][]string{
		{"prune"},
		{"prune", "python"},
		{"prune", "python", "--keep", "0"},
		{"prune", "python", "--keep", "-1"},
		{"prune", "python", "--keep", "2", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), arguments, &stdout, &stderr); err == nil {
			t.Fatalf("prune arguments unexpectedly accepted: %v", arguments)
		}
	}
}

func TestCheckRejectsUnexpectedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"check", "repository"}, &stdout, &stderr); err == nil {
		t.Fatal("check accepted an unexpected repository selector")
	}
}

func TestCheckReportsReadOnlyAuditScope(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := engine.InitWorkspace(engine.InitWorkspaceRequest{Root: root, Name: "cli-check"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.SetupRepository(engine.SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"check", "--workspace", root}, &stdout, &stderr); err != nil {
		t.Fatalf("check failed: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "checked 1 repository, 0 package versions, and 0 locked artifacts") ||
		!strings.Contains(stdout.String(), "upstream release checks unavailable") {
		t.Fatalf("unexpected check output %q", stdout.String())
	}
}

func TestStatusEmitsMachineReadableCommittedEvidence(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := engine.InitWorkspace(engine.InitWorkspaceRequest{Root: root, Name: "cli-status"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.SetupRepository(engine.SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", "-A").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", root, "-c", "user.name=Snailmail", "-c", "user.email=snailmail@example.invalid", "commit", "-m", "initialize").CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"status", "--workspace", root, "--json"}, &stdout, &stderr); err != nil {
		t.Fatalf("status failed: %v\n%s", err, stderr.String())
	}
	var document struct {
		Workspace        string `json:"workspace"`
		ObservationScope string `json:"observation_scope"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode status JSON: %v: %s", err, stdout.String())
	}
	if document.Workspace != "cli-status" || document.ObservationScope != "committed workspace evidence only" || strings.Contains(stdout.String(), "🐌") {
		t.Fatalf("unexpected status JSON %q", stdout.String())
	}
	firstJSON := stdout.String()
	stdout.Reset()
	if err := run(context.Background(), []string{"status", "--workspace", root, "--json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != firstJSON || !strings.Contains(firstJSON, `"visible_packages": []`) {
		t.Fatalf("status JSON is not deterministic or canonical: %q", stdout.String())
	}
	stdout.Reset()
	if err := run(context.Background(), []string{"status", "--workspace", root}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "live hosts, upstream releases") {
		t.Fatalf("status omitted observation scope: %q", stdout.String())
	}
}

func TestStatusRejectsUnexpectedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"status", "repository"}, &stdout, &stderr); err == nil {
		t.Fatal("status accepted a repository selector")
	}
}

func TestDoctorEmitsUnbrandedJSONWithoutWorkspace(t *testing.T) {
	fetcher := cliDoctorFetcher{response: source.Response{
		URL: "https://packages.example/simple/", StatusCode: 200, ContentType: "text/html",
		Body: []byte(`<html><body><a href="demo/">demo</a></body></html>`),
	}}
	var stdout, stderr bytes.Buffer
	if err := runDoctorWithFetcher(context.Background(), []string{"--format", "pypi", "--json", "https://packages.example"}, &stdout, &stderr, fetcher); err != nil {
		t.Fatal(err)
	}
	var result engine.DoctorResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode doctor JSON: %v: %s", err, stdout.String())
	}
	if result.Format != "pypi" || result.Entries != 1 || len(result.Findings) != 1 || result.Findings[0].Code != "scope.project-required" || strings.Contains(stdout.String(), "🐌") {
		t.Fatalf("unexpected doctor result %#v", result)
	}
}

func TestDoctorRequiresOneURL(t *testing.T) {
	for _, arguments := range [][]string{{"doctor"}, {"doctor", "https://one.example", "https://two.example"}} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), arguments, &stdout, &stderr); err == nil {
			t.Fatalf("doctor arguments accepted: %v", arguments)
		}
	}
}

func TestDoctorPrintsJSONBeforeUnhealthyExit(t *testing.T) {
	fetcher := cliDoctorFetcher{response: source.Response{URL: "https://packages.example/index.yaml", StatusCode: 404}}
	var stdout, stderr bytes.Buffer
	err := runDoctorWithFetcher(context.Background(), []string{"--format", "helm", "--json", "https://packages.example"}, &stdout, &stderr, fetcher)
	if err == nil {
		t.Fatal("doctor accepted a missing index")
	}
	var result engine.DoctorResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil || len(result.Findings) != 1 || result.Findings[0].Code != "index.missing" {
		t.Fatalf("doctor JSON=%q decode=%v result=%#v", stdout.String(), jsonErr, result)
	}
}

func TestDoctorPrintsMalformedIndexAsJSONFinding(t *testing.T) {
	fetcher := cliDoctorFetcher{response: source.Response{URL: "https://packages.example/index.yaml", StatusCode: 200, Body: []byte("not: [valid")}}
	var stdout, stderr bytes.Buffer
	err := runDoctorWithFetcher(context.Background(), []string{"--format", "helm", "--json", "https://packages.example"}, &stdout, &stderr, fetcher)
	if err == nil {
		t.Fatal("doctor accepted a malformed index")
	}
	var result engine.DoctorResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil || len(result.Findings) != 1 || result.Findings[0].Code != "index.invalid" {
		t.Fatalf("doctor malformed JSON=%q decode=%v result=%#v", stdout.String(), jsonErr, result)
	}
}

type cliDoctorFetcher struct{ response source.Response }

func (fetcher cliDoctorFetcher) Fetch(context.Context, string, int64) (source.Response, error) {
	return fetcher.response, nil
}

func TestDebBuildAndVerifyOutputUsesProductIcons(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteDeb(input, "snail-demo", "1.2.3-1", "amd64", nil); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"build", "deb", "--input", input, "--output", output, "--architectures", "amd64"}, &stdout, &stderr); err != nil {
		t.Fatalf("Debian build failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())
	stdout.Reset()
	stderr.Reset()
	if err := run(context.Background(), []string{"verify", "deb", "--repo", output, "--structural-only"}, &stdout, &stderr); err != nil {
		t.Fatalf("Debian verify failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())
}

func TestHelmBuildAndVerifyOutputUsesProductIcons(t *testing.T) {
	input := t.TempDir()
	if _, err := testutil.WriteHelmChart(input, "snail-demo", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "repository")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"build", "helm", "--input", input, "--output", output}, &stdout, &stderr); err != nil {
		t.Fatalf("Helm build failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())
	stdout.Reset()
	stderr.Reset()
	if err := run(context.Background(), []string{"verify", "helm", "--repo", output, "--structural-only"}, &stdout, &stderr); err != nil {
		t.Fatalf("Helm verify failed: %v\n%s", err, stderr.String())
	}
	assertIcons(t, stdout.String())
}

func assertIcons(t *testing.T, output string) {
	t.Helper()
	for _, icon := range []string{"🐌", "✉️", "📦"} {
		if !strings.Contains(output, icon) {
			t.Fatalf("output did not include %s: %q", icon, output)
		}
	}
}
