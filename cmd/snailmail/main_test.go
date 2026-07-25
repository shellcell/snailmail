package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/testutil"
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
