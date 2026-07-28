package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// PLAN.md §13: "--json on everything, so CI is the CLI in a container."
// Whatever a command prints under --json has to be a single JSON document, or
// a caller cannot consume it.
func TestJSONOutputIsAlwaysOneDocument(t *testing.T) {
	for _, arguments := range [][]string{
		{"approval-key", "generate", "--out", "", "--json"},
	} {
		var stdout, stderr bytes.Buffer
		_ = run(context.Background(), arguments, &stdout, &stderr)
		if stdout.Len() == 0 {
			continue
		}
		var document any
		if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
			t.Errorf("%v produced non-JSON stdout %q: %v", arguments, stdout.String(), err)
		}
	}
}

// The documented invocation puts the subcommand before its flags. Go's flag
// package stops parsing at the first non-flag argument, so parsing the whole
// tail silently discarded --out and rejected the form the README shows.
func TestApprovalKeyAcceptsSubcommandBeforeFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"approval-key", "generate", "--out", t.TempDir() + "/key.json"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("documented invocation failed: %v (%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "generated Ed25519 approval key") {
		t.Fatalf("unexpected output %q", stdout.String())
	}
}

func TestApprovalKeyStillRejectsMissingOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"approval-key", "generate"}, &stdout, &stderr); err == nil {
		t.Fatal("expected a missing --out to be rejected")
	}
	if err := run(context.Background(), []string{"approval-key", "unknown"}, &stdout, &stderr); err == nil {
		t.Fatal("expected an unknown subcommand to be rejected")
	}
}
