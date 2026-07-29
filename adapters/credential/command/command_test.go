package commandcredential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/host"

	"github.com/shellcell/snailmail/internal/hexdigest"
)

const helperModeEnvironment = "SNAILMAIL_BROKER_TEST_MODE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperModeEnvironment); mode != "" {
		runCredentialHelper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestBrokerIssuesAndDestroysBoundCredential(t *testing.T) {
	broker := newTestBroker(t, "valid")
	if !hexdigest.ValidSHA256(broker.Identity()) {
		t.Fatalf("invalid broker identity %q", broker.Identity())
	}
	credential, err := broker.Issue(context.Background(), validScope())
	if err != nil {
		t.Fatal(err)
	}
	username, password, err := credential.Basic(context.Background())
	if err != nil || username != "reader" || password != "topsecret" {
		t.Fatalf("credential username=%q password=%q err=%v", username, password, err)
	}
	credential.Destroy()
	if _, _, err := credential.Basic(context.Background()); err == nil {
		t.Fatal("destroyed credential remained usable")
	}
}

func TestBrokerExecutesHashedFileAfterPathReplacement(t *testing.T) {
	helper := copyExecutable(t, os.Args[0])
	t.Setenv(HelperEnvironment, helper)
	t.Setenv(helperModeEnvironment, "valid")
	broker, err := NewFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	replacement := helper + ".replacement"
	if err := os.WriteFile(replacement, []byte("replaced"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, helper); err != nil {
		t.Fatal(err)
	}
	credential, err := broker.Issue(context.Background(), validScope())
	if err != nil {
		t.Fatalf("issue through retained executable: %v", err)
	}
	credential.Destroy()
}

func TestBrokerExecutesSnapshotAfterInPlaceMutation(t *testing.T) {
	helper := copyExecutable(t, os.Args[0])
	t.Setenv(HelperEnvironment, helper)
	t.Setenv(helperModeEnvironment, "valid")
	broker, err := NewFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	if err := os.WriteFile(helper, []byte("mutated"), 0o700); err != nil {
		t.Fatal(err)
	}
	credential, err := broker.Issue(context.Background(), validScope())
	if err != nil {
		t.Fatalf("issue through immutable executable snapshot: %v", err)
	}
	credential.Destroy()
}

func TestBrokerRejectsInvalidScopes(t *testing.T) {
	broker := newTestBroker(t, "valid")
	for name, mutate := range map[string]func(*host.ReadScope){
		"workspace": func(scope *host.ReadScope) { scope.WorkspaceID = "bad" },
		"host":      func(scope *host.ReadScope) { scope.HostIdentity = "bad" },
		"plan":      func(scope *host.ReadScope) { scope.PlanID = "bad" },
		"tree":      func(scope *host.ReadScope) { scope.TreeSHA256 = "bad" },
		"prefix":    func(scope *host.ReadScope) { scope.Prefixes = []string{"bad\nvalue"} },
	} {
		t.Run(name, func(t *testing.T) {
			scope := validScope()
			mutate(&scope)
			if _, err := broker.Issue(context.Background(), scope); err == nil {
				t.Fatal("invalid scope was accepted")
			}
		})
	}
}

func TestBrokerRejectsInvalidResponsesWithoutLeakingStderr(t *testing.T) {
	for _, mode := range []string{"malformed", "trailing", "expired", "excessive", "oversized", "failure"} {
		t.Run(mode, func(t *testing.T) {
			broker := newTestBroker(t, mode)
			_, err := broker.Issue(context.Background(), validScope())
			if err == nil {
				t.Fatal("invalid response was accepted")
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("broker stderr leaked: %v", err)
			}
		})
	}
}

func TestBrokerDoesNotPassUnrelatedEnvironment(t *testing.T) {
	t.Setenv("DO_NOT_PASS_TO_BROKER", "do-not-leak")
	broker := newTestBroker(t, "environment")
	credential, err := broker.Issue(context.Background(), validScope())
	if err != nil {
		t.Fatal(err)
	}
	credential.Destroy()
}

func TestBrokerBoundsSustainedOutputByContext(t *testing.T) {
	broker := newTestBroker(t, "flood")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := broker.Issue(ctx, validScope()); err == nil {
		t.Fatal("unbounded helper output was accepted")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("unbounded helper output did not stop with its context")
	}
}

func newTestBroker(t *testing.T, mode string) *Broker {
	t.Helper()
	t.Setenv(HelperEnvironment, os.Args[0])
	t.Setenv(helperModeEnvironment, mode)
	broker, err := NewFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	return broker
}

func validScope() host.ReadScope {
	return host.ReadScope{
		WorkspaceID: strings.Repeat("a", 64), Repository: "python", HostIdentity: strings.Repeat("b", 64),
		Bucket: "packages", Endpoint: "https://packages.example/python", PlanID: strings.Repeat("c", 64),
		ChangeID: "python:123456789abc", TreeSHA256: strings.Repeat("d", 64), Prefixes: []string{"repo/simple/"},
	}
}

func copyExecutable(t *testing.T, source string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "credential-helper")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	inputErr := input.Close()
	outputErr := output.Close()
	if copyErr != nil || inputErr != nil || outputErr != nil {
		t.Fatalf("copy helper: copy=%v input=%v output=%v", copyErr, inputErr, outputErr)
	}
	return destination
}

func runCredentialHelper(mode string) {
	request, _ := io.ReadAll(os.Stdin)
	var scope host.ReadScope
	if json.Unmarshal(request, &scope) != nil || scope.Repository == "" {
		os.Exit(2)
	}
	switch mode {
	case "valid":
		writeCredentialResponse(time.Now().UTC().Add(5 * time.Minute))
	case "malformed":
		fmt.Print("not-json")
	case "trailing":
		writeCredentialResponse(time.Now().UTC().Add(5 * time.Minute))
		fmt.Print("{}")
	case "expired":
		writeCredentialResponse(time.Now().UTC().Add(-time.Minute))
	case "excessive":
		writeCredentialResponse(time.Now().UTC().Add(16 * time.Minute))
	case "oversized":
		fmt.Print(strings.Repeat("x", 65<<10))
	case "failure":
		_, _ = fmt.Fprint(os.Stderr, "do-not-leak")
		os.Exit(3)
	case "environment":
		if os.Getenv("DO_NOT_PASS_TO_BROKER") != "" {
			os.Exit(5)
		}
		writeCredentialResponse(time.Now().UTC().Add(5 * time.Minute))
	case "flood":
		for {
			_, _ = fmt.Print(strings.Repeat("x", 8<<10))
		}
	default:
		os.Exit(4)
	}
}

func writeCredentialResponse(expiresAt time.Time) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"username": "reader", "password": "topsecret", "expires_at": expiresAt.Format(time.RFC3339),
	})
}
