package tokenbroker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

// The test binary doubles as the helper, which is what makes it a native
// executable — brokerexec refuses a shell script, so a scripted helper could not
// be tested at all.
const helperModeEnvironment = "SNAILMAIL_BROKER_TEST_MODE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperModeEnvironment); mode != "" {
		runTokenHelper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
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

func validScope() forge.TokenScope {
	return forge.TokenScope{Provider: "forgejo", Host: "git.example", Repository: "acme/state"}
}

func TestBrokerIssuesAndDestroysAToken(t *testing.T) {
	broker := newTestBroker(t, "valid")
	if !hexdigest.ValidSHA256(broker.Identity()) {
		t.Fatalf("invalid broker identity %q", broker.Identity())
	}
	token, err := broker.Token(context.Background(), validScope())
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := token.Bearer(context.Background())
	if err != nil || bearer != "forge-token" {
		t.Fatalf("bearer=%q err=%v", bearer, err)
	}
	// Destroy overwrites the secret rather than dropping a reference, so a token
	// does not remain readable in the heap after the read it was issued for.
	token.Destroy()
	if _, err := token.Bearer(context.Background()); err == nil {
		t.Fatal("a destroyed token remained usable")
	}
}

// A token that outlived the read would be a standing grant on the repository
// that decides whether publication is authorized.
func TestBrokerRefusesTokensThatAreExpiredOrTooLongLived(t *testing.T) {
	for _, mode := range []string{"expired", "excessive", "undated"} {
		broker := newTestBroker(t, mode)
		if _, err := broker.Token(context.Background(), validScope()); err == nil {
			t.Errorf("%s token was accepted", mode)
		}
	}
}

// A token reaches the API as a header value, so a newline in one would let the
// helper inject a second header.
func TestBrokerRefusesATokenThatCannotBeSentAsAHeader(t *testing.T) {
	for _, mode := range []string{"empty", "newline"} {
		broker := newTestBroker(t, mode)
		if _, err := broker.Token(context.Background(), validScope()); err == nil {
			t.Errorf("%s token was accepted", mode)
		}
	}
}

// A helper's own diagnostics must not reach the caller: a broker that printed
// stderr on failure would put whatever it logged — plausibly a secret — into a
// snailmail error message and from there into CI output.
func TestBrokerRejectsInvalidResponsesWithoutLeakingStderr(t *testing.T) {
	for _, mode := range []string{"malformed", "trailing", "unknown-field", "oversized", "failure"} {
		broker := newTestBroker(t, mode)
		_, err := broker.Token(context.Background(), validScope())
		if err == nil {
			t.Fatalf("%s response was accepted", mode)
		}
		if strings.Contains(err.Error(), "do-not-leak") {
			t.Errorf("%s leaked helper stderr: %v", mode, err)
		}
	}
}

// An incomplete or control-carrying scope must not reach a helper: it is handed
// over as JSON and used to choose a token, so a forged field could select one for
// a different instance.
func TestBrokerRefusesAnInvalidScope(t *testing.T) {
	broker := newTestBroker(t, "valid")
	for name, scope := range map[string]forge.TokenScope{
		"no provider":   {Host: "h", Repository: "r"},
		"no host":       {Provider: "forgejo", Repository: "r"},
		"no repository": {Provider: "forgejo", Host: "h"},
		"newline":       {Provider: "forgejo", Host: "h\nx", Repository: "r"},
		"null":          {Provider: "forgejo", Host: "h", Repository: "r\x00"},
	} {
		if _, err := broker.Token(context.Background(), scope); err == nil {
			t.Errorf("scope %q was accepted", name)
		}
	}
}

// The scope reaches the helper, so it can hand back a token for one instance and
// refuse another.
func TestTheHelperSeesTheScope(t *testing.T) {
	broker := newTestBroker(t, "echo-scope")
	token, err := broker.Token(context.Background(), validScope())
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := token.Bearer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "forgejo|git.example|acme/state" {
		t.Errorf("helper saw %q", bearer)
	}
}

// Configured distinguishes an absent broker from one that refused, so a
// workspace whose adapters all use a vendor CLI is not told a broker failed.
func TestConfiguredReportsWhetherAHelperIsNamed(t *testing.T) {
	t.Setenv(HelperEnvironment, "")
	if Configured() {
		t.Error("an unset broker reported as configured")
	}
	t.Setenv(HelperEnvironment, os.Args[0])
	if !Configured() {
		t.Error("a named broker reported as absent")
	}
}

func TestUnconfiguredBrokerIsAnOrdinaryError(t *testing.T) {
	t.Setenv(HelperEnvironment, "")
	if _, err := NewFromEnvironment(); err == nil {
		t.Fatal("an unconfigured broker was opened")
	}
}

func writeTokenResponse(secret string, expiresAt time.Time) {
	fmt.Printf(`{"token":%q,"expires_at":%q}`, secret, expiresAt.Format(time.RFC3339))
}

func runTokenHelper(mode string) {
	request, _ := io.ReadAll(os.Stdin)
	var scope forge.TokenScope
	if json.Unmarshal(request, &scope) != nil || scope.Provider == "" {
		os.Exit(2)
	}
	valid := time.Now().UTC().Add(5 * time.Minute)
	switch mode {
	case "valid":
		writeTokenResponse("forge-token", valid)
	case "echo-scope":
		writeTokenResponse(scope.Provider+"|"+scope.Host+"|"+scope.Repository, valid)
	case "expired":
		writeTokenResponse("forge-token", time.Now().UTC().Add(-time.Minute))
	case "excessive":
		writeTokenResponse("forge-token", time.Now().UTC().Add(16*time.Minute))
	case "undated":
		fmt.Print(`{"token":"forge-token","expires_at":""}`)
	case "empty":
		writeTokenResponse("", valid)
	case "newline":
		writeTokenResponse("forge\ntoken", valid)
	case "malformed":
		fmt.Print("not-json")
	case "trailing":
		writeTokenResponse("forge-token", valid)
		fmt.Print("{}")
	case "unknown-field":
		fmt.Printf(`{"token":"forge-token","expires_at":%q,"scopes":["repo"]}`, valid.Format(time.RFC3339))
	case "oversized":
		fmt.Print(strings.Repeat("x", 65<<10))
	case "failure":
		_, _ = fmt.Fprint(os.Stderr, "do-not-leak")
		os.Exit(3)
	}
}
