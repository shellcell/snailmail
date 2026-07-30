package forgeio

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/forge"
)

type stubToken struct {
	secret    string
	err       error
	destroyed bool
}

func (token *stubToken) Bearer(context.Context) (string, error) { return token.secret, token.err }
func (token *stubToken) Destroy()                               { token.destroyed = true }

type stubBroker struct {
	token *stubToken
	err   error
	scope forge.TokenScope
}

func (broker *stubBroker) Token(_ context.Context, scope forge.TokenScope) (forge.Token, error) {
	broker.scope = scope
	if broker.err != nil {
		return nil, broker.err
	}
	return broker.token, nil
}
func (broker *stubBroker) Identity() string { return "stub" }

func serving(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// A 404 means the forge answered and said the thing does not exist. On some
// forges a commit with no pull request is exactly that, so it must be
// distinguishable — reading it as unavailable would tell an operator to check
// their credentials when the answer is that nothing reviewed the revision.
func TestNotFoundIsDistinguishableFromUnavailable(t *testing.T) {
	server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})
	client := HTTPClient{BaseURL: server.URL}
	var target map[string]any
	err := client.Get(context.Background(), "repos/a/b/commits/x/pull", &target)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if errors.Is(err, forge.ErrUnavailable) {
		t.Error("a 404 also reported as unavailable; a caller cannot tell them apart")
	}
}

// Every other failure is unknown, and unknown must refuse. A 403 in particular
// is not "not reviewed": it is a token that cannot see the answer.
func TestEveryOtherStatusIsUnavailable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden,
		http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusNoContent} {
		server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(status)
		})
		var target map[string]any
		err := HTTPClient{BaseURL: server.URL}.Get(context.Background(), "repos/a/b", &target)
		if !errors.Is(err, forge.ErrUnavailable) {
			t.Errorf("status %d gave %v, want ErrUnavailable", status, err)
		}
		if errors.Is(err, ErrNotFound) {
			t.Errorf("status %d reported as not-found", status)
		}
	}
}

func TestTokenIsPresentedAsBearerAndDestroyed(t *testing.T) {
	var seen string
	server := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		seen = request.Header.Get("Authorization")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	token := &stubToken{secret: "s3cret"}
	broker := &stubBroker{token: token}
	client := HTTPClient{
		BaseURL: server.URL, Broker: broker,
		Scope: forge.TokenScope{Provider: "forgejo", Host: "git.example", Repository: "acme/state"},
	}
	var target map[string]any
	if err := client.Get(context.Background(), "repos/acme/state", &target); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer s3cret" {
		t.Errorf("Authorization = %q", seen)
	}
	// Held for one read and then overwritten, so it does not outlive the call.
	if !token.destroyed {
		t.Error("the token was not destroyed after the request")
	}
	// The broker is told which instance and repository it is answering for, so it
	// can hand back different tokens without snailmail knowing how it decides.
	if broker.scope.Host != "git.example" || broker.scope.Repository != "acme/state" {
		t.Errorf("broker saw scope %+v", broker.scope)
	}
}

// A gate that cannot authenticate cannot read review evidence. That is unknown,
// not "not reviewed", so it must refuse and say why.
func TestABrokerFailureIsUnavailable(t *testing.T) {
	server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	for name, broker := range map[string]*stubBroker{
		"broker refused": {err: errors.New("helper exited 1")},
		"token expired":  {token: &stubToken{err: errors.New("expired")}},
	} {
		t.Run(name, func(t *testing.T) {
			var target map[string]any
			err := HTTPClient{BaseURL: server.URL, Broker: broker,
				Scope: forge.TokenScope{Provider: "forgejo", Host: "h", Repository: "r"}}.
				Get(context.Background(), "repos/a/b", &target)
			if !errors.Is(err, forge.ErrUnavailable) {
				t.Errorf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// No broker is a legitimate configuration: a public repository needs no token.
func TestNoBrokerSendsNoAuthorization(t *testing.T) {
	var had bool
	server := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		_, had = request.Header["Authorization"]
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	var target map[string]any
	if err := (HTTPClient{BaseURL: server.URL}).Get(context.Background(), "repos/a/b", &target); err != nil {
		t.Fatal(err)
	}
	if had {
		t.Error("an unauthenticated read sent an Authorization header")
	}
}

// A token sent over http is a token disclosed. Loopback is exempt because that is
// how a test server and a local instance are reached.
func TestPlainHTTPIsRefusedExceptOnLoopback(t *testing.T) {
	var target map[string]any
	err := HTTPClient{BaseURL: "http://forge.example/api/v1"}.Get(context.Background(), "repos/a/b", &target)
	if err == nil || !strings.Contains(err.Error(), "over http") {
		t.Errorf("error = %v, want a refusal to send a token over http", err)
	}
	// httptest serves http on 127.0.0.1, and that must keep working.
	server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	if err := (HTTPClient{BaseURL: server.URL}).Get(context.Background(), "repos/a/b", &target); err != nil {
		t.Errorf("a loopback address was refused: %v", err)
	}
}

// An endpoint is joined to the base as text, so one that begins with a slash or
// climbs would otherwise reach a different path — or a different host.
func TestAnEndpointCannotEscapeTheAPIBase(t *testing.T) {
	var reached string
	server := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		reached = request.URL.Path
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	client := HTTPClient{BaseURL: server.URL + "/api/v1"}
	var target map[string]any
	for _, endpoint := range []string{"/etc/passwd", "//evil.example/x", "../../admin", "repos/../../admin", ""} {
		if err := client.Get(context.Background(), endpoint, &target); err == nil {
			t.Errorf("endpoint %q was accepted and reached %q", endpoint, reached)
		}
	}
	if err := client.Get(context.Background(), "repos/a/b", &target); err != nil {
		t.Fatal(err)
	}
	if reached != "/api/v1/repos/a/b" {
		t.Errorf("a plain endpoint reached %q", reached)
	}
	// A traversal is a ".." segment, not those characters anywhere. Forgejo
	// addresses a comparison as compare/main...<revision>, so refusing every
	// occurrence would refuse the endpoint that answers ancestry.
	if err := client.Get(context.Background(), "repos/a/b/compare/main...abc123", &target); err != nil {
		t.Fatalf("a comparison endpoint was refused: %v", err)
	}
	if reached != "/api/v1/repos/a/b/compare/main...abc123" {
		t.Errorf("a comparison endpoint reached %q", reached)
	}
}

// A response the client cannot fully account for is unknown, the same as for the
// CLI transport — both share the decode so they cannot come to differ.
func TestHTTPRefusesAResponseItCannotAccountFor(t *testing.T) {
	for name, body := range map[string]string{
		"trailing document": `{"a":1}{"b":2}`,
		"not json":          `<html>502</html>`,
		"truncated":         `{"a":`,
		"oversized":         `{"a":"` + strings.Repeat("x", MaxResponseSize+1) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			})
			var target map[string]any
			err := HTTPClient{BaseURL: server.URL}.Get(context.Background(), "repos/a/b", &target)
			if !errors.Is(err, forge.ErrUnavailable) {
				t.Errorf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// A cancelled read has not answered, and an apply that was interrupted has not
// been authorized.
func TestACancelledReadIsNotAnAnswer(t *testing.T) {
	server := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target map[string]any
	if err := (HTTPClient{BaseURL: server.URL}).Get(ctx, "repos/a/b", &target); err == nil {
		t.Error("a cancelled read returned an answer")
	}
}
