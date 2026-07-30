package forgeio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shellcell/snailmail/forge"
)

// ErrNotFound reports that the forge answered, and said the thing asked about
// does not exist.
//
// Distinct from forge.ErrUnavailable, and the distinction matters: a commit with
// no pull request is a 404 on some forges, and reading that as "review state
// unknown" would tell an operator to check their credentials when the real answer
// is that the revision was never reviewed. Only a caller that knows what a 404
// means for the endpoint it asked about may act on this.
var ErrNotFound = errors.New("forge reports no such resource")

// requestTimeout bounds one API call. A gate read happens while a lock is held.
const requestTimeout = 30 * time.Second

// HTTPClient reads a forge API directly, presenting a token from a broker.
//
// Used where no vendor CLI can be delegated to: Forgejo and Gitea have no
// generic API passthrough, and a runner may have neither gh nor glab installed.
// It is the weaker option — snailmail holds the token rather than letting a
// vendor tool own it — so it is chosen only when the CLI path is unavailable.
type HTTPClient struct {
	// BaseURL is the API root, ending without a slash.
	BaseURL string
	// Broker supplies the token. Nil means unauthenticated, which works for a
	// public repository and is how a gate can read review evidence with no
	// credentials at all.
	Broker forge.TokenBroker
	// Scope identifies what the token is for.
	Scope forge.TokenScope
	// Client is the transport. Nil uses a bounded default.
	Client *http.Client
}

// Get reads one endpoint, relative to BaseURL, and decodes it into target.
//
// endpoint must already be escaped: it is joined to the base as given, so a
// caller that interpolates a name has to escape it. Only https is allowed unless
// the host is a loopback address, because a token presented over http is a token
// disclosed.
func (client HTTPClient) Get(ctx context.Context, endpoint string, target any) error {
	address, err := client.resolve(endpoint)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, address, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", forge.ErrUnavailable, endpoint)
	}
	request.Header.Set("Accept", "application/json")
	if client.Broker != nil {
		token, err := client.Broker.Token(requestCtx, client.Scope)
		if err != nil {
			return fmt.Errorf("%w: no token for %s: %w", forge.ErrUnavailable, client.Scope.Host, err)
		}
		defer token.Destroy()
		bearer, err := token.Bearer(requestCtx)
		if err != nil {
			return fmt.Errorf("%w: no token for %s: %w", forge.ErrUnavailable, client.Scope.Host, err)
		}
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	transport := client.Client
	if transport == nil {
		transport = &http.Client{Timeout: requestTimeout}
	}
	response, err := transport.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s", forge.ErrUnavailable, endpoint)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseSize))
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, endpoint)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", forge.ErrUnavailable, endpoint, response.StatusCode)
	}
	// Read one byte past the limit, so a body exactly at it is still detected as
	// over rather than silently truncated into something that parses.
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseSize+1))
	if err != nil {
		return fmt.Errorf("%w: %s", forge.ErrUnavailable, endpoint)
	}
	if len(body) > MaxResponseSize {
		return fmt.Errorf("%w: response from %s exceeds the read limit", forge.ErrUnavailable, endpoint)
	}
	return decodeSingle(body, target, endpoint)
}

func (client HTTPClient) resolve(endpoint string) (string, error) {
	if client.BaseURL == "" || endpoint == "" || strings.ContainsAny(endpoint, " \t\r\n") {
		return "", fmt.Errorf("%w: %q is not an endpoint", forge.ErrUnavailable, endpoint)
	}
	base, err := url.Parse(client.BaseURL)
	if err != nil || base.Host == "" {
		return "", fmt.Errorf("%w: %q is not an API base", forge.ErrUnavailable, client.BaseURL)
	}
	if base.Scheme != "https" && !isLoopback(base.Hostname()) {
		return "", fmt.Errorf("%w: refusing to send a token to %s over %s",
			forge.ErrUnavailable, base.Host, base.Scheme)
	}
	// Joined textually rather than through URL resolution, which would let an
	// endpoint beginning with / or // escape the base path or the host entirely.
	if strings.HasPrefix(endpoint, "/") {
		return "", fmt.Errorf("%w: endpoint %q must be relative to the API base", forge.ErrUnavailable, endpoint)
	}
	// A traversal is a ".." path segment, not the characters appearing anywhere:
	// a Forgejo comparison is addressed as "compare/main...<revision>", and
	// refusing every ".." would refuse the endpoint that answers ancestry.
	for _, segment := range strings.Split(endpoint, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: endpoint %q must be relative to the API base", forge.ErrUnavailable, endpoint)
		}
	}
	return strings.TrimSuffix(client.BaseURL, "/") + "/" + endpoint, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// decodeSingle is the decode both transports share: exactly one JSON document,
// with nothing after it.
func decodeSingle(body []byte, target any, endpoint string) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid response from %s", forge.ErrUnavailable, endpoint)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data in response from %s", forge.ErrUnavailable, endpoint)
	}
	return nil
}
