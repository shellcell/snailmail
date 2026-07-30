// Package tokenbroker supplies a forge API token from an operator-supplied
// helper program.
//
// This is the path for reading review evidence without a vendor CLI: Forgejo and
// Gitea have no generic API passthrough, and a runner with neither gh nor glab
// installed cannot run a gate otherwise. It reuses internal/brokerexec, so the
// helper is snapshotted, its environment reduced and its output bounded exactly
// as for a private host's read credentials — a weaker path to a token that
// authorizes publication would be the whole point undone.
package tokenbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/internal/brokerexec"
)

// HelperEnvironment names the helper. Separate from the host credential broker's
// variable because they are different grants: one reads objects from a bucket,
// the other reads review state from a forge, and an operator may well want
// different programs, or only one of them.
const HelperEnvironment = "SNAILMAIL_FORGE_TOKEN_BROKER"

// maxTokenLifetime bounds what a helper may hand back. A gate read takes seconds;
// a token good for a day would be a standing grant on the repository that decides
// whether publication is authorized.
const maxTokenLifetime = 15 * time.Minute

type Broker struct {
	helper *brokerexec.Helper
}

// NewFromEnvironment returns a broker, or an error if none is configured.
//
// Not configured is an ordinary outcome rather than a failure: a workspace whose
// adapters all use a vendor CLI needs no broker, so the caller decides whether
// its absence matters.
func NewFromEnvironment() (*Broker, error) {
	helper, err := brokerexec.Open("forge token", HelperEnvironment)
	if err != nil {
		return nil, err
	}
	return &Broker{helper: helper}, nil
}

// Configured reports whether a helper is named, so a caller can tell "no broker"
// from "the broker refused" without attempting a read.
func Configured() bool { return brokerexec.Named(HelperEnvironment) }

func (broker *Broker) Identity() string { return broker.helper.Identity() }

func (broker *Broker) Close() error { return broker.helper.Close() }

func (broker *Broker) Token(ctx context.Context, scope forge.TokenScope) (forge.Token, error) {
	if scope.Provider == "" || scope.Host == "" || scope.Repository == "" {
		return nil, errors.New("forge token scope is incomplete")
	}
	// The scope is handed to a helper as JSON and used by it to pick a token, so
	// a value carrying a control character could forge a second field in a
	// helper that parses loosely.
	for _, field := range []string{scope.Provider, scope.Host, scope.Repository} {
		if strings.ContainsAny(field, "\x00\r\n") {
			return nil, errors.New("forge token scope is invalid")
		}
	}
	var response struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := broker.helper.Run(ctx, scope, &response); err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) || expiresAt.After(time.Now().UTC().Add(maxTokenLifetime)) {
		return nil, errors.New("forge token broker returned an invalid or excessively long-lived token")
	}
	if response.Token == "" || strings.ContainsAny(response.Token, "\x00\r\n") {
		// A token reaches the API as a header value, so a newline in one would
		// let the helper inject a second header.
		return nil, fmt.Errorf("forge token broker returned a token that cannot be sent as a header")
	}
	return &token{secret: []byte(response.Token), expiresAt: expiresAt}, nil
}

// token holds its secret as bytes so Destroy can overwrite it. A Go string is
// immutable, so assigning "" only drops a reference and leaves the secret
// readable in the heap until the collector happens to reuse it.
type token struct {
	mutex     sync.Mutex
	secret    []byte
	expiresAt time.Time
}

func (token *token) Bearer(context.Context) (string, error) {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	if len(token.secret) == 0 || !time.Now().UTC().Before(token.expiresAt) {
		return "", errors.New("forge token is unavailable or expired")
	}
	return string(token.secret), nil
}

func (token *token) Destroy() {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	clear(token.secret)
	token.secret = nil
	token.expiresAt = time.Time{}
}
