// Package commandcredential issues short-lived read credentials for a private
// host by asking an operator-supplied helper program.
//
// snailmail never holds a long-lived cloud credential. It asks for one scoped to
// the objects a client is about to read, valid for minutes, and discards it. How
// the helper is run — snapshotted, environment-reduced, output-bounded — lives in
// internal/brokerexec, shared with the forge token broker so that the hardening
// cannot come to differ between them.
package commandcredential

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/brokerexec"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

const HelperEnvironment = "SNAILMAIL_CREDENTIAL_BROKER"

// maxCredentialLifetime bounds what a helper may hand back. A credential that
// outlived the read it was issued for would be a standing grant, which is the
// thing this exists to avoid.
const maxCredentialLifetime = 15 * time.Minute

type Broker struct {
	helper *brokerexec.Helper
}

func NewFromEnvironment() (*Broker, error) {
	helper, err := brokerexec.Open("private read credential", HelperEnvironment)
	if err != nil {
		return nil, err
	}
	return &Broker{helper: helper}, nil
}

func (broker *Broker) Identity() string { return broker.helper.Identity() }

func (broker *Broker) Close() error { return broker.helper.Close() }

func (broker *Broker) Issue(ctx context.Context, scope host.ReadScope) (host.BasicCredential, error) {
	if !hexdigest.ValidSHA256(scope.WorkspaceID) || scope.Repository == "" || !hexdigest.ValidSHA256(scope.HostIdentity) || scope.Bucket == "" || scope.Endpoint == "" ||
		!hexdigest.ValidSHA256(scope.PlanID) || scope.ChangeID == "" || !hexdigest.ValidSHA256(scope.TreeSHA256) || len(scope.Prefixes) == 0 {
		return nil, errors.New("credential scope is incomplete")
	}
	for _, prefix := range scope.Prefixes {
		if prefix == "" || strings.ContainsAny(prefix, "\x00\r\n") {
			return nil, errors.New("credential scope is invalid")
		}
	}
	var response struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := broker.helper.Run(ctx, scope, &response); err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) || expiresAt.After(time.Now().UTC().Add(maxCredentialLifetime)) ||
		response.Username == "" || response.Password == "" {
		return nil, errors.New("credential broker returned invalid or excessive credentials")
	}
	return &credential{username: []byte(response.Username), password: []byte(response.Password), expiresAt: expiresAt}, nil
}

// credential holds its secret as bytes so Destroy can actually overwrite it.
// Go strings are immutable, so assigning "" only drops a reference and leaves
// the secret readable in the heap until the collector happens to reuse it.
type credential struct {
	mutex     sync.Mutex
	username  []byte
	password  []byte
	expiresAt time.Time
}

func (credential *credential) Basic(_ context.Context) (string, string, error) {
	credential.mutex.Lock()
	defer credential.mutex.Unlock()
	if len(credential.username) == 0 || len(credential.password) == 0 || !time.Now().UTC().Before(credential.expiresAt) {
		return "", "", errors.New("private read credential is unavailable or expired")
	}
	return string(credential.username), string(credential.password), nil
}

func (credential *credential) Destroy() {
	credential.mutex.Lock()
	defer credential.mutex.Unlock()
	clear(credential.username)
	clear(credential.password)
	credential.username = nil
	credential.password = nil
	credential.expiresAt = time.Time{}
}
