package engine

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	filesigner "github.com/shellcell/snailmail/adapters/signer/file"
	"github.com/shellcell/snailmail/internal/state"
)

// attachFixture builds a workspace holding an unsigned Debian repository and a
// published signing key that has not been attached to it.
func attachFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "attach-test"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "apt", Format: "deb", HostType: "local", Output: "public/apt",
		Visibility: "public", Suite: "stable", Component: "main",
		Architectures: []string{"amd64"}, AllowUnsigned: true,
	}); err != nil {
		t.Fatal(err)
	}
	store, err := filesigner.New(t.TempDir(), func() ([]byte, error) { return []byte("attach-test-passphrase-value"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKey(context.Background(), NewKeyRequest{
		Root: root, Name: "archive-signing", Algorithm: "openpgp-rsa4096",
		CreatedAt: time.Now().UTC().Truncate(time.Second).Add(-time.Hour),
		ExpiresIn: 365 * 24 * time.Hour, Keys: store,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// A repository set up unsigned could not become signed: setup refuses a name
// that exists and rotate needs a key to replace, so the only way through was
// editing the manifest by hand.
func TestAttachKeySignsARepositoryThatWasSetUpUnsigned(t *testing.T) {
	root := attachFixture(t)
	before, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Repositories["apt"].SigningKeys) != 0 {
		t.Fatal("fixture repository is already signed")
	}

	result, err := AttachKey(AttachKeyRequest{Root: root, Repository: "apt", Key: "archive-signing"})
	if err != nil {
		t.Fatalf("attaching a key failed: %v", err)
	}

	after, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	repository := after.Repositories["apt"]
	if len(repository.SigningKeys) != 1 || repository.SigningKeys[0] != "archive-signing" {
		t.Fatalf("signing keys are %v", repository.SigningKeys)
	}
	// The keyring is what a client installs. Setting only the key name left the
	// manifest failing validation with a message that named neither.
	if repository.SigningKeyring != after.Keys["archive-signing"].PublicKeyPath {
		t.Fatalf("keyring is %q, want %q", repository.SigningKeyring, after.Keys["archive-signing"].PublicKeyPath)
	}
	if result.Fingerprint != after.Keys["archive-signing"].Fingerprint || result.Keyring != repository.SigningKeyring {
		t.Fatalf("result does not describe what was written: %+v", result)
	}

	// The whole point is that the repository is now valid to publish.
	audit, err := AuditKeys(PublishKeyRequest{Root: root}, time.Now().UTC())
	if err != nil {
		t.Fatalf("auditing after attach failed: %v", err)
	}
	for _, finding := range audit.Findings {
		if finding.Severity == "error" {
			t.Errorf("audit still reports an error: %s %s", finding.Subject, finding.Message)
		}
	}
}

// Replacing a live key is rotation, which serves both keys for an overlap.
// Silently swapping one here would strand every client that already trusts it.
func TestAttachKeyRefusesToReplaceALiveKey(t *testing.T) {
	root := attachFixture(t)
	if _, err := AttachKey(AttachKeyRequest{Root: root, Repository: "apt", Key: "archive-signing"}); err != nil {
		t.Fatal(err)
	}
	_, err := AttachKey(AttachKeyRequest{Root: root, Repository: "apt", Key: "archive-signing"})
	if err == nil {
		t.Fatal("attaching over an existing key was accepted")
	}
	if !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("error does not point at rotation: %v", err)
	}
}

func TestAttachKeyRejectsWhatItCannotSign(t *testing.T) {
	root := attachFixture(t)
	if err := SetupRepository(SetupRepositoryRequest{
		Root: root, Name: "python", Format: "pypi", HostType: "local",
		Output: "public/python", Visibility: "public",
	}); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]AttachKeyRequest{
		"unknown repository": {Root: root, Repository: "absent", Key: "archive-signing"},
		"unknown key":        {Root: root, Repository: "apt", Key: "absent"},
		// PyPI dropped repository signing, so a key there could never be used.
		"format without signing": {Root: root, Repository: "python", Key: "archive-signing"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := AttachKey(request); err == nil {
				t.Fatal("an unusable attachment was accepted")
			}
		})
	}
}
