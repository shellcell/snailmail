package apkrsa

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
	"time"

	"github.com/shellcell/snailmail/signer"
)

const testPassphrase = "apk-signing-test-passphrase-value"

func generate(t *testing.T) Generated {
	t.Helper()
	generated, err := Generate(time.Unix(1700000000, 0).UTC(), 365*24*time.Hour, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

// A plan records a signature and applies it later, so the same payload and key
// must produce the same bytes every time or a reviewed plan could not be
// applied. PKCS#1 v1.5 is deterministic; this is what pins that.
func TestSignaturesAreDeterministic(t *testing.T) {
	generated := generate(t)
	local, err := Open(generated.PrivateArmor, []byte(testPassphrase), generated.Identity)
	if err != nil {
		t.Fatal(err)
	}
	request := signer.Request{Scheme: signer.SchemeAPKRSA256, Payload: []byte("an index"), CreatedAt: time.Unix(1, 0).UTC()}
	first, err := local.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := local.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Content, second.Content) {
		t.Fatal("signing the same payload twice produced different bytes")
	}
	if err := VerifyResponse(request, first, publicDER(t, generated), generated.Identity.Fingerprint); err != nil {
		t.Fatalf("a freshly made signature did not verify: %v", err)
	}
}

func TestVerifyRejectsWhatItShould(t *testing.T) {
	generated := generate(t)
	local, err := Open(generated.PrivateArmor, []byte(testPassphrase), generated.Identity)
	if err != nil {
		t.Fatal(err)
	}
	request := signer.Request{Scheme: signer.SchemeAPKRSA256, Payload: []byte("an index"), CreatedAt: time.Unix(1, 0).UTC()}
	response, err := local.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	other := generate(t)
	for name, check := range map[string]func() error{
		"altered payload": func() error {
			altered := request
			altered.Payload = []byte("another index")
			return VerifyResponse(altered, response, publicDER(t, generated), generated.Identity.Fingerprint)
		},
		"altered signature": func() error {
			altered := response
			altered.Content = append(append([]byte(nil), response.Content[:len(response.Content)-1]...), 0x00)
			return VerifyResponse(request, altered, publicDER(t, generated), generated.Identity.Fingerprint)
		},
		"another key": func() error {
			return VerifyResponse(request, response, publicDER(t, other), other.Identity.Fingerprint)
		},
		"wrong fingerprint": func() error {
			return VerifyResponse(request, response, publicDER(t, generated), other.Identity.Fingerprint)
		},
		"wrong scheme": func() error {
			altered := request
			altered.Scheme = signer.SchemeOpenPGPDetached
			return VerifyResponse(altered, response, publicDER(t, generated), generated.Identity.Fingerprint)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("an invalid signature verified")
			}
		})
	}
}

// The passphrase is the only thing between a stolen key file and a signing
// oracle, so the wrong one must not open it — and must not say which it was.
func TestPrivateKeyNeedsItsPassphrase(t *testing.T) {
	generated := generate(t)
	if _, err := Open(generated.PrivateArmor, []byte("a-different-passphrase-entirely"), generated.Identity); err == nil {
		t.Fatal("the key opened under the wrong passphrase")
	}
	if bytes.Contains(generated.PrivateArmor, []byte("PRIVATE KEY-----\nMII")) {
		t.Fatal("the stored key looks unencrypted")
	}
}

func TestGenerateRefusesAWeakPassphrase(t *testing.T) {
	if _, err := Generate(time.Unix(1, 0).UTC(), time.Hour, []byte("short")); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
}

// A key altered on disk must not open, so a swapped file cannot sign.
func TestAlteredPrivateKeyIsRefused(t *testing.T) {
	generated := generate(t)
	altered := append([]byte(nil), generated.PrivateArmor...)
	for index := range altered {
		if altered[index] == 'A' {
			altered[index] = 'B'
			break
		}
	}
	if _, err := Open(altered, []byte(testPassphrase), generated.Identity); err == nil {
		t.Fatal("an altered key opened")
	}
}

func publicDER(t *testing.T, generated Generated) []byte {
	t.Helper()
	identity, err := InspectPublic(generated.PublicArmor)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Fingerprint != generated.Identity.Fingerprint {
		t.Fatal("public key does not match its identity")
	}
	block, rest := pem.Decode(generated.PublicArmor)
	if block == nil || len(rest) != 0 {
		t.Fatal("public key is not a single PEM block")
	}
	return block.Bytes
}
