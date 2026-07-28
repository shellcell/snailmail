package app

import (
	"strings"
	"testing"
)

func TestRedactCredentialLeavesPublicOutputIntact(t *testing.T) {
	// base64(":") is "Og==" and can appear in output that has nothing to do with
	// a credential; a public repository must not have it rewritten.
	output := "Downloading wheel Og== from simple/index.html"
	if redacted := redactCredential(output, "", ""); redacted != output {
		t.Fatalf("public output was rewritten: %q", redacted)
	}
}

func TestRedactCredentialHidesEveryDerivedForm(t *testing.T) {
	output := "user=reader pass=top secret escaped=top+secret basic=cmVhZGVyOnRvcCBzZWNyZXQ="
	redacted := redactCredential(output, "reader", "top secret")
	for _, secret := range []string{"reader", "top secret", "top+secret", "cmVhZGVyOnRvcCBzZWNyZXQ="} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("credential form %q survived redaction in %q", secret, redacted)
		}
	}
}
