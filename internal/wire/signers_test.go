package wire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPassphrase = "a-secret-manager-value-long-enough"

func TestSigningPassphraseReadsTheEnvironmentValue(t *testing.T) {
	t.Setenv(SigningPassphraseFileEnvironment, "")
	t.Setenv(SigningPassphraseEnvironment, validPassphrase)
	value, err := signingPassphrase()
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != validPassphrase {
		t.Fatalf("passphrase = %q", value)
	}
}

func TestSigningPassphraseReadsAFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "passphrase")
	// Written the way a here-doc or editor would leave it.
	if err := os.WriteFile(name, []byte(validPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SigningPassphraseEnvironment, "")
	t.Setenv(SigningPassphraseFileEnvironment, name)
	value, err := signingPassphrase()
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != validPassphrase {
		t.Fatalf("passphrase = %q, want the trailing newline stripped", value)
	}
}

// Accepting both silently would make it ambiguous which secret actually signed.
func TestSigningPassphraseRejectsBothSources(t *testing.T) {
	name := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(name, []byte(validPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SigningPassphraseEnvironment, validPassphrase)
	t.Setenv(SigningPassphraseFileEnvironment, name)
	if _, err := signingPassphrase(); err == nil {
		t.Fatal("expected configuring both sources to be rejected")
	}
}

func TestSigningPassphraseEnforcesTheFloorFromEitherSource(t *testing.T) {
	short := "too-short"
	t.Run("environment", func(t *testing.T) {
		t.Setenv(SigningPassphraseFileEnvironment, "")
		t.Setenv(SigningPassphraseEnvironment, short)
		_, err := signingPassphrase()
		if err == nil || !strings.Contains(err.Error(), SigningPassphraseEnvironment) {
			t.Fatalf("error = %v, want the environment name and the floor", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		name := filepath.Join(t.TempDir(), "passphrase")
		if err := os.WriteFile(name, []byte(short), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(SigningPassphraseEnvironment, "")
		t.Setenv(SigningPassphraseFileEnvironment, name)
		_, err := signingPassphrase()
		if err == nil || !strings.Contains(err.Error(), SigningPassphraseFileEnvironment) {
			t.Fatalf("error = %v, want the file variable name and the floor", err)
		}
	})
}

// Pointing the variable at an arbitrary path must fail rather than read it in.
func TestSigningPassphraseBoundsTheFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(name, []byte(strings.Repeat("x", maxSigningPassphraseBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SigningPassphraseEnvironment, "")
	t.Setenv(SigningPassphraseFileEnvironment, name)
	if _, err := signingPassphrase(); err == nil {
		t.Fatal("expected an oversized passphrase file to be rejected")
	}
}

func TestSigningPassphraseReportsAMissingFile(t *testing.T) {
	t.Setenv(SigningPassphraseEnvironment, "")
	t.Setenv(SigningPassphraseFileEnvironment, filepath.Join(t.TempDir(), "absent"))
	if _, err := signingPassphrase(); err == nil {
		t.Fatal("expected a missing passphrase file to be reported")
	}
}
