package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	filesigner "github.com/shellcell/snailmail/adapters/signer/file"
)

const SigningPassphraseEnvironment = "SNAILMAIL_KEY_PASSPHRASE"

// SigningPassphraseFileEnvironment names a file holding the passphrase.
//
// It is preferred over the value variable because a container's environment is
// readable through the runtime's inspection API for as long as the container
// exists, however the value was supplied. A file can be mounted, read once, and
// removed. The variable remains supported: it is what a local shell and most
// CI secret integrations offer directly.
const SigningPassphraseFileEnvironment = "SNAILMAIL_KEY_PASSPHRASE_FILE"

// MinimumSigningPassphraseBytes is the documented floor for a signing key
// passphrase, which should come from a secret manager rather than be typed.
const MinimumSigningPassphraseBytes = 24

// maxSigningPassphraseBytes bounds a passphrase file so pointing the variable
// at an arbitrary path fails cleanly instead of reading it into memory.
const maxSigningPassphraseBytes = 4 << 10

func NewSignerStore() (*filesigner.Store, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filesigner.New(filepath.Join(dataHome, "snailmail", "private-keys"), signingPassphrase)
}

func signingPassphrase() ([]byte, error) {
	name := os.Getenv(SigningPassphraseFileEnvironment)
	if name == "" {
		value := os.Getenv(SigningPassphraseEnvironment)
		return validSigningPassphrase([]byte(value), SigningPassphraseEnvironment)
	}
	if os.Getenv(SigningPassphraseEnvironment) != "" {
		return nil, fmt.Errorf("set %s or %s, not both", SigningPassphraseEnvironment, SigningPassphraseFileEnvironment)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", SigningPassphraseFileEnvironment, err)
	}
	value, readErr := io.ReadAll(io.LimitReader(file, maxSigningPassphraseBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", SigningPassphraseFileEnvironment, readErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(value) > maxSigningPassphraseBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", SigningPassphraseFileEnvironment, maxSigningPassphraseBytes)
	}
	// A here-doc, `echo`, or an editor leaves a trailing newline that was never
	// part of the passphrase.
	return validSigningPassphrase(bytes.TrimRight(value, "\r\n"), SigningPassphraseFileEnvironment)
}

func validSigningPassphrase(value []byte, source string) ([]byte, error) {
	if len(value) < MinimumSigningPassphraseBytes {
		if len(value) == 0 {
			return nil, errors.New("no signing key passphrase is configured")
		}
		return nil, fmt.Errorf("%s must contain at least %d bytes", source, MinimumSigningPassphraseBytes)
	}
	return value, nil
}
