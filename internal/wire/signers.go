package wire

import (
	"fmt"
	"os"
	"path/filepath"

	filesigner "github.com/shellcell/snailmail/adapters/signer/file"
)

const SigningPassphraseEnvironment = "SNAILMAIL_KEY_PASSPHRASE"

// MinimumSigningPassphraseBytes is the documented floor for a signing key
// passphrase, which should come from a secret manager rather than be typed.
const MinimumSigningPassphraseBytes = 24

func NewSignerStore() (*filesigner.Store, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filesigner.New(filepath.Join(dataHome, "snailmail", "private-keys"), func() ([]byte, error) {
		value := os.Getenv(SigningPassphraseEnvironment)
		if len(value) < MinimumSigningPassphraseBytes {
			return nil, fmt.Errorf("%s must contain at least %d bytes", SigningPassphraseEnvironment, MinimumSigningPassphraseBytes)
		}
		return []byte(value), nil
	})
}
