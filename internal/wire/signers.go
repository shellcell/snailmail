package wire

import (
	"errors"
	"os"
	"path/filepath"

	filesigner "github.com/shellcell/snailmail/adapters/signer/file"
)

const SigningPassphraseEnvironment = "SNAILMAIL_KEY_PASSPHRASE"

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
		if len(value) < 16 {
			return nil, errors.New("signing key passphrase environment must contain at least 16 bytes")
		}
		return []byte(value), nil
	})
}
