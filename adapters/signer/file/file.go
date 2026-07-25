package filesigner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

var referencePattern = regexp.MustCompile(`^[a-f0-9]{64}/[a-z][a-z0-9-]*$`)

type Store struct {
	root       string
	passphrase func() ([]byte, error)
}

func New(root string, passphrase func() ([]byte, error)) (*Store, error) {
	if root == "" || passphrase == nil {
		return nil, errors.New("private key store and passphrase provider are required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := makePrivateDirectoriesDurable(absolute); err != nil {
		return nil, fmt.Errorf("create private key store: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve private key store: %w", err)
	}
	if err := os.Chmod(resolved, 0o700); err != nil {
		return nil, fmt.Errorf("secure private key store: %w", err)
	}
	return &Store{root: resolved, passphrase: passphrase}, nil
}

func (store *Store) Generate(ctx context.Context, ref signer.Ref, name string, createdAt time.Time, expiresIn time.Duration) (signer.Generated, error) {
	if err := validateRef(ref); err != nil {
		return signer.Generated{}, err
	}
	if err := ctx.Err(); err != nil {
		return signer.Generated{}, err
	}
	passphrase, err := store.passphrase()
	if err != nil {
		return signer.Generated{}, err
	}
	defer wipe(passphrase)
	generated, err := openpgpsigner.Generate(name, createdAt, expiresIn, passphrase)
	if err != nil {
		return signer.Generated{}, err
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return signer.Generated{}, err
	}
	defer root.Close()
	directory := filepath.Dir(ref.ID)
	if err := root.MkdirAll(directory, 0o700); err != nil {
		return signer.Generated{}, err
	}
	storeDirectory, err := root.Open(".")
	if err != nil {
		return signer.Generated{}, err
	}
	storeSyncErr := storeDirectory.Sync()
	storeCloseErr := storeDirectory.Close()
	if storeSyncErr != nil || storeCloseErr != nil {
		return signer.Generated{}, errors.Join(storeSyncErr, storeCloseErr)
	}
	namePath := ref.ID + ".asc"
	output, err := root.OpenFile(namePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return signer.Generated{}, errors.New("private signing key already exists")
		}
		return signer.Generated{}, err
	}
	_, writeErr := output.Write(generated.PrivateArmor)
	syncErr := output.Sync()
	closeErr := output.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = root.Remove(namePath)
		return signer.Generated{}, errors.Join(writeErr, syncErr, closeErr)
	}
	directoryHandle, err := root.Open(directory)
	if err != nil {
		return signer.Generated{}, err
	}
	directorySyncErr := directoryHandle.Sync()
	directoryCloseErr := directoryHandle.Close()
	if directorySyncErr != nil || directoryCloseErr != nil {
		return signer.Generated{}, errors.Join(directorySyncErr, directoryCloseErr)
	}
	return signer.Generated{Identity: generated.Identity, PublicBinary: generated.PublicBinary, PublicArmor: generated.PublicArmor}, nil
}

func (store *Store) Public(ctx context.Context, ref signer.Ref) (signer.Generated, error) {
	local, err := store.load(ctx, ref)
	if err != nil {
		return signer.Generated{}, err
	}
	defer local.Close()
	return local.Public()
}

func (store *Store) Delete(_ context.Context, ref signer.Ref) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(ref.ID + ".asc"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (store *Store) Resolve(ctx context.Context, ref signer.Ref) (signer.Signer, error) {
	return store.load(ctx, ref)
}

func (store *Store) load(ctx context.Context, ref signer.Ref) (*openpgpsigner.Local, error) {
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return nil, err
	}
	name := ref.ID + ".asc"
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		_ = root.Close()
		return nil, signer.ErrNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 1<<20 {
		_ = root.Close()
		return nil, errors.New("encrypted private signing key must be a bounded regular file with mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		_ = root.Close()
		return nil, errors.New("encrypted private signing key must be owned by the current user")
	}
	input, err := root.Open(name)
	if err != nil {
		_ = root.Close()
		return nil, errors.New("read encrypted private signing key")
	}
	content, readErr := io.ReadAll(io.LimitReader(input, 1<<20+1))
	inputCloseErr := input.Close()
	closeErr := root.Close()
	if readErr != nil || inputCloseErr != nil || len(content) > 1<<20 {
		return nil, errors.New("read encrypted private signing key")
	}
	if closeErr != nil {
		return nil, closeErr
	}
	passphrase, err := store.passphrase()
	if err != nil {
		return nil, err
	}
	defer wipe(passphrase)
	return openpgpsigner.Load(content, passphrase)
}

func validateRef(ref signer.Ref) error {
	if ref.Backend != "file" || !referencePattern.MatchString(ref.ID) || filepath.Clean(ref.ID) != ref.ID {
		return errors.New("invalid file signing key reference")
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func makePrivateDirectoriesDurable(name string) error {
	var missing []string
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("private key store path %q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		if parent := filepath.Dir(current); parent == current {
			return errors.New("private key store has no existing directory ancestor")
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private key store path %q is not a directory", directory)
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
