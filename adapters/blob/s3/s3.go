package s3blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/shellcell/snailmail/blob"
)

type ObjectInfo struct {
	Size     int64
	SHA256   string
	Metadata map[string]string
}

type ObjectClient interface {
	Head(context.Context, string) (ObjectInfo, error)
	PutCreate(context.Context, string, io.Reader, int64, string, map[string]string) (ObjectInfo, error)
	Get(context.Context, string) (io.ReadCloser, ObjectInfo, error)
}

type Store struct {
	client      ObjectClient
	prefix      string
	workspaceID string
}

func New(client ObjectClient, configuration blob.Configuration) (*Store, error) {
	if client == nil || configuration.Type != "s3" || !validSHA256(configuration.WorkspaceID) {
		return nil, errors.New("invalid S3 blob store configuration")
	}
	prefix := strings.Trim(configuration.Prefix, "/")
	if prefix != configuration.Prefix || (prefix != "" && (path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../"))) {
		return nil, errors.New("invalid S3 blob prefix")
	}
	return &Store{client: client, prefix: prefix, workspaceID: configuration.WorkspaceID}, nil
}

func (store *Store) Put(ctx context.Context, ref blob.Ref, reader io.Reader) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	metadata := map[string]string{"sha256": ref.SHA256, "size": fmt.Sprintf("%d", ref.Size)}
	stored, err := store.client.PutCreate(ctx, store.key(ref), reader, ref.Size, ref.SHA256, metadata)
	if err != nil {
		if errors.Is(err, blob.ErrPrecondition) {
			stored, err = store.client.Head(ctx, store.key(ref))
			if err == nil {
				if !matches(stored, ref) {
					return errors.New("immutable S3 blob conflicts")
				}
				return store.verifyChecksumlessObject(ctx, ref, stored)
			}
			return err
		}
		if observed, headErr := store.client.Head(ctx, store.key(ref)); headErr == nil && matches(observed, ref) {
			if verifyErr := store.verifyChecksumlessObject(ctx, ref, observed); verifyErr == nil {
				return nil
			}
		}
		return err
	}
	if !matches(stored, ref) {
		return errors.New("stored S3 blob metadata does not match")
	}
	return store.verifyChecksumlessObject(ctx, ref, stored)
}

func (store *Store) verifyChecksumlessObject(ctx context.Context, ref blob.Ref, info ObjectInfo) error {
	if info.SHA256 != "" {
		return nil
	}
	if err := store.Fetch(ctx, ref, io.Discard); err != nil {
		return fmt.Errorf("verify checksum-less S3 blob: %w", err)
	}
	return nil
}

func (store *Store) Fetch(ctx context.Context, ref blob.Ref, writer io.Writer) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	reader, info, err := store.client.Get(ctx, store.key(ref))
	if err != nil {
		return err
	}
	if !matches(info, ref) {
		_ = reader.Close()
		return errors.New("fetched S3 blob metadata does not match its reference")
	}
	hash := sha256.New()
	written, readErr := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(reader, ref.Size+1))
	closeErr := reader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != ref.Size || hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
		return errors.New("fetched S3 blob does not match its reference")
	}
	return nil
}

func (store *Store) key(ref blob.Ref) string {
	return path.Join(store.prefix, store.workspaceID, "sha256", ref.SHA256[:2], ref.SHA256)
}

func validateRef(ref blob.Ref) error {
	if ref.Size < 0 || !validSHA256(ref.SHA256) {
		return errors.New("invalid blob reference")
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func matches(info ObjectInfo, ref blob.Ref) bool {
	return info.Size == ref.Size && (info.SHA256 == "" || info.SHA256 == ref.SHA256) && info.Metadata["sha256"] == ref.SHA256 && info.Metadata["size"] == fmt.Sprintf("%d", ref.Size)
}
