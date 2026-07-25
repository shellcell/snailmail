package s3blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"testing"

	"github.com/shellcell/snailmail/blob"
)

func TestStorePutFetchContract(t *testing.T) {
	ctx := context.Background()
	client := newMemoryClient()
	configuration := blob.Configuration{Type: "s3", WorkspaceID: strings64("1"), Prefix: "cas"}
	store, err := New(client, configuration)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("immutable artifact")
	ref := refFor(content)
	if err := store.Put(ctx, ref, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	client.mutex.Lock()
	object := client.objects[store.key(ref)]
	object.info.SHA256 = ""
	client.objects[store.key(ref)] = object
	client.mutex.Unlock()
	if err := store.Put(ctx, ref, bytes.NewReader(content)); err != nil {
		t.Fatalf("idempotent put without provider checksum response: %v", err)
	}
	var fetched bytes.Buffer
	if err := store.Fetch(ctx, ref, &fetched); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetched.Bytes(), content) {
		t.Fatalf("fetched %q, want %q", fetched.Bytes(), content)
	}
}

func TestStoreRejectsImmutableConflictAndCorruptFetch(t *testing.T) {
	ctx := context.Background()
	client := newMemoryClient()
	store, err := New(client, blob.Configuration{Type: "s3", WorkspaceID: strings64("2")})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("expected")
	ref := refFor(content)
	key := store.key(ref)
	client.objects[key] = memoryObject{content: []byte("conflict"), info: infoFor([]byte("conflict"))}
	if err := store.Put(ctx, ref, bytes.NewReader(content)); err == nil {
		t.Fatal("expected immutable conflict")
	}
	client.objects[key] = memoryObject{content: []byte("corrupt!"), info: ObjectInfo{
		Size: ref.Size, SHA256: ref.SHA256, Metadata: map[string]string{"sha256": ref.SHA256, "size": strconv.FormatInt(ref.Size, 10)},
	}}
	if err := store.Fetch(ctx, ref, io.Discard); err == nil {
		t.Fatal("expected corrupt fetch to fail")
	}
	client.objects[key] = memoryObject{content: []byte("corrupt!"), info: ObjectInfo{
		Size: ref.Size, Metadata: map[string]string{"sha256": ref.SHA256, "size": strconv.FormatInt(ref.Size, 10)},
	}}
	if err := store.Put(ctx, ref, bytes.NewReader(content)); err == nil {
		t.Fatal("checksum-less corrupt destination was accepted")
	}
}

func TestStoreRejectsMissingAndInvalidReferences(t *testing.T) {
	store, err := New(newMemoryClient(), blob.Configuration{Type: "s3", WorkspaceID: strings64("3")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Fetch(context.Background(), refFor([]byte("missing")), io.Discard); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	if err := store.Put(context.Background(), blob.Ref{SHA256: "bad", Size: 1}, bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("expected invalid reference rejection")
	}
}

type memoryObject struct {
	content []byte
	info    ObjectInfo
}

type memoryClient struct {
	mutex   sync.Mutex
	objects map[string]memoryObject
}

func newMemoryClient() *memoryClient {
	return &memoryClient{objects: make(map[string]memoryObject)}
}

func (client *memoryClient) Head(_ context.Context, key string) (ObjectInfo, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	object, exists := client.objects[key]
	if !exists {
		return ObjectInfo{}, blob.ErrNotFound
	}
	return cloneInfo(object.info), nil
}

func (client *memoryClient) PutCreate(_ context.Context, key string, reader io.Reader, size int64, expectedSHA256 string, metadata map[string]string) (ObjectInfo, error) {
	content, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return ObjectInfo{}, err
	}
	if int64(len(content)) != size || digest(content) != expectedSHA256 {
		return ObjectInfo{}, errors.New("put body mismatch")
	}
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if _, exists := client.objects[key]; exists {
		return ObjectInfo{}, blob.ErrPrecondition
	}
	info := ObjectInfo{Size: size, SHA256: expectedSHA256, Metadata: cloneMetadata(metadata)}
	client.objects[key] = memoryObject{content: append([]byte(nil), content...), info: info}
	return cloneInfo(info), nil
}

func (client *memoryClient) Get(_ context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	object, exists := client.objects[key]
	if !exists {
		return nil, ObjectInfo{}, blob.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(object.content)), cloneInfo(object.info), nil
}

func refFor(content []byte) blob.Ref {
	return blob.Ref{SHA256: digest(content), Size: int64(len(content))}
}

func infoFor(content []byte) ObjectInfo {
	sha256Value := digest(content)
	return ObjectInfo{Size: int64(len(content)), SHA256: sha256Value, Metadata: map[string]string{
		"sha256": sha256Value, "size": fmt.Sprintf("%d", len(content)),
	}}
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return hex.EncodeToString(value[:])
}

func strings64(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}

func cloneInfo(info ObjectInfo) ObjectInfo {
	info.Metadata = cloneMetadata(info.Metadata)
	return info
}

func cloneMetadata(metadata map[string]string) map[string]string {
	result := make(map[string]string, len(metadata))
	for key, value := range metadata {
		result[key] = value
	}
	return result
}
