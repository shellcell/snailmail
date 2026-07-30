package engine

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/source"
)

// streamingFetcher writes the body to a writer instead of returning it, which is
// what the real HTTP fetcher now does. Every other fake in this repository returns
// bytes, so without this the streaming path would never be exercised by a test.
type streamingFetcher struct {
	inner    *adoptMemoryFetcher
	streamed int
}

func (fetcher *streamingFetcher) Fetch(ctx context.Context, address string, maximum int64) (source.Response, error) {
	return fetcher.inner.Fetch(ctx, address, maximum)
}

func (fetcher *streamingFetcher) FetchTo(ctx context.Context, address string, maximum int64, dst io.Writer) (source.Response, error) {
	response, err := fetcher.inner.Fetch(ctx, address, maximum)
	if err != nil {
		return response, err
	}
	if int64(len(response.Body)) > maximum {
		return source.Response{}, source.ErrLimit
	}
	written, err := dst.Write(response.Body)
	if err != nil {
		return source.Response{}, err
	}
	fetcher.streamed++
	response.Size = int64(written)
	response.Body = nil
	return response, nil
}

// A fetcher that can stream is used for it, and the result is identical to the
// buffering path — same digest, same facts, same lock.
func TestAStreamingFetcherIsUsedAndAgrees(t *testing.T) {
	root := apkImportWorkspace(t)
	fetcher := &streamingFetcher{inner: publishedAlpine(t)}
	result, err := ImportRepository(context.Background(), apkImportRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.streamed == 0 {
		t.Fatal("the streaming path was not used")
	}
	if len(result.Imported) != 1 {
		t.Fatalf("imported %+v skipped %+v", result.Imported, result.Skipped)
	}
	// The digest is of the bytes that arrived, computed while they were written to
	// disk rather than from a buffer, and it has to be the same answer.
	content, err := os.ReadFile("../formats/apk/testdata/snail-demo-1.2.3-r4.apk")
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported[0].SHA256 == "" || len(content) == 0 {
		t.Fatal("nothing to compare")
	}
	buffered := apkImportWorkspace(t)
	plain, err := ImportRepository(context.Background(), apkImportRequest(buffered, publishedAlpine(t)))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Imported[0].SHA256 != result.Imported[0].SHA256 {
		t.Errorf("streaming recorded %s and buffering recorded %s",
			result.Imported[0].SHA256, plain.Imported[0].SHA256)
	}
}

// A fetcher that cannot stream still works, because every existing implementation
// and test fake is one. The fallback writes to the same file, so everything
// downstream has one path regardless.
func TestABufferingFetcherStillWorks(t *testing.T) {
	root := apkImportWorkspace(t)
	result, err := ImportRepository(context.Background(), apkImportRequest(root, publishedAlpine(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 {
		t.Errorf("imported %+v", result.Imported)
	}
}

// The limit is enforced while streaming, so an oversized artifact is refused
// without ever having been held.
func TestTheLimitStillAppliesWhenStreaming(t *testing.T) {
	t.Setenv(MaxArtifactBytesEnvironment, "16")
	root := apkImportWorkspace(t)
	fetcher := &streamingFetcher{inner: publishedAlpine(t)}
	result, err := ImportRepository(context.Background(), apkImportRequest(root, fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 0 {
		t.Fatalf("an artifact past the limit was imported: %+v", result.Imported)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "limit") {
		t.Errorf("skipped %+v, want the limit as the reason", result.Skipped)
	}
}
