package httpsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/source"
)

func TestValidatePublicURLRejectsUnsafeInputs(t *testing.T) {
	for _, raw := range []string{
		"http://packages.example/index.yaml",
		"https://user:secret@packages.example/index.yaml",
		"https://packages.example/index.yaml?token=secret",
		"https://packages.example/a%2fb",
		"https://packages.example/a\\b",
	} {
		parsed, _ := url.Parse(raw)
		if err := ValidatePublicURL(parsed); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestFetcherRejectsContentLengthBeforeReading(t *testing.T) {
	fetcher := &Fetcher{client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: 100, Body: io.NopCloser(strings.NewReader("ignored")), Header: make(http.Header), Request: request}, nil
	})}}
	if _, err := fetcher.Fetch(context.Background(), "https://packages.example/index.yaml", 10); !errors.Is(err, source.ErrLimit) {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestFetcherReturnsCompressed404WithoutReadingBody(t *testing.T) {
	fetcher := &Fetcher{client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Encoding", "gzip")
		return &http.Response{StatusCode: 404, Body: panicReadCloser{}, Header: header, Request: request}, nil
	})}}
	response, err := fetcher.Fetch(context.Background(), "https://packages.example/missing", 10)
	if err != nil || response.StatusCode != 404 {
		t.Fatalf("compressed 404 response=%#v err=%v", response, err)
	}
}

func TestFetcherRejectsUnsolicitedContentRange(t *testing.T) {
	fetcher := &Fetcher{client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Range", "bytes 0-3/10")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("part")), Header: header, Request: request}, nil
	})}}
	if _, err := fetcher.Fetch(context.Background(), "https://packages.example/index.yaml", 10); err == nil {
		t.Fatal("unsolicited partial response was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type panicReadCloser struct{}

func (panicReadCloser) Read([]byte) (int, error) { panic("404 body was read") }
func (panicReadCloser) Close() error             { return nil }

func TestPublicAddressPolicyRejectsNonPublicRanges(t *testing.T) {
	for _, raw := range []string{"0.1.2.3", "127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "100.64.0.1", "240.0.0.1", "::1", "64:ff9b::1", "64:ff9b:1::1", "2001:db8::1", "fec0::1"} {
		if isPublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %s", raw)
		}
	}
	if !isPublicAddress(netip.MustParseAddr("1.1.1.1")) || !isPublicAddress(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public resolver addresses were rejected")
	}
}
