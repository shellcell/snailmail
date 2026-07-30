package source

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

var ErrLimit = errors.New("source response exceeds limit")

// ValidatePublicURL accepts a URL an operator supplied. It refuses a query
// string because that URL is recorded as an artifact's origin and committed, and
// a query is where a credential would hide.
func ValidatePublicURL(value *url.URL) error {
	if value != nil && value.RawQuery != "" {
		return errors.New("source URL must not contain credentials, query, or fragment")
	}
	return validateURL(value)
}

// ValidateRedirectURL accepts a location a server chose rather than the operator.
//
// It permits a query string, because that is where object storage puts its
// signature: GitHub release assets, S3 presigned URLs and Azure SAS all redirect
// to one. Refusing it made every GitHub Release asset unfetchable. The redirect
// target is never recorded — the operator's URL is what the lock pins — so a
// signature cannot leak into the workspace, and every other protection holds.
func ValidateRedirectURL(value *url.URL) error {
	return validateURL(value)
}

func validateURL(value *url.URL) error {
	if value == nil || value.Scheme != "https" || value.Host == "" || value.Hostname() == "" {
		return errors.New("source URL must be an absolute HTTPS URL")
	}
	if value.User != nil || value.Fragment != "" {
		return errors.New("source URL must not contain credentials, query, or fragment")
	}
	hostname := strings.TrimSuffix(strings.ToLower(value.Hostname()), ".")
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return errors.New("source URL host is not public")
	}
	if address, err := netip.ParseAddr(hostname); err == nil && !IsPublicAddress(address) {
		return errors.New("source URL address is not public")
	}
	if strings.ContainsAny(value.String(), "\x00\r\n\\") || strings.Contains(value.Path, "\\") || strings.IndexFunc(value.Path, unicode.IsControl) >= 0 || strings.Contains(strings.ToLower(value.RawPath), "%2f") || strings.Contains(strings.ToLower(value.RawPath), "%5c") {
		return errors.New("source URL contains unsafe path characters")
	}
	for _, segment := range strings.Split(value.Path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("source URL contains unsafe dot segments")
		}
	}
	return nil
}

func IsPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

type Response struct {
	URL         string
	StatusCode  int
	ContentType string
	// Body is the whole response, and is empty when it was streamed to a writer
	// instead. Size reports how many bytes arrived either way, so a caller that
	// streamed still knows what it received.
	Body []byte
	Size int64
}

type Fetcher interface {
	Fetch(context.Context, string, int64) (Response, error)
}

// StreamingFetcher writes a response body to a writer instead of returning it.
//
// Optional, discovered by type assertion the way a host's collector and a format's
// root rewrite are. A fetcher that does not implement it still works — the caller
// falls back to Fetch — so every existing implementation and every test fake is
// unaffected by this existing.
//
// It exists because Response.Body is a []byte, which means an adopted artifact is
// held whole in memory purely to be hashed and then written to disk. Nothing in
// that sequence needs the bytes at once, and the 128 MiB bound on it is a memory
// limit wearing the costume of a policy about package size.
type StreamingFetcher interface {
	// FetchTo writes the body to dst and returns the response without it. The
	// limit is enforced while copying, so an oversized body is refused without
	// having been held.
	FetchTo(ctx context.Context, url string, maximum int64, dst io.Writer) (Response, error)
}
