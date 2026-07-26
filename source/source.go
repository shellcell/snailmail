package source

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

var ErrLimit = errors.New("source response exceeds limit")

func ValidatePublicURL(value *url.URL) error {
	if value == nil || value.Scheme != "https" || value.Host == "" || value.Hostname() == "" {
		return errors.New("source URL must be an absolute HTTPS URL")
	}
	if value.User != nil || value.RawQuery != "" || value.Fragment != "" {
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
	Body        []byte
}

type Fetcher interface {
	Fetch(context.Context, string, int64) (Response, error)
}
