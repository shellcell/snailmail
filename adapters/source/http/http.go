package httpsource

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/shellcell/snailmail/source"
)

const maximumRedirects = 3

type Fetcher struct {
	client *http.Client
}

func New() *Fetcher {
	fetcher := &Fetcher{}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext:           fetcher.dialContext,
	}
	fetcher.client = &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(request *http.Request, prior []*http.Request) error {
			if len(prior) >= maximumRedirects {
				return errors.New("too many repository redirects")
			}
			return ValidatePublicURL(request.URL)
		},
	}
	return fetcher
}

func (fetcher *Fetcher) Fetch(ctx context.Context, rawURL string, maximum int64) (source.Response, error) {
	if maximum <= 0 {
		return source.Response{}, errors.New("response size limit must be positive")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return source.Response{}, fmt.Errorf("parse repository URL: %w", err)
	}
	if err := ValidatePublicURL(parsed); err != nil {
		return source.Response{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return source.Response{}, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "snailmail-doctor/1")
	response, err := fetcher.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return source.Response{}, ctx.Err()
		}
		return source.Response{}, errors.New("repository HTTPS request failed")
	}
	defer response.Body.Close()
	result := source.Response{URL: response.Request.URL.String(), StatusCode: response.StatusCode, ContentType: response.Header.Get("Content-Type")}
	if response.StatusCode != http.StatusOK {
		return result, nil
	}
	if response.Header.Get("Content-Range") != "" {
		return source.Response{}, errors.New("repository returned an unsolicited partial response")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return source.Response{}, fmt.Errorf("unsupported HTTP content encoding %q", encoding)
	}
	if response.ContentLength > maximum {
		return source.Response{}, fmt.Errorf("%w: maximum is %d bytes", source.ErrLimit, maximum)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return source.Response{}, err
	}
	if int64(len(content)) > maximum {
		return source.Response{}, fmt.Errorf("%w: maximum is %d bytes", source.ErrLimit, maximum)
	}
	result.Body = content
	return result, nil
}

func ValidatePublicURL(value *url.URL) error {
	if value == nil || value.Scheme != "https" || value.Host == "" || value.Hostname() == "" {
		return errors.New("repository URL must be an absolute HTTPS URL")
	}
	if value.User != nil || value.RawQuery != "" || value.Fragment != "" {
		return errors.New("repository URL must not contain credentials, query, or fragment")
	}
	if strings.ContainsAny(value.String(), "\x00\r\n\\") || strings.Contains(value.Path, "\\") || strings.IndexFunc(value.Path, unicode.IsControl) >= 0 || strings.Contains(strings.ToLower(value.RawPath), "%2f") || strings.Contains(strings.ToLower(value.RawPath), "%5c") {
		return errors.New("repository URL contains unsafe path characters")
	}
	for _, segment := range strings.Split(value.Path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("repository URL contains unsafe dot segments")
		}
	}
	return nil
}

func (fetcher *Fetcher) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	allowed := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if isPublicAddress(address) {
			allowed = append(allowed, address)
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("repository host has no public network address")
	}
	sort.Slice(allowed, func(left, right int) bool { return allowed[left].Less(allowed[right]) })
	var dialer net.Dialer
	for _, address := range allowed {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		connection, err := dialer.DialContext(attemptCtx, network, net.JoinHostPort(address.String(), port))
		cancel()
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("repository public addresses are unreachable")
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
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

var _ source.Fetcher = (*Fetcher)(nil)
