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
			// A redirect target is the server's choice and may carry a signature
			// in its query, which is how release and object-storage downloads
			// work; the operator's URL is still held to the stricter rule.
			return source.ValidateRedirectURL(request.URL)
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
	return source.ValidatePublicURL(value)
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
	return source.IsPublicAddress(address)
}

var _ source.Fetcher = (*Fetcher)(nil)
