package pypi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

const maximumSimpleLinks = 100000

type SimpleProject struct {
	Name string
	URL  string
}

type SimpleFile struct {
	Filename  string
	URL       string
	SHA256    string
	Supported bool
}

// MaximumIndexBytes bounds a published index this reads.
//
// Set from measurement rather than guessed, because the previous 2 MiB refused
// real repositories: numpy's simple page is 2.2 MB and boto3's is 1.5 MB and
// growing, so the limit that was meant to bound a hostile response was quietly
// excluding ordinary ones. 32 MiB leaves room for the largest index observed —
// prometheus-community's Helm index at 6.2 MB — with headroom, while still
// refusing a response that could exhaust memory.
const MaximumIndexBytes = 32 << 20

func ParseSimpleIndex(contentType string, content []byte) ([]SimpleProject, error) {
	if len(content) > MaximumIndexBytes {
		return nil, errors.New("PyPI project index exceeds the readable size")
	}
	if strings.Contains(strings.ToLower(contentType), "json") || firstNonSpace(content) == '{' {
		var document struct {
			Meta struct {
				API string `json:"api-version"`
			} `json:"meta"`
			Projects []struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(content, &document); err != nil || !supportedSimpleAPI(document.Meta.API) || document.Projects == nil {
			return nil, errors.New("invalid PEP 691 project index")
		}
		if len(document.Projects) > maximumSimpleLinks {
			return nil, errors.New("PyPI project index has too many entries")
		}
		result := make([]SimpleProject, 0, len(document.Projects))
		seen := make(map[string]bool, len(document.Projects))
		for _, project := range document.Projects {
			if !validSimpleName(project.Name) {
				return nil, errors.New("PyPI project index has an invalid project link")
			}
			if project.URL == "" {
				project.URL = NormalizeName(project.Name) + "/"
			}
			if err := validateSimpleProjectURL(project.URL, project.Name); err != nil {
				return nil, err
			}
			identity := NormalizeName(project.Name)
			if seen[identity] {
				return nil, errors.New("PyPI project index has a duplicate normalized project")
			}
			seen[identity] = true
			result = append(result, SimpleProject{Name: project.Name, URL: project.URL})
		}
		return result, nil
	}
	if !bytes.Contains(bytes.ToLower(content), []byte("</html>")) {
		return nil, errors.New("PyPI project index is incomplete HTML")
	}
	links, err := htmlLinks(content)
	if err != nil {
		return nil, err
	}
	result := make([]SimpleProject, 0, len(links))
	seen := make(map[string]bool, len(links))
	for _, link := range links {
		name := strings.TrimSpace(link.text)
		if !validSimpleName(name) {
			return nil, errors.New("PyPI project index has an invalid project name")
		}
		if err := validateSimpleProjectURL(link.href, name); err != nil {
			return nil, err
		}
		identity := NormalizeName(name)
		if seen[identity] {
			return nil, errors.New("PyPI project index has a duplicate normalized project")
		}
		seen[identity] = true
		result = append(result, SimpleProject{Name: name, URL: link.href})
	}
	return result, nil
}

func ParseSimpleProject(contentType string, content []byte) (string, []SimpleFile, error) {
	if len(content) > MaximumIndexBytes {
		return "", nil, errors.New("PyPI project page exceeds the readable size")
	}
	if strings.Contains(strings.ToLower(contentType), "json") || firstNonSpace(content) == '{' {
		var document struct {
			Meta struct {
				API string `json:"api-version"`
			} `json:"meta"`
			Name  string `json:"name"`
			Files []struct {
				Filename string            `json:"filename"`
				URL      string            `json:"url"`
				Hashes   map[string]string `json:"hashes"`
			} `json:"files"`
		}
		if err := json.Unmarshal(content, &document); err != nil || !supportedSimpleAPI(document.Meta.API) || !validSimpleName(document.Name) || document.Files == nil {
			return "", nil, errors.New("invalid PEP 691 project page")
		}
		if len(document.Files) > maximumSimpleLinks {
			return "", nil, errors.New("PyPI project page has too many files")
		}
		result := make([]SimpleFile, 0, len(document.Files))
		seen := make(map[string]bool, len(document.Files))
		for _, file := range document.Files {
			if file.Hashes == nil {
				return "", nil, errors.New("PEP 691 project file has no hashes object")
			}
			if err := validateSimpleFile(file.Filename, file.URL, file.Hashes["sha256"]); err != nil {
				return "", nil, err
			}
			if seen[file.Filename] {
				return "", nil, errors.New("PyPI project page has a duplicate filename")
			}
			seen[file.Filename] = true
			result = append(result, SimpleFile{Filename: file.Filename, URL: file.URL, SHA256: file.Hashes["sha256"], Supported: IsDistributionFilename(file.Filename)})
		}
		return document.Name, result, nil
	}
	if !bytes.Contains(bytes.ToLower(content), []byte("</html>")) {
		return "", nil, errors.New("PyPI project page is incomplete HTML")
	}
	links, err := htmlLinks(content)
	if err != nil {
		return "", nil, err
	}
	result := make([]SimpleFile, 0, len(links))
	seen := make(map[string]bool, len(links))
	for _, link := range links {
		parsed, err := url.Parse(link.href)
		if err != nil {
			return "", nil, errors.New("PyPI project page has an invalid file URL")
		}
		filename := path.Base(parsed.Path)
		digest := strings.TrimPrefix(parsed.Fragment, "sha256=")
		if parsed.Fragment != "" && digest == parsed.Fragment {
			digest = ""
		}
		if err := validateSimpleFile(filename, link.href, digest); err != nil {
			return "", nil, err
		}
		if strings.TrimSpace(link.text) != filename {
			return "", nil, errors.New("PyPI project page link text does not match its filename")
		}
		if seen[filename] {
			return "", nil, errors.New("PyPI project page has a duplicate filename")
		}
		seen[filename] = true
		result = append(result, SimpleFile{Filename: filename, URL: link.href, SHA256: digest, Supported: IsDistributionFilename(filename)})
	}
	return "", result, nil
}

func validateSimpleFile(filename, rawURL, digest string) error {
	if filename == "" || filename != path.Base(filename) || len(filename) > 255 || strings.IndexFunc(filename, unicode.IsControl) >= 0 || rawURL == "" {
		return errors.New("PyPI project page has an invalid distribution link")
	}
	parsed, err := url.Parse(rawURL)
	lower := strings.ToLower(rawURL)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || strings.ContainsAny(rawURL, "\x00\r\n\\") || strings.IndexFunc(parsed.Path, unicode.IsControl) >= 0 || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") || parsed.Scheme != "" && parsed.Scheme != "https" || parsed.Scheme == "https" && parsed.Host == "" {
		return errors.New("PyPI project page has an unsafe distribution URL")
	}
	if digest != "" {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
			return errors.New("PyPI project page has an invalid SHA-256")
		}
	}
	return nil
}

func supportedSimpleAPI(value string) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 || parts[0] != "1" || parts[1] == "" {
		return false
	}
	for _, character := range parts[1] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validSimpleName(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) <= 255 && packageNamePattern.MatchString(value)
}

func validateSimpleProjectURL(rawURL, projectName string) error {
	if rawURL == "" {
		return errors.New("PyPI project index has an empty project URL")
	}
	if len(rawURL) > 4096 {
		return fmt.Errorf("PyPI project URL is %d characters, over the 4096 limit", len(rawURL))
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("PyPI project URL %q is unparseable: %w", rawURL, err)
	}
	lower := strings.ToLower(rawURL)
	// Percent-encoded separators are rejected before the path is examined,
	// because url.Parse decodes them: one that reached the segment check below
	// would already have become a separator, and one that did not would hide
	// one. An encoded dot needs no separate rule for the same reason — it
	// decodes into the path this walks.
	switch {
	case parsed.User != nil:
		return fmt.Errorf("PyPI project URL %q carries credentials", rawURL)
	case parsed.RawQuery != "" || parsed.Fragment != "":
		return fmt.Errorf("PyPI project URL %q has a query or fragment", rawURL)
	case strings.ContainsAny(rawURL, "\x00\r\n\\"):
		return fmt.Errorf("PyPI project URL %q contains a control character or backslash", rawURL)
	case strings.Contains(lower, "%2f"), strings.Contains(lower, "%5c"):
		return fmt.Errorf("PyPI project URL %q percent-encodes a path separator", rawURL)
	case parsed.Scheme != "" && parsed.Scheme != "https":
		return fmt.Errorf("PyPI project URL %q uses scheme %q, not https", rawURL, parsed.Scheme)
	case parsed.Scheme == "https" && parsed.Host == "":
		return fmt.Errorf("PyPI project URL %q is https with no host", rawURL)
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("PyPI project URL %q traverses its own path", rawURL)
		}
	}
	linkedName := path.Base(strings.TrimSuffix(parsed.Path, "/"))
	if NormalizeName(linkedName) != NormalizeName(projectName) {
		return errors.New("PyPI project URL does not match its normalized project name")
	}
	return nil
}

type simpleHTMLLink struct{ href, text string }

func htmlLinks(content []byte) ([]simpleHTMLLink, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(content))
	var result []simpleHTMLLink
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return result, nil
		case html.StartTagToken:
			token := tokenizer.Token()
			if token.Data != "a" {
				continue
			}
			href := ""
			for _, attribute := range token.Attr {
				if attribute.Key == "href" {
					href = attribute.Val
				}
			}
			if href == "" {
				continue
			}
			if len(result) >= maximumSimpleLinks {
				return nil, errors.New("PyPI page has too many links")
			}
			text := ""
			if tokenizer.Next() == html.TextToken {
				text = string(tokenizer.Text())
			}
			result = append(result, simpleHTMLLink{href: href, text: text})
		}
	}
}

func firstNonSpace(content []byte) byte {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return 0
	}
	return content[0]
}
