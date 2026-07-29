package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"

	semver "github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

// indexChartVersion is one published chart version as index.yaml describes it.
// Named rather than inline so the checks over it can be, too.
type indexChartVersion struct {
	Name    string   `yaml:"name"`
	Version string   `yaml:"version"`
	Digest  string   `yaml:"digest"`
	URLs    []string `yaml:"urls"`
}

type RepositoryChart struct {
	Name    string
	Version string
	Digest  string
	URLs    []string
}

func ParseRepositoryIndex(content []byte) ([]RepositoryChart, error) {
	if len(content) > 256<<10 {
		return nil, errors.New("Helm repository index exceeds 256 KiB")
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil || validateRepositoryNode(&root, 0, new(int)) != nil {
		return nil, errors.New("invalid Helm repository index")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid Helm repository index")
	} else if err == nil && len(extra.Content) != 0 {
		return nil, errors.New("Helm repository index has multiple documents")
	}
	var document struct {
		APIVersion string                         `yaml:"apiVersion"`
		Entries    map[string][]indexChartVersion `yaml:"entries"`
	}
	if err := root.Decode(&document); err != nil || document.APIVersion != "v1" || document.Entries == nil {
		return nil, errors.New("invalid Helm repository index")
	}
	if len(document.Entries) > 100000 {
		return nil, errors.New("Helm repository index has too many charts")
	}
	var result []RepositoryChart
	identities := make(map[string]string)
	for key, versions := range document.Entries {
		for _, version := range versions {
			if err := validateChartEntry(key, version); err != nil {
				return nil, err
			}
			for _, rawURL := range version.URLs {
				if err := validateChartURL(rawURL); err != nil {
					return nil, err
				}
			}
			identity := key + "\x00" + version.Version
			if existing := identities[identity]; existing != "" {
				return nil, errors.New("Helm repository has a duplicate chart version")
			}
			identities[identity] = version.Digest
			result = append(result, RepositoryChart{Name: key, Version: version.Version, Digest: version.Digest, URLs: append([]string(nil), version.URLs...)})
			if len(result) > 100000 {
				return nil, errors.New("Helm repository index has too many versions")
			}
		}
	}
	return result, nil
}

func validateRepositoryNode(node *yaml.Node, depth int, count *int) error {
	*count++
	if depth > 64 || *count > 10000 || node.Kind == yaml.AliasNode || len(node.Value) > 256<<10 {
		return errors.New("unsafe Helm repository YAML")
	}
	for _, child := range node.Content {
		if err := validateRepositoryNode(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

// validateChartEntry checks one entry of a published index.
//
// It is written as separate checks rather than one boolean because every one of
// them is a different thing being wrong, and an operator reading a rejected
// index needs to know which. The single condition this replaced tested eleven
// things and reported "invalid Helm repository chart entry" for all of them.
func validateChartEntry(key string, version indexChartVersion) error {
	switch {
	case key == "":
		return errors.New("Helm repository index has a chart with no name")
	case len(key) > 255:
		return fmt.Errorf("Helm chart name is %d characters, over the 255 limit", len(key))
	case !chartNamePattern.MatchString(key):
		return fmt.Errorf("Helm chart name %q is not a valid chart name", key)
	case version.Name != key:
		return fmt.Errorf("Helm chart %q is indexed under %q", version.Name, key)
	case len(version.Version) > 255:
		return fmt.Errorf("Helm chart %q has a version of %d characters, over the 255 limit", key, len(version.Version))
	}
	if _, err := semver.NewVersion(version.Version); err != nil {
		return fmt.Errorf("Helm chart %q has version %q, which is not semver: %w", key, version.Version, err)
	}
	decoded, err := hex.DecodeString(version.Digest)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("Helm chart %s@%s has a digest that is not a SHA-256", key, version.Version)
	}
	if version.Digest != strings.ToLower(version.Digest) {
		return fmt.Errorf("Helm chart %s@%s has an uppercase digest, which compares unequal to its lowercase form", key, version.Version)
	}
	if len(version.URLs) == 0 {
		return fmt.Errorf("Helm chart %s@%s has no download URL", key, version.Version)
	}
	if len(version.URLs) > 3 {
		return fmt.Errorf("Helm chart %s@%s lists %d download URLs, over the limit of 3", key, version.Version, len(version.URLs))
	}
	return nil
}

// validateChartURL refuses a download URL that could point somewhere other than
// where it appears to.
//
// Percent-encoded separators are rejected before the path is examined, because
// url.Parse decodes them: a %2f that reached the segment check below would have
// already become a separator, and one that did not would hide one.
func validateChartURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("Helm chart entry has an empty download URL")
	}
	if len(rawURL) > 4096 {
		return fmt.Errorf("Helm chart download URL is %d characters, over the 4096 limit", len(rawURL))
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("Helm chart download URL %q is unparseable: %w", rawURL, err)
	}
	lower := strings.ToLower(rawURL)
	switch {
	case parsed.User != nil:
		return fmt.Errorf("Helm chart download URL %q carries credentials", rawURL)
	case parsed.RawQuery != "" || parsed.Fragment != "":
		return fmt.Errorf("Helm chart download URL %q has a query or fragment", rawURL)
	case strings.IndexFunc(parsed.Path, unicode.IsControl) >= 0:
		return fmt.Errorf("Helm chart download URL %q has a control character in its path", rawURL)
	case strings.Contains(rawURL, "\\"):
		return fmt.Errorf("Helm chart download URL %q contains a backslash", rawURL)
	case strings.Contains(lower, "%2f"), strings.Contains(lower, "%5c"), strings.Contains(lower, "%2e"):
		return fmt.Errorf("Helm chart download URL %q percent-encodes a path separator or dot", rawURL)
	case parsed.Scheme != "" && parsed.Scheme != "https":
		return fmt.Errorf("Helm chart download URL %q uses scheme %q, not https", rawURL, parsed.Scheme)
	case parsed.Scheme == "https" && parsed.Host == "":
		return fmt.Errorf("Helm chart download URL %q is https with no host", rawURL)
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("Helm chart download URL %q traverses its own path", rawURL)
		}
	}
	return nil
}
