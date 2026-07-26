package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode"

	semver "github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

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
		APIVersion string `yaml:"apiVersion"`
		Entries    map[string][]struct {
			Name    string   `yaml:"name"`
			Version string   `yaml:"version"`
			Digest  string   `yaml:"digest"`
			URLs    []string `yaml:"urls"`
		} `yaml:"entries"`
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
			decoded, digestErr := hex.DecodeString(version.Digest)
			_, versionErr := semver.NewVersion(version.Version)
			if key == "" || len(key) > 255 || !chartNamePattern.MatchString(key) || version.Name != key || len(version.Version) > 255 || versionErr != nil || digestErr != nil || len(decoded) != sha256.Size || version.Digest != strings.ToLower(version.Digest) || len(version.URLs) == 0 || len(version.URLs) > 3 {
				return nil, errors.New("invalid Helm repository chart entry")
			}
			for _, rawURL := range version.URLs {
				parsed, err := url.Parse(rawURL)
				lower := strings.ToLower(rawURL)
				if err != nil || rawURL == "" || len(rawURL) > 4096 || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.IndexFunc(parsed.Path, unicode.IsControl) >= 0 || strings.Contains(rawURL, "\\") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") || parsed.Scheme != "" && parsed.Scheme != "https" || parsed.Scheme == "https" && parsed.Host == "" {
					return nil, errors.New("Helm repository chart entry has an unsafe URL")
				}
				for _, segment := range strings.Split(parsed.Path, "/") {
					if segment == "." || segment == ".." {
						return nil, errors.New("Helm repository chart entry has an unsafe URL")
					}
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
