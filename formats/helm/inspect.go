package helm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/shellcell/snailmail/internal/domain"
)

const (
	MaxArtifactSize   = 256 << 20
	maxExpandedSize   = 512 << 20
	maxArchiveEntries = 100_000
	maxArchivePath    = 1_024
	maxChartYAML      = 1 << 20
)

var chartNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type chartMetadata struct {
	APIVersion  string `yaml:"apiVersion"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	KubeVersion string `yaml:"kubeVersion"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	Home        string `yaml:"home"`
	Icon        string `yaml:"icon"`
	AppVersion  string `yaml:"appVersion"`
	Deprecated  bool   `yaml:"deprecated"`
}

func IsChartFilename(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".tgz")
}

// Inspect derives chart metadata from the exact archive bytes and validates
// the complete tar stream before returning facts.
func Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	return InspectWithExpandedLimit(filename, reader, size, maxExpandedSize)
}

func InspectWithExpandedLimit(filename string, reader io.ReaderAt, size, maximumExpanded int64) (domain.PackageFacts, error) {
	if !IsChartFilename(filename) {
		return domain.PackageFacts{}, fmt.Errorf("unsupported Helm chart %q", filename)
	}
	if size < 1 || size > MaxArtifactSize {
		return domain.PackageFacts{}, fmt.Errorf("Helm chart size %d is outside the supported range", size)
	}
	if maximumExpanded < maxChartYAML || maximumExpanded > maxExpandedSize {
		return domain.PackageFacts{}, errors.New("Helm expanded-size limit is outside the supported range")
	}
	chartYAML, root, expandedSize, err := readChartYAML(filename, reader, size, maximumExpanded)
	if err != nil {
		return domain.PackageFacts{}, err
	}
	if err := validateMetadataScalars(chartYAML); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	var metadata chartMetadata
	if err := yaml.Unmarshal(chartYAML, &metadata); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: parse Chart.yaml: %w", filename, err)
	}
	if metadata.APIVersion != "v1" && metadata.APIVersion != "v2" {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: unsupported chart apiVersion %q", filename, metadata.APIVersion)
	}
	if !chartNamePattern.MatchString(metadata.Name) || root != metadata.Name {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: chart name %q does not match archive root %q", filename, metadata.Name, root)
	}
	if _, err := semver.NewVersion(metadata.Version); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid chart version %q", filename, metadata.Version)
	}
	if metadata.Type != "" && metadata.Type != "application" && metadata.Type != "library" {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid chart type %q", filename, metadata.Type)
	}
	if filename != metadata.Name+"-"+metadata.Version+".tgz" {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: filename does not match chart identity", filename)
	}
	for field, value := range map[string]string{
		"apiVersion":  metadata.APIVersion,
		"appVersion":  metadata.AppVersion,
		"description": metadata.Description,
		"type":        metadata.Type,
		"kubeVersion": metadata.KubeVersion,
		"home":        metadata.Home,
		"icon":        metadata.Icon,
	} {
		if strings.ContainsAny(value, "\x00\r") {
			return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid %s value", filename, field)
		}
	}
	return domain.PackageFacts{
		Name:          metadata.Name,
		Version:       metadata.Version,
		InstalledSize: expandedSize,
		Fields: map[string]string{
			"apiVersion":  metadata.APIVersion,
			"appVersion":  metadata.AppVersion,
			"description": metadata.Description,
			"type":        metadata.Type,
			"kubeVersion": metadata.KubeVersion,
			"home":        metadata.Home,
			"icon":        metadata.Icon,
			"deprecated":  fmt.Sprintf("%t", metadata.Deprecated),
		},
	}, nil
}

func validateMetadataScalars(content []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("parse Chart.yaml nodes: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("Chart.yaml must be a mapping")
	}
	requiredStrings := map[string]bool{"apiVersion": true, "name": true, "version": true}
	found := make(map[string]bool)
	mapping := document.Content[0]
	for index := 0; index < len(mapping.Content); index += 2 {
		key, value := mapping.Content[index], mapping.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return errors.New("Chart.yaml field names must be strings")
		}
		if requiredStrings[key.Value] {
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return fmt.Errorf("Chart.yaml field %s must be a string", key.Value)
			}
			found[key.Value] = true
		}
	}
	for name := range requiredStrings {
		if !found[name] {
			return fmt.Errorf("Chart.yaml field %s is required", name)
		}
	}
	return nil
}

// readChartYAML walks the archive and returns the chart's Chart.yaml.
//
// It is separate from Inspect because provenance signs a document built from
// the same Chart.yaml the facts came from. Two walks would be two readings of
// one archive, and a signature made over the second while the lock recorded the
// first is exactly the disagreement signing is supposed to rule out.
func readChartYAML(filename string, reader io.ReaderAt, size, maximumExpanded int64) (chart []byte, chartRoot string, expanded int64, err error) {
	compressed, err := gzip.NewReader(io.NewSectionReader(reader, 0, size))
	if err != nil {
		return nil, "", 0, fmt.Errorf("inspect %q: open gzip: %w", filename, err)
	}
	defer compressed.Close()
	limited := &io.LimitedReader{R: compressed, N: maximumExpanded + 1}
	archive := tar.NewReader(limited)
	root := ""
	var chartYAML []byte
	var expandedSize int64
	entries := 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", 0, fmt.Errorf("inspect %q: read archive: %w", filename, err)
		}
		entries++
		if entries > maxArchiveEntries {
			return nil, "", 0, fmt.Errorf("inspect %q: archive has too many entries", filename)
		}
		if len(header.Name) > maxArchivePath {
			return nil, "", 0, fmt.Errorf("inspect %q: archive path is too long", filename)
		}
		// "." is the archive root, not a path within it. `helm package` writes no
		// such entry, but tar does, and a chart rolled by hand is still a chart.
		clean := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, "", 0, fmt.Errorf("inspect %q: unsafe archive path %q", filename, header.Name)
		}
		if clean == "." {
			// The root entry names no chart directory, so it neither sets nor
			// contradicts the single root a chart must have.
			continue
		}
		entryRoot := strings.SplitN(clean, "/", 2)[0]
		if root == "" {
			root = entryRoot
		} else if root != entryRoot {
			return nil, "", 0, fmt.Errorf("inspect %q: chart has multiple archive roots", filename)
		}
		switch header.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maximumExpanded-expandedSize {
				return nil, "", 0, fmt.Errorf("inspect %q: expanded chart exceeds limit", filename)
			}
			expandedSize += header.Size
			if clean == root+"/Chart.yaml" {
				if chartYAML != nil {
					return nil, "", 0, fmt.Errorf("inspect %q: duplicate Chart.yaml", filename)
				}
				if header.Size > maxChartYAML {
					return nil, "", 0, fmt.Errorf("inspect %q: Chart.yaml exceeds 1 MiB", filename)
				}
				chartYAML, err = io.ReadAll(io.LimitReader(archive, maxChartYAML+1))
				if err != nil {
					return nil, "", 0, fmt.Errorf("inspect %q: read Chart.yaml: %w", filename, err)
				}
			}
		default:
			return nil, "", 0, fmt.Errorf("inspect %q: unsupported archive entry %q", filename, header.Name)
		}
	}
	if limited.N <= 0 {
		return nil, "", 0, fmt.Errorf("inspect %q: expanded chart exceeds limit", filename)
	}
	// The tar walk stops at the end-of-archive marker, which comes before gzip's
	// CRC and length trailer — so without reading the rest, those are never
	// checked and an archive missing its last eight bytes parses as a valid
	// chart. Draining the stream is what makes the compressed bytes have to
	// agree with what was decompressed from them.
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return nil, "", 0, fmt.Errorf("inspect %q: read archive: %w", filename, err)
	}
	if chartYAML == nil {
		return nil, "", 0, fmt.Errorf("inspect %q: Chart.yaml not found", filename)
	}
	return chartYAML, root, expandedSize, nil
}
