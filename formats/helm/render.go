package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "helm/v1"

type BuildOptions struct {
	GeneratedAt time.Time
}

type indexedChart struct {
	blob domain.Blob
	path string
}

func Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	if options.GeneratedAt.IsZero() {
		return domain.RepositoryArtifact{}, fmt.Errorf("generation time is required")
	}
	charts := make(map[string][]indexedChart)
	identityDigests := make(map[string]string)
	var files []domain.File
	seenFiles := make(map[string]bool)
	for _, blob := range blobs {
		if err := validateBlob(blob); err != nil {
			return domain.RepositoryArtifact{}, err
		}
		identity := blob.Facts.Name + "\x00" + blob.Facts.Version
		if previous := identityDigests[identity]; previous != "" {
			if previous != blob.SHA256 {
				return domain.RepositoryArtifact{}, fmt.Errorf("chart identity %s@%s is bound to different bytes", blob.Facts.Name, blob.Facts.Version)
			}
			continue
		}
		identityDigests[identity] = blob.SHA256
		chartPath := path.Join("charts", blob.SHA256, blob.Filename)
		charts[blob.Facts.Name] = append(charts[blob.Facts.Name], indexedChart{blob: blob, path: chartPath})
		if !seenFiles[chartPath] {
			files = append(files, domain.File{Path: chartPath, Size: blob.Size, SHA256: blob.SHA256, BlobSHA256: blob.SHA256})
			seenFiles[chartPath] = true
		}
	}
	index, verification, err := renderIndex(charts, options.GeneratedAt)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	files = append(files, domain.File{Path: "index.yaml", Content: index})
	return domain.RepositoryArtifact{
		Format:            FormatID,
		Files:             files,
		Install:           domain.InstallSpec{Kind: "helm", IndexPath: "index.yaml"},
		VerificationCases: verification,
	}, nil
}

func validateBlob(blob domain.Blob) error {
	if !IsChartFilename(blob.Filename) || !chartNamePattern.MatchString(blob.Facts.Name) || blob.Facts.Version == "" || blob.Size < 0 {
		return fmt.Errorf("Helm chart %q has invalid facts", blob.Filename)
	}
	if _, err := semver.NewVersion(blob.Facts.Version); err != nil {
		return fmt.Errorf("Helm chart %q has invalid version: %w", blob.Filename, err)
	}
	decoded, err := hex.DecodeString(blob.SHA256)
	if err != nil || len(decoded) != sha256.Size || blob.SHA256 != strings.ToLower(blob.SHA256) {
		return fmt.Errorf("Helm chart %q has an invalid SHA-256", blob.Filename)
	}
	if blob.Filename != blob.Facts.Name+"-"+blob.Facts.Version+".tgz" || blob.Facts.Fields["apiVersion"] == "" {
		return fmt.Errorf("Helm chart %q has inconsistent identity facts", blob.Filename)
	}
	return nil
}

func renderIndex(charts map[string][]indexedChart, generatedAt time.Time) ([]byte, []domain.VerificationCase, error) {
	names := make([]string, 0, len(charts))
	for name := range charts {
		names = append(names, name)
	}
	sort.Strings(names)
	var index strings.Builder
	index.WriteString("apiVersion: v1\nentries:\n")
	var verification []domain.VerificationCase
	seenCases := make(map[string]bool)
	for _, name := range names {
		versions := charts[name]
		sort.Slice(versions, func(i, j int) bool {
			left, _ := semver.NewVersion(versions[i].blob.Facts.Version)
			right, _ := semver.NewVersion(versions[j].blob.Facts.Version)
			comparison := left.Compare(right)
			if comparison != 0 {
				return comparison > 0
			}
			return versions[i].blob.SHA256 < versions[j].blob.SHA256
		})
		index.WriteString("  " + yamlString(name) + ":\n")
		for _, chart := range versions {
			fields := chart.blob.Facts.Fields
			index.WriteString("  - apiVersion: " + yamlString(fields["apiVersion"]) + "\n")
			writeOptionalYAML(&index, "    ", "appVersion", fields["appVersion"])
			index.WriteString("    created: " + yamlString(generatedAt.UTC().Format(time.RFC3339)) + "\n")
			if fields["deprecated"] == "true" {
				index.WriteString("    deprecated: true\n")
			}
			writeOptionalYAML(&index, "    ", "description", fields["description"])
			index.WriteString("    digest: " + yamlString(chart.blob.SHA256) + "\n")
			writeOptionalYAML(&index, "    ", "home", fields["home"])
			writeOptionalYAML(&index, "    ", "icon", fields["icon"])
			writeOptionalYAML(&index, "    ", "kubeVersion", fields["kubeVersion"])
			index.WriteString("    name: " + yamlString(chart.blob.Facts.Name) + "\n")
			writeOptionalYAML(&index, "    ", "type", fields["type"])
			index.WriteString("    urls:\n")
			index.WriteString("    - " + yamlString(chart.path) + "\n")
			index.WriteString("    version: " + yamlString(chart.blob.Facts.Version) + "\n")
			caseKey := chart.blob.Facts.Name + "\x00" + chart.blob.Facts.Version
			if !seenCases[caseKey] {
				verification = append(verification, domain.VerificationCase{Project: chart.blob.Facts.Name, Version: chart.blob.Facts.Version})
				seenCases[caseKey] = true
			}
		}
	}
	index.WriteString("generated: " + yamlString(generatedAt.UTC().Format(time.RFC3339)) + "\n")
	return []byte(index.String()), verification, nil
}

func writeOptionalYAML(output *strings.Builder, indent, name, value string) {
	if value != "" {
		output.WriteString(indent + name + ": " + yamlString(value) + "\n")
	}
}

func yamlString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
