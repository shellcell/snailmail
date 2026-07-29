package helm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// ProvenanceSuffix is appended to a chart's published path to name the file
// carrying its signature.
const ProvenanceSuffix = ".prov"

// ProvenancePayload builds the document a chart's provenance signature covers.
//
// Helm signs each chart rather than the repository index, which is why this
// exists at all: every other format snailmail signs has one document per
// repository, and a Helm repository has one per chart.
//
// The document is the chart's own metadata, a YAML end-of-document marker, and
// a map from the published archive filename to its SHA-256. `helm verify`
// checks the signature over the whole document and then checks that the digest
// recorded for the archive's basename is the digest of the archive in hand, so
// the metadata is carried rather than checked. It is still reproduced exactly
// as the chart declares it: a signed document that paraphrased the chart would
// be attesting to something nobody published.
//
// Keys are emitted in sorted order because that is what Helm's own signer
// produces — it marshals through JSON, which sorts — and a provenance file that
// differed only in field order would look tampered with to anyone diffing one
// against the other.
func ProvenancePayload(filename string, reader io.ReaderAt, size int64) ([]byte, error) {
	return ProvenancePayloadWithExpandedLimit(filename, reader, size, maxExpandedSize)
}

func ProvenancePayloadWithExpandedLimit(filename string, reader io.ReaderAt, size, maximumExpanded int64) ([]byte, error) {
	// Inspect first, so provenance is only ever made for an archive that has
	// already been established to be the chart it claims to be. Signing an
	// archive this package would refuse would put a signature on bytes nothing
	// else in the system accepts.
	if _, err := InspectWithExpandedLimit(filename, reader, size, maximumExpanded); err != nil {
		return nil, err
	}
	chartYAML, _, _, err := readChartYAML(filename, reader, size, maximumExpanded)
	if err != nil {
		return nil, err
	}
	metadata, err := sortedMetadata(chartYAML)
	if err != nil {
		return nil, fmt.Errorf("provenance %q: %w", filename, err)
	}
	digest, err := archiveDigest(reader, size)
	if err != nil {
		return nil, fmt.Errorf("provenance %q: %w", filename, err)
	}

	var document bytes.Buffer
	document.Write(metadata)
	// The marker separates the two YAML documents. Helm writes it with a blank
	// line before it, which falls out of the metadata's own trailing newline.
	document.WriteString("\n...\n")
	// Two-space indentation, because Helm's signer marshals through JSON and
	// that is what it emits; yaml.v3 defaults to four. The difference changes no
	// meaning and every byte of the signature.
	sums, err := encodeYAML(map[string]map[string]string{
		"files": {filename: "sha256:" + digest},
	})
	if err != nil {
		return nil, fmt.Errorf("provenance %q: %w", filename, err)
	}
	document.Write(sums)
	return document.Bytes(), nil
}

// sortedMetadata re-serializes Chart.yaml with its keys in sorted order.
//
// It round-trips the document rather than a struct of known fields so a chart
// that declares keywords, maintainers or annotations has them carried into what
// is signed. A struct would silently drop whatever it had no field for, and the
// signed document would then describe a chart slightly different from the one
// published.
func sortedMetadata(chartYAML []byte) ([]byte, error) {
	var document map[string]any
	if err := yaml.Unmarshal(chartYAML, &document); err != nil {
		return nil, fmt.Errorf("parse Chart.yaml: %w", err)
	}
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var out bytes.Buffer
	for _, key := range keys {
		// Each entry is marshalled on its own so the value is quoted however
		// YAML requires, without depending on how a map happens to be ordered.
		encoded, err := encodeYAML(map[string]any{key: document[key]})
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
	}
	return out.Bytes(), nil
}

func archiveDigest(reader io.ReaderAt, size int64) (string, error) {
	hash := sha256.New()
	read, err := io.Copy(hash, io.NewSectionReader(reader, 0, size))
	if err != nil {
		return "", err
	}
	if read != size {
		return "", fmt.Errorf("chart is %d bytes, not the declared %d", read, size)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// encodeYAML marshals with the indentation Helm's provenance files use.
func encodeYAML(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
