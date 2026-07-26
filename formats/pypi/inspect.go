package pypi

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
)

const maxMetadataSize = 1 << 20

const (
	MaxArtifactSize   = 1 << 30
	maxArchiveEntries = 10_000
	maxArchivePath    = 1_024
	maxTarScanBytes   = 64 << 20
	maxZipDirectory   = 16 << 20
)

var (
	packageNamePattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	versionPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.!+_-]*$`)
	requiresPythonPattern = regexp.MustCompile(`^[A-Za-z0-9.*<>=!~(), \t+-]*$`)
	wheelEscapePattern    = regexp.MustCompile(`[^A-Za-z0-9.]+`)
)

type embeddedMetadata struct {
	content []byte
	path    string
}

// IsDistributionFilename reports whether Phase 0 can inspect the artifact.
func IsDistributionFilename(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".whl") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".zip")
}

// Inspect derives package facts from wheel or source-distribution metadata.
func Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	if size < 0 || size > MaxArtifactSize {
		return domain.PackageFacts{}, fmt.Errorf("PyPI distribution size %d is outside the supported range", size)
	}
	lower := strings.ToLower(filename)
	var metadata embeddedMetadata
	var err error
	switch {
	case strings.HasSuffix(lower, ".whl"):
		metadata, err = metadataFromZip(reader, size, true)
	case strings.HasSuffix(lower, ".zip"):
		metadata, err = metadataFromZip(reader, size, false)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		metadata, err = metadataFromTarGz(reader, size)
	default:
		return domain.PackageFacts{}, fmt.Errorf("unsupported PyPI distribution %q", filename)
	}
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	facts, err := parseMetadata(metadata.content)
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	if err := validateDistributionIdentity(filename, metadata.path, facts); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	return facts, nil
}

func metadataFromZip(reader io.ReaderAt, size int64, wheel bool) (embeddedMetadata, error) {
	if err := validateZipDirectory(reader, size); err != nil {
		return embeddedMetadata{}, err
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return embeddedMetadata{}, fmt.Errorf("open zip: %w", err)
	}
	if len(archive.File) > maxArchiveEntries {
		return embeddedMetadata{}, fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
	}
	var candidates []*zip.File
	for _, file := range archive.File {
		if len(file.Name) > maxArchivePath {
			return embeddedMetadata{}, fmt.Errorf("archive path exceeds %d bytes", maxArchivePath)
		}
		clean := path.Clean(file.Name)
		if wheel && strings.HasSuffix(clean, ".dist-info/METADATA") {
			candidates = append(candidates, file)
		}
		if !wheel && path.Base(clean) == "PKG-INFO" {
			candidates = append(candidates, file)
		}
	}
	if len(candidates) == 0 {
		return embeddedMetadata{}, errors.New("package metadata not found")
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := path.Clean(candidates[i].Name), path.Clean(candidates[j].Name)
		leftDepth, rightDepth := strings.Count(left, "/"), strings.Count(right, "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return left < right
	})
	if wheel && len(candidates) != 1 {
		return embeddedMetadata{}, errors.New("wheel contains multiple METADATA files")
	}
	if candidates[0].UncompressedSize64 > maxMetadataSize {
		return embeddedMetadata{}, errors.New("package metadata exceeds 1 MiB")
	}
	stream, err := candidates[0].Open()
	if err != nil {
		return embeddedMetadata{}, fmt.Errorf("open metadata: %w", err)
	}
	defer stream.Close()
	content, err := io.ReadAll(io.LimitReader(stream, maxMetadataSize+1))
	if err != nil {
		return embeddedMetadata{}, err
	}
	return embeddedMetadata{content: content, path: path.Clean(candidates[0].Name)}, nil
}

func validateZipDirectory(reader io.ReaderAt, size int64) error {
	const (
		endRecordSize  = 22
		maxCommentSize = 1<<16 - 1
	)
	if size < endRecordSize {
		return errors.New("zip end record is missing")
	}
	tailSize := min(size, endRecordSize+maxCommentSize)
	tail := make([]byte, tailSize)
	if _, err := reader.ReadAt(tail, size-tailSize); err != nil {
		return fmt.Errorf("read zip end record: %w", err)
	}
	signature := []byte{'P', 'K', 0x05, 0x06}
	for offset := len(tail) - endRecordSize; offset >= 0; offset-- {
		if !bytes.Equal(tail[offset:offset+4], signature) {
			continue
		}
		commentSize := int(binary.LittleEndian.Uint16(tail[offset+20 : offset+22]))
		if offset+endRecordSize+commentSize != len(tail) {
			continue
		}
		entries := binary.LittleEndian.Uint16(tail[offset+10 : offset+12])
		directorySize := binary.LittleEndian.Uint32(tail[offset+12 : offset+16])
		directoryOffset := binary.LittleEndian.Uint32(tail[offset+16 : offset+20])
		if entries == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
			return errors.New("ZIP64 distributions are not supported")
		}
		if entries > maxArchiveEntries {
			return fmt.Errorf("archive declares more than %d entries", maxArchiveEntries)
		}
		if directorySize > maxZipDirectory {
			return fmt.Errorf("zip central directory exceeds %d bytes", maxZipDirectory)
		}
		if int64(directoryOffset)+int64(directorySize) != size-int64(endRecordSize+commentSize) {
			return errors.New("zip central directory does not end at the end record")
		}
		return nil
	}
	return errors.New("zip end record is missing or has trailing data")
}

func metadataFromTarGz(reader io.ReaderAt, size int64) (embeddedMetadata, error) {
	compressed, err := gzip.NewReader(io.NewSectionReader(reader, 0, size))
	if err != nil {
		return embeddedMetadata{}, fmt.Errorf("open gzip: %w", err)
	}
	defer compressed.Close()
	limited := &io.LimitedReader{R: compressed, N: maxTarScanBytes + 1}
	archive := tar.NewReader(limited)
	var metadata []byte
	var metadataPath string
	entries := 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if metadata != nil && limited.N <= 0 {
				break
			}
			return embeddedMetadata{}, fmt.Errorf("read tar: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return embeddedMetadata{}, fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
		}
		if len(header.Name) > maxArchivePath {
			return embeddedMetadata{}, fmt.Errorf("archive path exceeds %d bytes", maxArchivePath)
		}
		clean := path.Clean(header.Name)
		if header.Typeflag != tar.TypeReg || path.Base(clean) != "PKG-INFO" {
			continue
		}
		if header.Size > maxMetadataSize {
			return embeddedMetadata{}, errors.New("package metadata exceeds 1 MiB")
		}
		if metadata != nil && strings.Count(clean, "/") >= strings.Count(metadataPath, "/") {
			continue
		}
		metadata, err = io.ReadAll(io.LimitReader(archive, maxMetadataSize+1))
		if err != nil {
			return embeddedMetadata{}, fmt.Errorf("read metadata: %w", err)
		}
		metadataPath = clean
	}
	if metadata == nil {
		if limited.N <= 0 {
			return embeddedMetadata{}, fmt.Errorf("metadata not found within the %d byte decompression limit", maxTarScanBytes)
		}
		return embeddedMetadata{}, errors.New("package metadata not found")
	}
	return embeddedMetadata{content: metadata, path: metadataPath}, nil
}

func parseMetadata(raw []byte) (domain.PackageFacts, error) {
	if len(raw) > maxMetadataSize {
		return domain.PackageFacts{}, errors.New("package metadata exceeds 1 MiB")
	}
	message, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(string(raw))))
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("parse package metadata: %w", err)
	}
	name := strings.TrimSpace(message.Header.Get("Name"))
	version := strings.TrimSpace(message.Header.Get("Version"))
	if !packageNamePattern.MatchString(name) {
		return domain.PackageFacts{}, fmt.Errorf("invalid package name %q", name)
	}
	if !versionPattern.MatchString(version) {
		return domain.PackageFacts{}, fmt.Errorf("invalid package version %q", version)
	}
	if _, err := parsePEP440(version); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("invalid package version %q", version)
	}
	requiresPython := strings.TrimSpace(message.Header.Get("Requires-Python"))
	if !requiresPythonPattern.MatchString(requiresPython) {
		return domain.PackageFacts{}, errors.New("invalid Requires-Python metadata")
	}
	return domain.PackageFacts{
		Name:           name,
		Version:        version,
		RequiresPython: requiresPython,
		Requirements:   headerValues(message.Header, "Requires-Dist"),
	}, nil
}

func validateDistributionIdentity(filename, metadataPath string, facts domain.PackageFacts) error {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".whl") {
		stem := filename[:len(filename)-len(".whl")]
		parts := strings.Split(stem, "-")
		if len(parts) != 5 && len(parts) != 6 {
			return errors.New("wheel filename does not have five or six components")
		}
		if NormalizeName(strings.ReplaceAll(parts[0], "_", "-")) != NormalizeName(facts.Name) {
			return fmt.Errorf("wheel filename project %q does not match metadata name %q", parts[0], facts.Name)
		}
		if !strings.EqualFold(parts[1], wheelEscapePattern.ReplaceAllString(facts.Version, "_")) {
			return fmt.Errorf("wheel filename version %q does not match metadata version %q", parts[1], facts.Version)
		}
		distInfo := path.Base(path.Dir(metadataPath))
		if !strings.EqualFold(distInfo, parts[0]+"-"+parts[1]+".dist-info") {
			return fmt.Errorf("metadata directory %q does not match wheel filename", distInfo)
		}
		return nil
	}

	stem := filename
	for _, suffix := range []string{".tar.gz", ".tgz", ".zip"} {
		if strings.HasSuffix(strings.ToLower(stem), suffix) {
			stem = stem[:len(stem)-len(suffix)]
			break
		}
	}
	versionSuffix := "-" + facts.Version
	if !strings.HasSuffix(stem, versionSuffix) {
		return fmt.Errorf("source distribution filename does not end in version %q", facts.Version)
	}
	project := strings.TrimSuffix(stem, versionSuffix)
	if NormalizeName(project) != NormalizeName(facts.Name) {
		return fmt.Errorf("source distribution project %q does not match metadata name %q", project, facts.Name)
	}
	return nil
}

func headerValues(header mail.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				values = append(values, entry)
			}
		}
	}
	sort.Strings(values)
	return values
}
