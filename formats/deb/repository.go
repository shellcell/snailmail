package deb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

type ReleaseFile struct {
	Path   string
	Size   int64
	SHA256 string
}

type RepositoryRelease struct {
	Suite         string
	Codename      string
	Components    []string
	Architectures []string
	ValidUntil    string
	Files         []ReleaseFile
}

type RepositoryPackage struct {
	Package      string
	Version      string
	Architecture string
	Filename     string
	Size         int64
	SHA256       string
}

func ParseRepositoryRelease(content []byte) (RepositoryRelease, error) {
	if len(content) > 8<<20 {
		return RepositoryRelease{}, errors.New("Debian Release exceeds 8 MiB")
	}
	fields, err := parseRepositoryFields(content)
	if err != nil {
		return RepositoryRelease{}, err
	}
	release := RepositoryRelease{
		Suite: fields["suite"], Codename: fields["codename"], Components: strings.Fields(fields["components"]),
		Architectures: strings.Fields(fields["architectures"]), ValidUntil: fields["valid-until"],
	}
	seenPaths := make(map[string]bool)
	for _, line := range strings.Split(fields["sha256"], "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 3 {
			return RepositoryRelease{}, errors.New("invalid Debian Release SHA256 entry")
		}
		size, parseErr := strconv.ParseInt(parts[1], 10, 64)
		if parseErr != nil || size < 0 || !validRepositoryDigest(parts[0]) || !safeRepositoryPath(parts[2]) {
			return RepositoryRelease{}, errors.New("invalid Debian Release SHA256 entry")
		}
		if seenPaths[parts[2]] {
			return RepositoryRelease{}, errors.New("Debian Release has a duplicate SHA256 path")
		}
		seenPaths[parts[2]] = true
		release.Files = append(release.Files, ReleaseFile{Path: parts[2], Size: size, SHA256: parts[0]})
	}
	if len(release.Files) == 0 {
		return RepositoryRelease{}, errors.New("Debian Release has no SHA256 entries")
	}
	return release, nil
}

func ParseRepositoryPackages(content []byte) ([]RepositoryPackage, error) {
	if len(content) > 64<<20 {
		return nil, errors.New("Debian Packages exceeds 64 MiB")
	}
	result := make([]RepositoryPackage, 0)
	identities := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	scanner.Split(splitRepositoryParagraph)
	for scanner.Scan() {
		paragraph := scanner.Bytes()
		paragraph = bytes.TrimSpace(paragraph)
		if len(paragraph) == 0 {
			continue
		}
		fields, err := parseRepositoryFields(paragraph)
		if err != nil {
			return nil, err
		}
		size, sizeErr := strconv.ParseInt(fields["size"], 10, 64)
		entry := RepositoryPackage{
			Package: fields["package"], Version: fields["version"], Architecture: fields["architecture"],
			Filename: fields["filename"], Size: size, SHA256: fields["sha256"],
		}
		if err := validatePackagesEntry(entry, sizeErr); err != nil {
			return nil, err
		}
		identity := entry.Package + "\x00" + entry.Version + "\x00" + entry.Architecture
		if existing := identities[identity]; existing != "" {
			return nil, errors.New("Debian Packages has a duplicate package identity")
		}
		identities[identity] = entry.SHA256
		result = append(result, entry)
		if len(result) > 100000 {
			return nil, errors.New("Debian Packages has too many entries")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.New("Debian Packages has no package entries")
	}
	return result, nil
}

func splitRepositoryParagraph(data []byte, atEOF bool) (advance int, token []byte, err error) {
	lf := bytes.Index(data, []byte("\n\n"))
	crlf := bytes.Index(data, []byte("\r\n\r\n"))
	if lf >= 0 && (crlf < 0 || lf < crlf) {
		return lf + 2, data[:lf], nil
	}
	if crlf >= 0 {
		return crlf + 4, data[:crlf], nil
	}
	if atEOF && len(data) != 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func DecompressRepositoryPackages(name string, content []byte) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(content)
	var closer io.ReadCloser
	var err error
	switch {
	case strings.HasSuffix(name, ".gz"):
		closer, err = gzip.NewReader(reader)
	case strings.HasSuffix(name, ".xz"):
		reader, err = (xz.ReaderConfig{DictCap: 32 << 20}).NewReader(reader)
	case strings.HasSuffix(name, ".zst"):
		var decoder *zstd.Decoder
		decoder, err = zstd.NewReader(reader, zstd.WithDecoderMaxMemory(64<<20))
		if decoder != nil {
			closer = decoder.IOReadCloser()
		}
	}
	if err != nil {
		return nil, err
	}
	if closer != nil {
		reader = closer
		defer closer.Close()
	}
	result, err := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(result) > 64<<20 {
		return nil, errors.New("Debian Packages decompression exceeds 64 MiB")
	}
	return result, nil
}

func parseRepositoryFields(content []byte) (map[string]string, error) {
	for _, character := range content {
		if character < 0x20 && character != '\n' && character != '\r' && character != '\t' {
			return nil, errors.New("Debian control data contains a control byte")
		}
	}
	builders := make(map[string]*strings.Builder)
	current := ""
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if current == "" {
				return nil, errors.New("Debian control continuation has no field")
			}
			builders[current].WriteByte('\n')
			builders[current].WriteString(line[1:])
			continue
		}
		separator := strings.IndexByte(line, ':')
		if separator <= 0 || separator > 64 || len(builders) >= 256 {
			return nil, errors.New("invalid Debian control field")
		}
		name := strings.ToLower(line[:separator])
		for _, character := range name {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return nil, errors.New("invalid Debian control field name")
			}
		}
		if builders[name] != nil {
			return nil, errors.New("duplicate Debian control field")
		}
		current = name
		builders[name] = new(strings.Builder)
		builders[name].WriteString(strings.TrimSpace(line[separator+1:]))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fields := make(map[string]string, len(builders))
	for name, builder := range builders {
		fields[name] = builder.String()
	}
	return fields, nil
}

func validRepositoryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func safeRepositoryPath(value string) bool {
	cleanValue := strings.TrimPrefix(value, "./")
	if cleanValue == "" || strings.ContainsAny(value, "\\\x00\r\n") || path.IsAbs(value) || path.Clean(cleanValue) != cleanValue || strings.HasPrefix(cleanValue, "../") {
		return false
	}
	parsed, err := url.Parse(cleanValue)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || strings.Contains(parsed.Path, "\\") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// validatePackagesEntry checks one stanza of a published Packages file.
//
// Written as separate checks because each is a different thing being wrong, and
// an operator reading a rejected index needs to know which one. The single
// condition this replaced tested eleven things and reported "invalid Debian
// Packages entry" for every one of them.
func validatePackagesEntry(entry RepositoryPackage, sizeErr error) error {
	for _, field := range []struct{ name, value string }{
		{"Package", entry.Package}, {"Version", entry.Version}, {"Architecture", entry.Architecture},
	} {
		if field.value == "" {
			return fmt.Errorf("Debian Packages entry has no %s field", field.name)
		}
		if len(field.value) > 255 {
			return fmt.Errorf("Debian Packages %s field is %d characters, over the 255 limit", field.name, len(field.value))
		}
	}
	switch {
	case len(entry.Filename) > 4096:
		return fmt.Errorf("Debian Packages entry for %s has a filename of %d characters, over the 4096 limit", entry.Package, len(entry.Filename))
	case sizeErr != nil:
		return fmt.Errorf("Debian Packages entry for %s has an unreadable Size: %w", entry.Package, sizeErr)
	case entry.Size < 0:
		return fmt.Errorf("Debian Packages entry for %s has a negative Size", entry.Package)
	case !validRepositoryDigest(entry.SHA256):
		return fmt.Errorf("Debian Packages entry for %s has a SHA256 that is not a lowercase hex digest", entry.Package)
	case !safeRepositoryPath(entry.Filename):
		return fmt.Errorf("Debian Packages entry for %s has an unsafe Filename %q", entry.Package, entry.Filename)
	}
	return nil
}
