// Package apk reads Alpine packages and renders an APKINDEX repository.
//
// An .apk is not one archive but three gzip streams concatenated: a signature,
// a control section holding .PKGINFO, and the data. Nothing declares where one
// ends, so they are found by decompressing in sequence and noting how many
// bytes each consumed. That accounting is load-bearing beyond parsing: the
// checksum apk records for a package is the SHA-1 of the control stream's
// compressed bytes, so getting the boundary wrong produces an index every
// client rejects.
package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
)

const (
	// MaxArtifactSize bounds one package.
	MaxArtifactSize = 1 << 30

	// maxControlSize bounds the control section, which holds only .PKGINFO and
	// install scripts, so a package claiming more is malformed.
	maxControlSize = 8 << 20
	maxPKGINFOSize = 1 << 20
)

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[0-9][A-Za-z0-9._+~-]{0,127}$`)
)

// Package is what an APKINDEX entry needs about one artifact.
type Package struct {
	Name          string
	Version       string
	Architecture  string
	Description   string
	URL           string
	License       string
	Origin        string
	Maintainer    string
	BuildTime     int64
	InstalledSize int64
	Size          int64
	Provides      []string
	Depends       []string
	// Checksum is the "Q1"-prefixed base64 SHA-1 of the control stream, which
	// is the identity apk uses for a package.
	Checksum string
}

// IsArtifactFilename reports whether a filename is one this format serves.
func IsArtifactFilename(name string) bool {
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return false
	}
	return strings.HasSuffix(strings.ToLower(name), ".apk")
}

// Inspect reads a package's identity out of its control section.
func Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	pkg, err := InspectPackage(filename, reader, size)
	if err != nil {
		return domain.PackageFacts{}, err
	}
	fields := map[string]string{
		"description": pkg.Description,
		"url":         pkg.URL,
		"license":     pkg.License,
		"origin":      pkg.Origin,
		"maintainer":  pkg.Maintainer,
		"build_time":  strconv.FormatInt(pkg.BuildTime, 10),
		"checksum":    pkg.Checksum,
		"provides":    strings.Join(pkg.Provides, " "),
		"depends":     strings.Join(pkg.Depends, " "),
	}
	for key, value := range fields {
		if value == "" {
			delete(fields, key)
		}
	}
	return domain.PackageFacts{
		Name:          pkg.Name,
		Version:       pkg.Version,
		Architecture:  pkg.Architecture,
		InstalledSize: pkg.InstalledSize,
		Requirements:  append([]string(nil), pkg.Depends...),
		Fields:        fields,
	}, nil
}

// InspectPackage reads the full metadata an index needs.
func InspectPackage(filename string, reader io.ReaderAt, size int64) (Package, error) {
	if !IsArtifactFilename(filename) {
		return Package{}, fmt.Errorf("inspect %q: not an Alpine package", filename)
	}
	if reader == nil || size <= 0 || size > MaxArtifactSize {
		return Package{}, fmt.Errorf("inspect %q: package size is outside the supported range", filename)
	}
	control, info, err := readControl(reader, size)
	if err != nil {
		return Package{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	digest := sha1.Sum(control)
	pkg := Package{
		Name:          info["pkgname"],
		Version:       info["pkgver"],
		Architecture:  info["arch"],
		Description:   info["pkgdesc"],
		URL:           info["url"],
		License:       info["license"],
		Origin:        info["origin"],
		Maintainer:    info["maintainer"],
		BuildTime:     parseInt(info["builddate"]),
		InstalledSize: parseInt(info["size"]),
		Size:          size,
		Provides:      splitFields(info["provides"]),
		Depends:       splitFields(info["depend"]),
		Checksum:      "Q1" + base64.StdEncoding.EncodeToString(digest[:]),
	}
	if !namePattern.MatchString(pkg.Name) {
		return Package{}, fmt.Errorf("inspect %q: package name %q is unusable", filename, pkg.Name)
	}
	if !versionPattern.MatchString(pkg.Version) {
		return Package{}, fmt.Errorf("inspect %q: version %q is unusable", filename, pkg.Version)
	}
	if pkg.Architecture == "" || strings.ContainsAny(pkg.Architecture, "/\\ \t\r\n") {
		return Package{}, fmt.Errorf("inspect %q: architecture %q is unusable", filename, pkg.Architecture)
	}
	return pkg, nil
}

// readControl returns the compressed bytes of the control stream and the
// .PKGINFO it holds.
//
// The signature stream comes first in a signed package and is absent in an
// unsigned one, so streams are read in order and the one carrying .PKGINFO is
// the control section wherever it lands.
func readControl(reader io.ReaderAt, size int64) ([]byte, map[string]string, error) {
	content := make([]byte, size)
	if _, err := reader.ReadAt(content, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("read package: %w", err)
	}
	offset := 0
	for stream := 0; stream < 4 && offset < len(content); stream++ {
		consumed, expanded, err := readGzipStream(content[offset:])
		if err != nil {
			return nil, nil, err
		}
		if info, found := parsePKGINFO(expanded); found {
			return content[offset : offset+consumed], info, nil
		}
		if consumed <= 0 {
			break
		}
		offset += consumed
	}
	return nil, nil, errors.New("package has no .PKGINFO")
}

// readGzipStream decompresses one member and reports how many compressed bytes
// it used, which is what locates the next stream.
func readGzipStream(content []byte) (int, []byte, error) {
	source := bytes.NewReader(content)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return 0, nil, fmt.Errorf("read gzip stream: %w", err)
	}
	// One member at a time: the default would run them together and hide the
	// boundary the checksum depends on.
	reader.Multistream(false)
	expanded, err := io.ReadAll(io.LimitReader(reader, maxControlSize+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read gzip stream: %w", err)
	}
	if int64(len(expanded)) > maxControlSize {
		return 0, nil, errors.New("package section exceeds the supported size")
	}
	// Close consumes the member's trailer, after which the unread remainder of
	// the reader is exactly what follows this stream.
	if err := reader.Close(); err != nil {
		return 0, nil, fmt.Errorf("read gzip stream: %w", err)
	}
	consumed := len(content) - source.Len()
	return consumed, expanded, nil
}

// parsePKGINFO finds .PKGINFO in an expanded tar and reads its key = value
// lines. A key may repeat, and repeated keys accumulate space-separated, which
// is how depend and provides carry more than one entry.
func parsePKGINFO(expanded []byte) (map[string]string, bool) {
	body, found := tarEntry(expanded, ".PKGINFO")
	if !found {
		return nil, false
	}
	info := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64<<10), maxPKGINFOSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if existing, seen := info[key]; seen && existing != "" {
			info[key] = existing + " " + value
			continue
		}
		info[key] = value
	}
	return info, true
}

func splitFields(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}

func parseInt(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

// tarEntry returns one file's content from an expanded tar, without extracting
// anything to disk.
func tarEntry(expanded []byte, want string) ([]byte, bool) {
	archive := tar.NewReader(bytes.NewReader(expanded))
	for {
		header, err := archive.Next()
		if err != nil {
			return nil, false
		}
		if strings.TrimPrefix(header.Name, "./") != want {
			continue
		}
		if header.Size < 0 || header.Size > maxPKGINFOSize {
			return nil, false
		}
		body, err := io.ReadAll(io.LimitReader(archive, maxPKGINFOSize))
		if err != nil {
			return nil, false
		}
		return body, true
	}
}
