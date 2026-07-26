package deb

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/shellcell/snailmail/internal/domain"
)

const (
	MaxArtifactSize    = 256 << 20
	maxControlSize     = 1 << 20
	maxControlArchive  = 16 << 20
	maxControlEntries  = 1_000
	maxControlPathSize = 1_024
	maxDataArchive     = 512 << 20
	maxDataEntries     = 100_000
)

var (
	packagePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	fieldNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
)

type arMember struct {
	name   string
	offset int64
	size   int64
}

func IsPackageFilename(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".deb")
}

// Inspect derives package identity and control fields directly from a Debian
// binary package without invoking dpkg.
func Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	return InspectWithExpandedLimit(filename, reader, size, maxDataArchive)
}

func InspectWithExpandedLimit(filename string, reader io.ReaderAt, size, maximumExpanded int64) (domain.PackageFacts, error) {
	if !IsPackageFilename(filename) {
		return domain.PackageFacts{}, fmt.Errorf("unsupported Debian package %q", filename)
	}
	if size < 8 || size > MaxArtifactSize {
		return domain.PackageFacts{}, fmt.Errorf("Debian package size %d is outside the supported range", size)
	}
	if maximumExpanded < 1<<20 || maximumExpanded > maxDataArchive {
		return domain.PackageFacts{}, errors.New("Debian expanded-size limit is outside the supported range")
	}
	members, err := readArMembers(reader, size)
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	var binaryVersion, control, data *arMember
	for index := range members {
		member := &members[index]
		switch {
		case member.name == "debian-binary":
			binaryVersion = member
		case strings.HasPrefix(member.name, "control.tar"):
			if control != nil {
				return domain.PackageFacts{}, fmt.Errorf("inspect %q: multiple control archives", filename)
			}
			control = member
		case strings.HasPrefix(member.name, "data.tar"):
			if data != nil {
				return domain.PackageFacts{}, fmt.Errorf("inspect %q: multiple data archives", filename)
			}
			data = member
		}
	}
	if binaryVersion == nil || control == nil || data == nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: package is missing debian-binary, control, or data archive", filename)
	}
	versionBytes := make([]byte, binaryVersion.size)
	if _, err := reader.ReadAt(versionBytes, binaryVersion.offset); err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: read debian-binary: %w", filename, err)
	}
	if string(versionBytes) != "2.0\n" {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: unsupported debian-binary version %q", filename, strings.TrimSpace(string(versionBytes)))
	}
	fields, err := readControlArchive(control.name, io.NewSectionReader(reader, control.offset, control.size))
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	installedSize, err := validateDataArchive(data.name, io.NewSectionReader(reader, data.offset, data.size), maximumExpanded)
	if err != nil {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: %w", filename, err)
	}
	name, version, architecture := fields["Package"], fields["Version"], fields["Architecture"]
	if !packagePattern.MatchString(name) {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid Package field %q", filename, name)
	}
	if !validVersion(version) {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid Version field %q", filename, version)
	}
	if !architecturePattern.MatchString(architecture) {
		return domain.PackageFacts{}, fmt.Errorf("inspect %q: invalid Architecture field %q", filename, architecture)
	}
	for _, required := range []string{"Maintainer", "Description"} {
		if strings.TrimSpace(fields[required]) == "" {
			return domain.PackageFacts{}, fmt.Errorf("inspect %q: required %s field is missing", filename, required)
		}
	}
	return domain.PackageFacts{
		Name:          name,
		Version:       version,
		Architecture:  architecture,
		InstalledSize: installedSize,
		Fields:        fields,
	}, nil
}

func readArMembers(reader io.ReaderAt, size int64) ([]arMember, error) {
	magic := make([]byte, 8)
	if _, err := reader.ReadAt(magic, 0); err != nil {
		return nil, err
	}
	if string(magic) != "!<arch>\n" {
		return nil, errors.New("invalid ar archive header")
	}
	var members []arMember
	for offset := int64(8); offset < size; {
		if len(members) >= 64 {
			return nil, errors.New("ar archive has too many members")
		}
		if size-offset < 60 {
			return nil, errors.New("truncated ar member header")
		}
		header := make([]byte, 60)
		if _, err := reader.ReadAt(header, offset); err != nil {
			return nil, err
		}
		if string(header[58:60]) != "`\n" {
			return nil, errors.New("invalid ar member trailer")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		if name == "" || strings.ContainsAny(name, " /\\") {
			return nil, fmt.Errorf("unsupported ar member name %q", name)
		}
		memberSize, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || memberSize < 0 {
			return nil, fmt.Errorf("invalid size for ar member %q", name)
		}
		contentOffset := offset + 60
		if memberSize > size-contentOffset {
			return nil, fmt.Errorf("ar member %q exceeds archive", name)
		}
		members = append(members, arMember{name: name, offset: contentOffset, size: memberSize})
		offset = contentOffset + memberSize
		if offset%2 != 0 {
			if offset >= size {
				return nil, fmt.Errorf("ar member %q is missing alignment padding", name)
			}
			offset++
		}
	}
	return members, nil
}

func validateDataArchive(name string, raw io.Reader, maximumExpanded int64) (int64, error) {
	stream, closeStream, err := compressedTarReader(name, raw, uint64(maximumExpanded))
	if err != nil {
		return 0, fmt.Errorf("open data archive: %w", err)
	}
	if closeStream != nil {
		defer closeStream()
	}
	limited := &io.LimitedReader{R: stream, N: maximumExpanded + 1}
	archive := tar.NewReader(limited)
	entries := 0
	var installedSize int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("read data archive: %w", err)
		}
		entries++
		if entries > maxDataEntries {
			return 0, fmt.Errorf("data archive has more than %d entries", maxDataEntries)
		}
		if len(header.Name) > maxControlPathSize {
			return 0, errors.New("data archive path is too long")
		}
		clean := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return 0, fmt.Errorf("data archive contains unsafe path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir, tar.TypeSymlink, tar.TypeLink:
			if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
				if header.Size < 0 || header.Size > maximumExpanded-installedSize {
					return 0, errors.New("data archive expanded size exceeds limit")
				}
				installedSize += header.Size
			}
		default:
			return 0, fmt.Errorf("data archive contains unsupported entry type for %q", header.Name)
		}
	}
	if limited.N <= 0 {
		return 0, errors.New("data archive exceeds decompression limit")
	}
	if entries == 0 {
		return 0, errors.New("data archive is empty")
	}
	return installedSize, nil
}

func compressedTarReader(name string, raw io.Reader, maxMemory uint64) (io.Reader, func(), error) {
	switch {
	case name == "control.tar", name == "data.tar":
		return raw, nil, nil
	case strings.HasSuffix(name, ".gz"):
		compressed, err := gzip.NewReader(raw)
		if err != nil {
			return nil, nil, err
		}
		return compressed, func() { _ = compressed.Close() }, nil
	case strings.HasSuffix(name, ".xz"):
		compressed, err := (xz.ReaderConfig{DictCap: int(maxMemory)}).NewReader(raw)
		return compressed, nil, err
	case strings.HasSuffix(name, ".zst"):
		compressed, err := zstd.NewReader(raw, zstd.WithDecoderMaxMemory(maxMemory))
		if err != nil {
			return nil, nil, err
		}
		return compressed, compressed.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported tar archive %q", name)
	}
}

func validVersion(version string) bool {
	if version == "" || strings.ContainsAny(version, "\x00\r\n \t/\\") {
		return false
	}
	remainder := version
	if separator := strings.IndexByte(remainder, ':'); separator >= 0 {
		if separator == 0 {
			return false
		}
		epoch := strings.TrimPrefix(remainder[:separator], "+")
		if epoch == "" {
			return false
		}
		if _, err := strconv.ParseUint(epoch, 10, 64); err != nil {
			return false
		}
		remainder = remainder[separator+1:]
	}
	if remainder == "" || remainder[0] < '0' || remainder[0] > '9' {
		return false
	}
	if strings.HasSuffix(remainder, "-") {
		return false
	}
	if separator := strings.LastIndexByte(remainder, '-'); separator >= 0 && strings.ContainsRune(remainder[separator+1:], ':') {
		return false
	}
	for _, character := range remainder {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune(".:+~-", character) {
			continue
		}
		return false
	}
	return true
}

func readControlArchive(name string, raw io.Reader) (map[string]string, error) {
	var stream io.Reader = raw
	var closeStream func()
	switch {
	case name == "control.tar":
	case strings.HasSuffix(name, ".gz"):
		compressed, err := gzip.NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("open gzip control archive: %w", err)
		}
		stream = compressed
		closeStream = func() { _ = compressed.Close() }
	case strings.HasSuffix(name, ".xz"):
		compressed, err := (xz.ReaderConfig{DictCap: maxControlArchive}).NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("open xz control archive: %w", err)
		}
		stream = compressed
	case strings.HasSuffix(name, ".zst"):
		compressed, err := zstd.NewReader(raw, zstd.WithDecoderMaxMemory(maxControlArchive))
		if err != nil {
			return nil, fmt.Errorf("open zstd control archive: %w", err)
		}
		stream = compressed
		closeStream = compressed.Close
	default:
		return nil, fmt.Errorf("unsupported control archive %q", name)
	}
	if closeStream != nil {
		defer closeStream()
	}
	limited := &io.LimitedReader{R: stream, N: maxControlArchive + 1}
	archive := tar.NewReader(limited)
	for entries := 0; ; entries++ {
		if entries >= maxControlEntries {
			return nil, errors.New("control archive has too many entries")
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read control archive: %w", err)
		}
		if len(header.Name) > maxControlPathSize {
			return nil, errors.New("control archive path is too long")
		}
		clean := strings.TrimPrefix(header.Name, "./")
		if clean != "control" || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size < 0 || header.Size > maxControlSize {
			return nil, errors.New("control file exceeds 1 MiB")
		}
		content, err := io.ReadAll(io.LimitReader(archive, maxControlSize+1))
		if err != nil {
			return nil, fmt.Errorf("read control file: %w", err)
		}
		return parseControl(content)
	}
	if limited.N <= 0 {
		return nil, errors.New("control archive exceeds decompression limit")
	}
	return nil, errors.New("control archive has no control file")
}

func parseControl(content []byte) (map[string]string, error) {
	for _, character := range content {
		if character < 0x20 && character != '\n' && character != '\r' && character != '\t' {
			return nil, fmt.Errorf("control file contains byte 0x%02x", character)
		}
	}
	fields := make(map[string]string)
	seenFields := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 4096), maxControlSize)
	current := ""
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if current == "" {
				return nil, errors.New("control continuation has no field")
			}
			continuation := line[1:]
			if continuation == "." {
				continuation = ""
			}
			fields[current] += "\n" + continuation
			continue
		}
		separator := strings.IndexByte(line, ':')
		if separator <= 0 {
			return nil, fmt.Errorf("invalid control line %q", line)
		}
		name := textproto.CanonicalMIMEHeaderKey(line[:separator])
		if !fieldNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid control field %q", name)
		}
		identity := strings.ToLower(name)
		if seenFields[identity] {
			return nil, fmt.Errorf("duplicate control field %q", name)
		}
		seenFields[identity] = true
		current = name
		fields[name] = strings.TrimSpace(line[separator+1:])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}
