// Package rpm reads binary RPM packages and renders yum/dnf repositories.
//
// An RPM carries its identity in a tagged header rather than in its filename,
// so everything published about a package is read from the bytes. The header is
// a flat table of (tag, type, offset, count) entries pointing into a data store,
// which is untrusted input: every offset and length here is checked against the
// store before it is used.
package rpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
)

const (
	// MaxArtifactSize bounds one package. Kernels and toolchains are large, so
	// this is generous, but a repository is still not a place to put disk images.
	MaxArtifactSize = 3 << 30

	leadSize       = 96
	headerMagicLen = 8
	indexEntrySize = 16

	// maxIndexEntries and maxStoreSize bound what a header may claim before any
	// of it is read, so a corrupt or hostile length cannot allocate freely.
	maxIndexEntries = 1 << 16
	maxStoreSize    = 64 << 20
)

// RPM header tags, from rpmtag.h. Only what a repository index needs is read.
const (
	tagName         = 1000
	tagVersion      = 1001
	tagRelease      = 1002
	tagEpoch        = 1003
	tagSummary      = 1004
	tagDescription  = 1005
	tagBuildTime    = 1006
	tagBuildHost    = 1007
	tagSize         = 1009
	tagVendor       = 1011
	tagLicense      = 1014
	tagPackager     = 1015
	tagGroup        = 1016
	tagURL          = 1020
	tagArch         = 1022
	tagSourceRPM    = 1044
	tagProvideName  = 1047
	tagRequireName  = 1049
	tagProvideVers  = 1113
	tagRequireVers  = 1050
	tagRequireFlags = 1048
	tagProvideFlags = 1112
)

// RPM header entry types, from rpmtag.h.
const (
	typeNull uint32 = iota
	typeChar
	typeInt8
	typeInt16
	typeInt32
	typeInt64
	typeString
	typeBin
	typeStringArray
	typeI18NString
)

var (
	leadMagic   = []byte{0xed, 0xab, 0xee, 0xdb}
	headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01}
)

// namePattern keeps a package name usable as a path segment and as XML content.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// Package is everything the index needs about one artifact. It is a distinct
// type from domain.PackageFacts because a yum index carries considerably more
// than a name and a version.
type Package struct {
	Name          string
	Epoch         int32
	Version       string
	Release       string
	Architecture  string
	Summary       string
	Description   string
	License       string
	Vendor        string
	Group         string
	URL           string
	Packager      string
	BuildHost     string
	BuildTime     int64
	InstalledSize int64
	SourceRPM     string
	Provides      []Dependency
	Requires      []Dependency
	// HeaderStart and HeaderEnd bound the main header within the file. dnf reads
	// only that range when it wants a package's metadata without the payload.
	HeaderStart int64
	HeaderEnd   int64
}

// Dependency is one provides or requires entry.
type Dependency struct {
	Name    string
	Flags   int32
	Version string
}

// EVR renders the epoch-version-release string RPM compares and displays.
func (pkg Package) EVR() string {
	evr := pkg.Version + "-" + pkg.Release
	if pkg.Epoch != 0 {
		return strconv.FormatInt(int64(pkg.Epoch), 10) + ":" + evr
	}
	return evr
}

// IsArtifactFilename reports whether a filename is one this format serves.
func IsArtifactFilename(name string) bool {
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return false
	}
	lower := strings.ToLower(name)
	// A source package builds other packages; it is not installable and does not
	// belong in a binary repository.
	return strings.HasSuffix(lower, ".rpm") && !strings.HasSuffix(lower, ".src.rpm")
}

// Inspect reads a package's identity out of its header.
func Inspect(filename string, reader io.ReaderAt, size int64) (domain.PackageFacts, error) {
	pkg, err := InspectPackage(filename, reader, size)
	if err != nil {
		return domain.PackageFacts{}, err
	}
	// The index needs considerably more than a name and a version, and the only
	// place that survives the trip through a lock is Fields. Everything here is
	// what the header said; nothing is inferred.
	fields := map[string]string{
		"summary":      pkg.Summary,
		"description":  pkg.Description,
		"license":      pkg.License,
		"vendor":       pkg.Vendor,
		"group":        pkg.Group,
		"url":          pkg.URL,
		"packager":     pkg.Packager,
		"buildhost":    pkg.BuildHost,
		"sourcerpm":    pkg.SourceRPM,
		"build_time":   strconv.FormatInt(pkg.BuildTime, 10),
		"header_start": strconv.FormatInt(pkg.HeaderStart, 10),
		"header_end":   strconv.FormatInt(pkg.HeaderEnd, 10),
		"provides":     encodeDependencies(pkg.Provides),
		"requires":     encodeDependencies(pkg.Requires),
	}
	for key, value := range fields {
		if value == "" {
			delete(fields, key)
		}
	}
	requirements := make([]string, 0, len(pkg.Requires))
	for _, dependency := range pkg.Requires {
		requirements = append(requirements, dependency.Name)
	}
	return domain.PackageFacts{
		Name:          pkg.Name,
		Version:       pkg.EVR(),
		Architecture:  pkg.Architecture,
		InstalledSize: pkg.InstalledSize,
		Requirements:  requirements,
		Fields:        fields,
	}, nil
}

// InspectPackage reads the full metadata an index needs.
func InspectPackage(filename string, reader io.ReaderAt, size int64) (Package, error) {
	if !IsArtifactFilename(filename) {
		return Package{}, fmt.Errorf("inspect %q: not an installable RPM package", filename)
	}
	if reader == nil || size < leadSize || size > MaxArtifactSize {
		return Package{}, fmt.Errorf("inspect %q: package size is outside the supported range", filename)
	}
	lead := make([]byte, leadSize)
	if _, err := reader.ReadAt(lead, 0); err != nil {
		return Package{}, fmt.Errorf("inspect %q: read lead: %w", filename, err)
	}
	if string(lead[:4]) != string(leadMagic) {
		return Package{}, fmt.Errorf("inspect %q: not an RPM package", filename)
	}
	// Lead type 1 is a source package. The filename check above already refuses
	// the conventional name, and this refuses one that lied about it.
	if binary.BigEndian.Uint16(lead[6:8]) != 0 {
		return Package{}, fmt.Errorf("inspect %q: source packages are not installable", filename)
	}

	// The signature header comes first and is padded to an eight-byte boundary;
	// it is skipped rather than read, because a repository index describes what
	// the package is, and the signature over it is checked by the client.
	signature, err := readHeader(reader, leadSize, size)
	if err != nil {
		return Package{}, fmt.Errorf("inspect %q: signature header: %w", filename, err)
	}
	headerStart := signature.end
	if remainder := headerStart % 8; remainder != 0 {
		headerStart += 8 - remainder
	}
	main, err := readHeader(reader, headerStart, size)
	if err != nil {
		return Package{}, fmt.Errorf("inspect %q: header: %w", filename, err)
	}

	pkg := Package{
		Name:          main.string(tagName),
		Epoch:         main.int32(tagEpoch),
		Version:       main.string(tagVersion),
		Release:       main.string(tagRelease),
		Architecture:  main.string(tagArch),
		Summary:       main.string(tagSummary),
		Description:   main.string(tagDescription),
		License:       main.string(tagLicense),
		Vendor:        main.string(tagVendor),
		Group:         main.string(tagGroup),
		URL:           main.string(tagURL),
		Packager:      main.string(tagPackager),
		BuildHost:     main.string(tagBuildHost),
		BuildTime:     int64(main.int32(tagBuildTime)),
		InstalledSize: int64(main.int32(tagSize)),
		SourceRPM:     main.string(tagSourceRPM),
		Provides:      main.dependencies(tagProvideName, tagProvideFlags, tagProvideVers),
		Requires:      main.dependencies(tagRequireName, tagRequireFlags, tagRequireVers),
		HeaderStart:   headerStart,
		HeaderEnd:     main.end,
	}
	if !namePattern.MatchString(pkg.Name) {
		return Package{}, fmt.Errorf("inspect %q: package name %q is unusable", filename, pkg.Name)
	}
	if err := validVersionPart(pkg.Version); err != nil {
		return Package{}, fmt.Errorf("inspect %q: version: %w", filename, err)
	}
	if err := validVersionPart(pkg.Release); err != nil {
		return Package{}, fmt.Errorf("inspect %q: release: %w", filename, err)
	}
	if pkg.Architecture == "" || strings.ContainsAny(pkg.Architecture, "/\\ \t\r\n") {
		return Package{}, fmt.Errorf("inspect %q: architecture %q is unusable", filename, pkg.Architecture)
	}
	if pkg.Epoch < 0 {
		return Package{}, fmt.Errorf("inspect %q: epoch is negative", filename)
	}
	return pkg, nil
}

// validVersionPart accepts what RPM allows in a version or release: no dash,
// which separates them, and nothing that would break an index or a path.
func validVersionPart(value string) error {
	if value == "" {
		return errors.New("is empty")
	}
	if len(value) > 128 {
		return errors.New("is too long")
	}
	if strings.ContainsAny(value, "-/\\ \t\r\n") {
		return fmt.Errorf("%q contains a separator", value)
	}
	return nil
}

// header is a parsed RPM header: its index entries and the store they point at.
type header struct {
	entries map[uint32]indexEntry
	store   []byte
	end     int64
}

type indexEntry struct {
	kind   uint32
	offset uint32
	count  uint32
}

// readHeader parses one header structure beginning at offset.
func readHeader(reader io.ReaderAt, offset, size int64) (header, error) {
	if offset < 0 || offset+headerMagicLen+8 > size {
		return header{}, errors.New("header does not fit in the package")
	}
	prologue := make([]byte, headerMagicLen+8)
	if _, err := reader.ReadAt(prologue, offset); err != nil {
		return header{}, err
	}
	if string(prologue[:4]) != string(headerMagic) {
		return header{}, errors.New("header magic is missing")
	}
	count := binary.BigEndian.Uint32(prologue[8:12])
	storeSize := binary.BigEndian.Uint32(prologue[12:16])
	if count == 0 || count > maxIndexEntries {
		return header{}, fmt.Errorf("header declares %d index entries", count)
	}
	if storeSize > maxStoreSize {
		return header{}, fmt.Errorf("header declares a %d byte store", storeSize)
	}
	indexSize := int64(count) * indexEntrySize
	dataStart := offset + headerMagicLen + 8 + indexSize
	end := dataStart + int64(storeSize)
	if end > size {
		return header{}, errors.New("header extends past the end of the package")
	}
	index := make([]byte, indexSize)
	if _, err := reader.ReadAt(index, offset+headerMagicLen+8); err != nil {
		return header{}, err
	}
	store := make([]byte, storeSize)
	if storeSize > 0 {
		if _, err := reader.ReadAt(store, dataStart); err != nil {
			return header{}, err
		}
	}
	parsed := header{entries: make(map[uint32]indexEntry, count), store: store, end: end}
	for position := int64(0); position < indexSize; position += indexEntrySize {
		entry := index[position : position+indexEntrySize]
		tag := binary.BigEndian.Uint32(entry[0:4])
		kind := binary.BigEndian.Uint32(entry[4:8])
		dataOffset := binary.BigEndian.Uint32(entry[8:12])
		dataCount := binary.BigEndian.Uint32(entry[12:16])
		if kind > typeI18NString || dataOffset > storeSize {
			return header{}, fmt.Errorf("header tag %d is malformed", tag)
		}
		// A later entry for one tag would shadow an earlier one; keep the first
		// so a duplicate cannot restate identity after it has been read.
		if _, seen := parsed.entries[tag]; !seen {
			parsed.entries[tag] = indexEntry{kind: kind, offset: dataOffset, count: dataCount}
		}
	}
	return parsed, nil
}

// string returns a string-valued tag, or empty when it is absent or not a string.
func (parsed header) string(tag uint32) string {
	entry, exists := parsed.entries[tag]
	if !exists || (entry.kind != typeString && entry.kind != typeI18NString && entry.kind != typeStringArray) {
		return ""
	}
	return readCString(parsed.store, entry.offset)
}

// int32 returns an INT32-valued tag, or zero when it is absent.
func (parsed header) int32(tag uint32) int32 {
	entry, exists := parsed.entries[tag]
	if !exists || entry.kind != typeInt32 || entry.count == 0 {
		return 0
	}
	if int64(entry.offset)+4 > int64(len(parsed.store)) {
		return 0
	}
	return int32(binary.BigEndian.Uint32(parsed.store[entry.offset : entry.offset+4]))
}

// strings returns a STRING_ARRAY tag as a slice.
func (parsed header) strings(tag uint32) []string {
	entry, exists := parsed.entries[tag]
	if !exists || entry.kind != typeStringArray {
		return nil
	}
	values := make([]string, 0, min(entry.count, maxIndexEntries))
	offset := entry.offset
	for index := uint32(0); index < entry.count && int64(offset) < int64(len(parsed.store)); index++ {
		value := readCString(parsed.store, offset)
		values = append(values, value)
		offset += uint32(len(value)) + 1
	}
	return values
}

// int32s returns an INT32 array tag as a slice.
func (parsed header) int32s(tag uint32) []int32 {
	entry, exists := parsed.entries[tag]
	if !exists || entry.kind != typeInt32 {
		return nil
	}
	values := make([]int32, 0, min(entry.count, maxIndexEntries))
	for index := uint32(0); index < entry.count; index++ {
		start := int64(entry.offset) + int64(index)*4
		if start+4 > int64(len(parsed.store)) {
			break
		}
		values = append(values, int32(binary.BigEndian.Uint32(parsed.store[start:start+4])))
	}
	return values
}

// dependencies zips the parallel name, flag and version arrays RPM stores.
func (parsed header) dependencies(nameTag, flagTag, versionTag uint32) []Dependency {
	names := parsed.strings(nameTag)
	if len(names) == 0 {
		return nil
	}
	flags := parsed.int32s(flagTag)
	versions := parsed.strings(versionTag)
	dependencies := make([]Dependency, 0, len(names))
	for index, name := range names {
		dependency := Dependency{Name: name}
		if index < len(flags) {
			dependency.Flags = flags[index]
		}
		if index < len(versions) {
			dependency.Version = versions[index]
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies
}

// readCString reads a NUL-terminated string from the store, stopping at its end
// so a missing terminator cannot read past it.
func readCString(store []byte, offset uint32) string {
	if int64(offset) >= int64(len(store)) {
		return ""
	}
	tail := store[offset:]
	if end := bytes.IndexByte(tail, 0); end >= 0 {
		return string(tail[:end])
	}
	return string(tail)
}
