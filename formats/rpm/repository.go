package rpm

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Reading somebody else's yum repository, which is the other direction from
// render.go: that writes repodata for publication, this parses it for import.
//
// The chain is the point. repomd.xml states the digest and size of primary.xml.gz,
// and primary.xml states the digest of every package. So a reader that checks
// repomd against the primary it fetched has established the same thing a Debian
// Release establishes about its Packages, and the artifacts it lists are pinned at
// index-chain rather than merely index-stated. Verifying repomd.xml.asc would raise
// that to signed-index; that is not done here, so the root of trust is the
// transport and the lock says so.

const (
	// MaximumRepomdBytes bounds repomd.xml, which names a handful of indexes and is
	// kilobytes even for a large repository.
	MaximumRepomdBytes = 4 << 20

	// MaximumPrimaryBytes bounds primary.xml after decompression. Fedora's is around
	// 250 MB uncompressed for the everything repository, which is far past what is
	// worth reading into memory; this refuses those with a sentence rather than
	// exhausting the host. It is deliberately larger than the deb and helm limits
	// because an uncompressed primary.xml is the largest index of any format here.
	MaximumPrimaryBytes = 512 << 20

	// maximumPrimaryPackages bounds the entry count independently of bytes, since a
	// document can be small and still describe an unreasonable number of packages.
	maximumPrimaryPackages = 1_000_000
)

// RepositoryMetadata is one index repomd.xml declares.
type RepositoryMetadata struct {
	Kind     string
	Location string
	SHA256   string
	Size     int64
	// OpenSHA256 covers the decompressed bytes. Recorded because it is what lets a
	// caller check the chain after decompressing rather than before.
	OpenSHA256 string
}

// RepositoryPackage is one package primary.xml names.
type RepositoryPackage struct {
	Name         string
	Epoch        string
	Version      string
	Release      string
	Architecture string
	Location     string
	SHA256       string
	Size         int64
	// Ambiguous marks a package primary.xml lists more than once with disagreeing
	// digests. As in helm, one such entry does not make the rest unreadable.
	Ambiguous bool
}

// EVR is the version as rpm names it, which is what a lock should record: a bare
// version loses the release, and two builds of one version are different packages.
func (p RepositoryPackage) EVR() string {
	if p.Epoch != "" && p.Epoch != "0" {
		return fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)
	}
	return fmt.Sprintf("%s-%s", p.Version, p.Release)
}

// ParseRepomd reads repodata/repomd.xml.
func ParseRepomd(content []byte) ([]RepositoryMetadata, error) {
	if len(content) > MaximumRepomdBytes {
		return nil, fmt.Errorf("repomd.xml is %d bytes, over the %d byte limit", len(content), MaximumRepomdBytes)
	}
	var document struct {
		XMLName xml.Name `xml:"repomd"`
		Data    []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			OpenChecksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"open-checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
			Size int64 `xml:"size"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parse repomd.xml: %w", err)
	}
	if document.XMLName.Local != "repomd" {
		return nil, fmt.Errorf("root element is %q, want repomd", document.XMLName.Local)
	}
	metadata := make([]RepositoryMetadata, 0, len(document.Data))
	for _, data := range document.Data {
		if data.Type == "" {
			return nil, errors.New("repomd.xml declares an index with no type")
		}
		if !safePath(data.Location.Href) {
			return nil, fmt.Errorf("repomd.xml declares %s at unsafe location %q", data.Type, data.Location.Href)
		}
		entry := RepositoryMetadata{
			Kind:     data.Type,
			Location: data.Location.Href,
			Size:     data.Size,
		}
		// Only SHA-256 is accepted. repomd may state sha1 or md5, and following a
		// digest snailmail would not itself record is a chain that proves nothing.
		if strings.EqualFold(data.Checksum.Type, "sha256") {
			entry.SHA256 = strings.ToLower(strings.TrimSpace(data.Checksum.Value))
		}
		if strings.EqualFold(data.OpenChecksum.Type, "sha256") {
			entry.OpenSHA256 = strings.ToLower(strings.TrimSpace(data.OpenChecksum.Value))
		}
		if entry.SHA256 != "" && !validDigest(entry.SHA256) {
			return nil, fmt.Errorf("repomd.xml states a malformed digest for %s", data.Type)
		}
		metadata = append(metadata, entry)
	}
	return metadata, nil
}

// FindMetadata returns the index of the given type, which for import is "primary".
func FindMetadata(metadata []RepositoryMetadata, kind string) (RepositoryMetadata, bool) {
	for _, entry := range metadata {
		if entry.Kind == kind {
			return entry, true
		}
	}
	return RepositoryMetadata{}, false
}

// DecompressPrimary expands primary.xml.gz. The location repomd states carries the
// encoding in its suffix, which is what this dispatches on.
func DecompressPrimary(location string, content []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(location, ".gz"):
		reader, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, fmt.Errorf("read gzip: %w", err)
		}
		defer reader.Close()
		// Bounded at one byte past the limit so an oversized document is detected
		// rather than silently truncated into a document that parses.
		expanded, err := io.ReadAll(io.LimitReader(reader, MaximumPrimaryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("expand gzip: %w", err)
		}
		if len(expanded) > MaximumPrimaryBytes {
			return nil, fmt.Errorf("primary.xml expands past the %d byte limit", MaximumPrimaryBytes)
		}
		return expanded, nil
	case strings.HasSuffix(location, ".xml"):
		if len(content) > MaximumPrimaryBytes {
			return nil, fmt.Errorf("primary.xml is over the %d byte limit", MaximumPrimaryBytes)
		}
		return content, nil
	default:
		// zstd and xz appear in newer repositories. Naming the encoding beats
		// failing to parse the compressed bytes as XML.
		return nil, fmt.Errorf("primary.xml at %q uses an encoding snailmail cannot read yet", location)
	}
}

// ParsePrimary reads primary.xml and returns every package it names.
//
// Decoded as a stream rather than unmarshalled whole: a large primary.xml holds
// hundreds of thousands of packages, and building the intermediate structure for
// all of them before looking at any costs more than the result.
func ParsePrimary(content []byte) ([]RepositoryPackage, error) {
	if len(content) > MaximumPrimaryBytes {
		return nil, fmt.Errorf("primary.xml is over the %d byte limit", MaximumPrimaryBytes)
	}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	var packages []RepositoryPackage
	// Keyed by name-EVR.arch, which is what identifies an rpm. Two entries under one
	// key with disagreeing digests are ambiguous rather than fatal.
	seen := make(map[string]int)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse primary.xml: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}
		if len(packages) >= maximumPrimaryPackages {
			return nil, fmt.Errorf("primary.xml names more than %d packages", maximumPrimaryPackages)
		}
		var element struct {
			Name    string `xml:"name"`
			Arch    string `xml:"arch"`
			Version struct {
				Epoch string `xml:"epoch,attr"`
				Ver   string `xml:"ver,attr"`
				Rel   string `xml:"rel,attr"`
			} `xml:"version"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
			Size struct {
				Package int64 `xml:"package,attr"`
			} `xml:"size"`
		}
		if err := decoder.DecodeElement(&element, &start); err != nil {
			return nil, fmt.Errorf("parse a package in primary.xml: %w", err)
		}
		if element.Name == "" || element.Location.Href == "" {
			continue
		}
		if !safePath(element.Location.Href) {
			return nil, fmt.Errorf("primary.xml names %s at unsafe location %q", element.Name, element.Location.Href)
		}
		entry := RepositoryPackage{
			Name:         element.Name,
			Epoch:        strings.TrimSpace(element.Version.Epoch),
			Version:      strings.TrimSpace(element.Version.Ver),
			Release:      strings.TrimSpace(element.Version.Rel),
			Architecture: element.Arch,
			Location:     element.Location.Href,
			Size:         element.Size.Package,
		}
		if strings.EqualFold(element.Checksum.Type, "sha256") {
			candidate := strings.ToLower(strings.TrimSpace(element.Checksum.Value))
			if validDigest(candidate) {
				entry.SHA256 = candidate
			}
		}
		key := entry.Name + "-" + entry.EVR() + "." + entry.Architecture
		if previous, duplicate := seen[key]; duplicate {
			// Identical repeats are harmless; disagreeing ones mean the index cannot
			// say which artifact this package is, so neither copy is importable.
			if packages[previous].SHA256 != entry.SHA256 {
				packages[previous].Ambiguous = true
			}
			continue
		}
		seen[key] = len(packages)
		packages = append(packages, entry)
	}
	return packages, nil
}

// safePath refuses a location that escapes the repository root or is absolute,
// which is what stops an index from directing a fetch somewhere else.
func safePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	if strings.Contains(value, "://") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && !strings.HasPrefix(cleaned, "../") && cleaned != ".."
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
