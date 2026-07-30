package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Reading somebody else's Alpine repository, the other direction from render.go.
//
// Alpine is the format that cannot support a pinned digest from its index, and
// that is a measured fact rather than a cautious assumption. An APKINDEX entry
// carries C:Q1<base64>, twenty bytes that decode to a SHA-1 — but of the package's
// control section, not of the file. Checked against Alpine 3.19's own archive:
// the index states 6026787bf915d146b29e1d78fffcef4d3c8def1f for 7zip-23.01-r0.apk,
// whose actual SHA-1 is 76a960426c3b96d593078c94c6ea40d2cf2373ed. They do not
// agree because they are not the same thing.
//
// So an imported Alpine artifact is pinned to a SHA-256 snailmail computed from
// bytes it downloaded, recorded as ProvenanceComputed and visible as such in the
// lock. APKINDEX.tar.gz does carry a .SIGN.RSA member, so authenticating the index
// is possible and would establish that these entries are Alpine's; it still would
// not produce a digest of the file, so it would not raise the pin above computed.

const (
	// MaximumIndexBytes bounds APKINDEX.tar.gz. Alpine 3.19 main/x86_64 is about
	// 468 KiB compressed, so this leaves room for a much larger third-party index
	// without admitting an unbounded one.
	MaximumIndexBytes = 64 << 20

	// maximumIndexEntries bounds the entry count independently of bytes, since a
	// small compressed index can describe an unreasonable number of packages.
	maximumIndexEntries = 1_000_000

	// indexMemberName is the file inside APKINDEX.tar.gz holding the entries.
	indexMemberName = "APKINDEX"
)

// RepositoryPackage is one package APKINDEX names.
type RepositoryPackage struct {
	Name         string
	Version      string
	Architecture string
	Size         int64
	// ControlSHA1 is the C: field decoded, which identifies the control section
	// rather than the file. Kept because it is what the index actually said, and
	// dropping it would lose the only integrity statement Alpine publishes.
	ControlSHA1 []byte
	// Ambiguous marks a name and version the index lists more than once with
	// disagreeing entries.
	Ambiguous bool
}

// Filename is the artifact's name in the repository, which APKINDEX does not state
// because apk derives it from the name and version.
func (p RepositoryPackage) Filename() string {
	return p.Name + "-" + p.Version + ".apk"
}

// Signed reports whether APKINDEX.tar.gz carried a signature member, and names the
// key it claims. The signature is not verified here; this reports what is on offer
// so a caller can say so rather than implying an unsigned index was signed.
func Signed(archive []byte) (string, bool) {
	names, err := indexMemberNames(archive)
	if err != nil {
		return "", false
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".SIGN.") {
			return name, true
		}
	}
	return "", false
}

// ParseIndex reads APKINDEX.tar.gz and returns the packages it names.
func ParseIndex(archive []byte) ([]RepositoryPackage, error) {
	content, err := readIndexMember(archive)
	if err != nil {
		return nil, err
	}
	return ParseIndexEntries(content)
}

// ParseIndexEntries reads the uncompressed APKINDEX, whose entries are
// blank-line-separated blocks of single-letter fields.
func ParseIndexEntries(content []byte) ([]RepositoryPackage, error) {
	var packages []RepositoryPackage
	seen := make(map[string]int)
	for _, block := range strings.Split(string(content), "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if len(packages) >= maximumIndexEntries {
			return nil, fmt.Errorf("APKINDEX names more than %d packages", maximumIndexEntries)
		}
		var entry RepositoryPackage
		var checksum string
		for _, line := range strings.Split(block, "\n") {
			key, value, found := strings.Cut(line, ":")
			if !found || len(key) != 1 {
				continue
			}
			switch key {
			case "P":
				entry.Name = value
			case "V":
				entry.Version = value
			case "A":
				entry.Architecture = value
			case "C":
				checksum = value
			case "S":
				entry.Size, _ = strconv.ParseInt(value, 10, 64)
			}
		}
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		// A name or version that is a path is what would let an index direct a fetch
		// somewhere else, since the filename is derived from both.
		if !safeComponent(entry.Name) || !safeComponent(entry.Version) {
			return nil, fmt.Errorf("APKINDEX names a package snailmail will not build a path from: %q %q",
				entry.Name, entry.Version)
		}
		if decoded, ok := decodeQ1(checksum); ok {
			entry.ControlSHA1 = decoded
		}
		key := entry.Name + "-" + entry.Version
		if previous, duplicate := seen[key]; duplicate {
			if !bytes.Equal(packages[previous].ControlSHA1, entry.ControlSHA1) {
				packages[previous].Ambiguous = true
			}
			continue
		}
		seen[key] = len(packages)
		packages = append(packages, entry)
	}
	return packages, nil
}

// decodeQ1 decodes the C: field. Q1 prefixes a base64 SHA-1; other prefixes have
// existed and are not assumed to be interchangeable.
func decodeQ1(value string) ([]byte, bool) {
	if !strings.HasPrefix(value, "Q1") {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "Q1"))
	if err != nil || len(decoded) != 20 {
		return nil, false
	}
	return decoded, true
}

func readIndexMember(archive []byte) ([]byte, error) {
	if len(archive) > MaximumIndexBytes {
		return nil, fmt.Errorf("APKINDEX.tar.gz is over the %d byte limit", MaximumIndexBytes)
	}
	var content []byte
	err := eachIndexMember(archive, func(name string, reader io.Reader) (bool, error) {
		if name != indexMemberName {
			return false, nil
		}
		body, err := io.ReadAll(io.LimitReader(reader, MaximumIndexBytes+1))
		if err != nil {
			return true, fmt.Errorf("read APKINDEX: %w", err)
		}
		if len(body) > MaximumIndexBytes {
			return true, fmt.Errorf("APKINDEX expands past the %d byte limit", MaximumIndexBytes)
		}
		content = body
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, errors.New("APKINDEX.tar.gz contains no APKINDEX")
	}
	return content, nil
}

func indexMemberNames(archive []byte) ([]string, error) {
	var names []string
	err := eachIndexMember(archive, func(name string, _ io.Reader) (bool, error) {
		names = append(names, name)
		return false, nil
	})
	return names, err
}

// eachIndexMember walks every tar member across every gzip stream, calling visit
// until it reports that it is done.
//
// APKINDEX.tar.gz is a concatenation of gzip streams — apk calls them segments —
// and the tar inside each is read separately rather than as one continuous
// archive. Alpine itself writes the signature segment with no end-of-archive
// marker, so a plain multistream read does find the entries; but a segment that is
// terminated, which a third-party index generator may well produce, would end the
// tar stream early and the entries after it would silently not exist. Reading
// stream by stream handles both, and the difference between them is exactly the
// kind that yields an empty repository reported as a successful import.
func eachIndexMember(archive []byte, visit func(string, io.Reader) (bool, error)) error {
	if len(archive) > MaximumIndexBytes {
		return fmt.Errorf("APKINDEX.tar.gz is over the %d byte limit", MaximumIndexBytes)
	}
	source := bytes.NewReader(archive)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return fmt.Errorf("read APKINDEX.tar.gz: %w", err)
	}
	defer reader.Close()
	for {
		reader.Multistream(false)
		archiveReader := tar.NewReader(reader)
		for {
			header, err := archiveReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				// A malformed member inside one segment does not condemn the ones
				// already read; stop this segment and try the next.
				break
			}
			done, err := visit(header.Name, archiveReader)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
		if err := reader.Reset(source); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("read APKINDEX.tar.gz: %w", err)
		}
	}
}

// safeComponent refuses a name or version that would build a path elsewhere.
func safeComponent(value string) bool {
	return value != "" && !strings.ContainsAny(value, "/\\") &&
		value != "." && value != ".." && !strings.Contains(value, "://")
}
