package rpm

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "rpm/v1"

// PackageDirectory is where artifacts live under the repository root. dnf takes
// the location from the index, so this is a convention rather than a protocol.
const PackageDirectory = "Packages"

// BuildOptions carries the inputs a repodata render depends on.
type BuildOptions struct {
	GeneratedAt time.Time
}

// Build renders repodata for the given packages.
//
// A yum repository is repodata/repomd.xml naming three compressed XML indexes:
// primary, which describes each package; filelists, which lists the files a
// package owns so a dependency on a path can be resolved; and other, which
// carries changelogs. All three are generated even when the last two are empty,
// because dnf fetches what repomd.xml declares and a missing declared file is
// an error while an empty one is not.
func Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	if options.GeneratedAt.IsZero() {
		return domain.RepositoryArtifact{}, fmt.Errorf("generation time is required")
	}
	entries, err := collectEntries(blobs)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}

	primary, err := renderPrimary(entries)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	filelists, err := renderFilelists(entries)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	other, err := renderOther(entries)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}

	files := make([]domain.File, 0, len(entries)+4)
	for _, entry := range entries {
		files = append(files, domain.File{
			Path: entry.location, Size: entry.blob.Size, SHA256: entry.blob.SHA256, BlobSHA256: entry.blob.SHA256,
		})
	}

	var metadata []metadataFile
	for _, described := range []struct {
		kind    string
		content []byte
	}{
		{"primary", primary},
		{"filelists", filelists},
		{"other", other},
	} {
		compressed, err := compress(described.content, options.GeneratedAt)
		if err != nil {
			return domain.RepositoryArtifact{}, err
		}
		location := path.Join("repodata", checksum(compressed)+"-"+described.kind+".xml.gz")
		files = append(files, domain.File{Path: location, Content: compressed})
		metadata = append(metadata, metadataFile{
			kind: described.kind, location: location,
			checksum: checksum(compressed), openChecksum: checksum(described.content),
			size: int64(len(compressed)), openSize: int64(len(described.content)),
		})
	}

	repomd, err := renderRepomd(metadata, options.GeneratedAt)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	files = append(files, domain.File{Path: "repodata/repomd.xml", Content: repomd})

	verification := make([]domain.VerificationCase, 0, len(entries))
	for _, entry := range entries {
		verification = append(verification, domain.VerificationCase{
			Package: entry.pkg.Name, Version: entry.pkg.EVR(), Architecture: entry.pkg.Architecture,
		})
	}
	return domain.RepositoryArtifact{
		Format:            FormatID,
		Files:             files,
		Install:           domain.InstallSpec{Kind: "rpm", IndexPath: "repodata/repomd.xml"},
		VerificationCases: verification,
	}, nil
}

// entry is one package and where it sits in the published tree.
type entry struct {
	blob     domain.Blob
	pkg      Package
	location string
}

// metadataFile is one index repomd.xml declares.
type metadataFile struct {
	kind         string
	location     string
	checksum     string
	openChecksum string
	size         int64
	openSize     int64
}

func collectEntries(blobs []domain.Blob) ([]entry, error) {
	entries := make([]entry, 0, len(blobs))
	occupied := make(map[string]string, len(blobs))
	for _, blob := range blobs {
		pkg, err := packageFromBlob(blob)
		if err != nil {
			return nil, err
		}
		location := path.Join(PackageDirectory, blob.Filename)
		if previous, taken := occupied[location]; taken {
			if previous != blob.SHA256 {
				return nil, fmt.Errorf("different bytes would occupy %q", location)
			}
			continue
		}
		occupied[location] = blob.SHA256
		entries = append(entries, entry{blob: blob, pkg: pkg, location: location})
	}
	// Sorted by where the package lands, so a repository is a function of its
	// contents rather than of the order they were handed over.
	sort.Slice(entries, func(left, right int) bool { return entries[left].location < entries[right].location })
	return entries, nil
}

// packageFromBlob recovers the metadata the index needs from a blob's facts.
// A blob reaching here has already been inspected, so this validates rather
// than reparses.
func packageFromBlob(blob domain.Blob) (Package, error) {
	if !IsArtifactFilename(blob.Filename) {
		return Package{}, fmt.Errorf("rpm artifact filename %q is unusable", blob.Filename)
	}
	if len(blob.SHA256) != sha256.Size*2 || blob.SHA256 != strings.ToLower(blob.SHA256) {
		return Package{}, fmt.Errorf("rpm artifact %q has an invalid digest", blob.Filename)
	}
	if _, err := hex.DecodeString(blob.SHA256); err != nil {
		return Package{}, fmt.Errorf("rpm artifact %q has an invalid digest", blob.Filename)
	}
	if blob.Size < 0 {
		return Package{}, fmt.Errorf("rpm artifact %q has an invalid size", blob.Filename)
	}
	epoch, version, release, err := splitEVR(blob.Facts.Version)
	if err != nil {
		return Package{}, fmt.Errorf("rpm artifact %q: %w", blob.Filename, err)
	}
	if !namePattern.MatchString(blob.Facts.Name) {
		return Package{}, fmt.Errorf("rpm artifact %q has an unusable package name", blob.Filename)
	}
	if blob.Facts.Architecture == "" {
		return Package{}, fmt.Errorf("rpm artifact %q has no architecture", blob.Filename)
	}
	return Package{
		Name: blob.Facts.Name, Epoch: int32(epoch), Version: version, Release: release,
		Architecture: blob.Facts.Architecture, InstalledSize: blob.Facts.InstalledSize,
		Summary: blob.Facts.Fields["summary"], Description: blob.Facts.Fields["description"],
		License: blob.Facts.Fields["license"], Vendor: blob.Facts.Fields["vendor"],
		SourceRPM:   blob.Facts.Fields["sourcerpm"],
		HeaderStart: parseInt(blob.Facts.Fields["header_start"]),
		HeaderEnd:   parseInt(blob.Facts.Fields["header_end"]),
		BuildTime:   parseInt(blob.Facts.Fields["build_time"]),
		Provides:    decodeDependencies(blob.Facts.Fields["provides"]),
		Requires:    decodeDependencies(blob.Facts.Fields["requires"]),
	}, nil
}

func parseInt(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func checksum(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// compress gzips an index with a fixed modification time, so the same packages
// render byte-for-byte identically however often they are built.
func compress(content []byte, generatedAt time.Time) ([]byte, error) {
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.ModTime = generatedAt.UTC()
	writer.OS = 255
	if _, err := writer.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func escape(value string) string {
	var buffer bytes.Buffer
	if err := xml.EscapeText(&buffer, []byte(value)); err != nil {
		return ""
	}
	return buffer.String()
}

// Dependencies have to survive a lock, and a lock carries only Fields, so they
// are encoded as one entry per line of "name\tflags\tversion".
//
// Dropping them would publish an index saying every package needs nothing,
// which a client believes: it would install a package without whatever it
// depends on and only fail when the missing thing is used.
func encodeDependencies(dependencies []Dependency) string {
	if len(dependencies) == 0 {
		return ""
	}
	var encoded strings.Builder
	for _, dependency := range dependencies {
		// A name carrying a separator cannot be round-tripped, and no real
		// dependency has one, so it is dropped rather than silently mangled.
		if dependency.Name == "" || strings.ContainsAny(dependency.Name, "\t\n") || strings.ContainsAny(dependency.Version, "\t\n") {
			continue
		}
		if encoded.Len() > 0 {
			encoded.WriteByte('\n')
		}
		encoded.WriteString(dependency.Name)
		encoded.WriteByte('\t')
		encoded.WriteString(strconv.FormatInt(int64(dependency.Flags), 10))
		encoded.WriteByte('\t')
		encoded.WriteString(dependency.Version)
	}
	return encoded.String()
}

func decodeDependencies(encoded string) []Dependency {
	if encoded == "" {
		return nil
	}
	lines := strings.Split(encoded, "\n")
	dependencies := make([]Dependency, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || parts[0] == "" {
			continue
		}
		flags, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			continue
		}
		dependencies = append(dependencies, Dependency{Name: parts[0], Flags: int32(flags), Version: parts[2]})
	}
	return dependencies
}
