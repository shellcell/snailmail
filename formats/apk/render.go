package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "apk/v1"

// IndexFilename is the only name a client asks for; everything else in the
// repository is reached through it.
const IndexFilename = "APKINDEX.tar.gz"

// BuildOptions carries the inputs an index render depends on.
type BuildOptions struct {
	GeneratedAt time.Time
	// Architectures are the client architectures served. An Alpine repository is
	// partitioned by architecture and a client fetches only its own index, so a
	// repository of nothing but noarch packages still has to say which clients
	// it is for. Absent, the concrete architectures of the packages are used.
	Architectures []string
}

// Build renders an APKINDEX repository over the given packages.
//
// The layout is partitioned, and by two different architectures at once:
//
//	<client-arch>/APKINDEX.tar.gz   the index apk fetches, one per client
//	<package-arch>/<file>.apk       the package, where its own arch puts it
//
// apk appends its own architecture to the repository URL to find the index,
// then resolves each package from the architecture that index records. A noarch
// package therefore appears in every index while existing once, under noarch.
// A flat directory is readable by nothing.
func Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	if options.GeneratedAt.IsZero() {
		return domain.RepositoryArtifact{}, fmt.Errorf("generation time is required")
	}
	entries, err := collectEntries(blobs)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	architectures, err := indexArchitectures(entries, options.Architectures)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}

	files := make([]domain.File, 0, len(entries)+len(architectures))
	placed := make(map[string]bool, len(entries))
	for _, item := range entries {
		if placed[item.location] {
			continue
		}
		placed[item.location] = true
		files = append(files, domain.File{
			Path: item.location, Size: item.blob.Size, SHA256: item.blob.SHA256, BlobSHA256: item.blob.SHA256,
		})
	}
	for _, architecture := range architectures {
		served := make([]entry, 0, len(entries))
		for _, item := range entries {
			if item.pkg.Architecture == architecture || item.pkg.Architecture == noArchitecture {
				served = append(served, item)
			}
		}
		archive, err := indexArchive(renderIndex(served), options.GeneratedAt)
		if err != nil {
			return domain.RepositoryArtifact{}, err
		}
		files = append(files, domain.File{Path: path.Join(architecture, IndexFilename), Content: archive})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })

	verification := make([]domain.VerificationCase, 0, len(entries))
	for _, item := range entries {
		verification = append(verification, domain.VerificationCase{
			Package: item.pkg.Name, Version: item.pkg.Version, Architecture: item.pkg.Architecture,
		})
	}
	return domain.RepositoryArtifact{
		Format:            FormatID,
		Files:             files,
		Install:           domain.InstallSpec{Kind: "apk", Architectures: architectures},
		VerificationCases: verification,
	}, nil
}

// noArchitecture is the architecture a package uses when it runs anywhere. It
// is never a client architecture, so it never gets an index of its own.
const noArchitecture = "noarch"

// indexArchitectures decides which clients this repository serves.
func indexArchitectures(entries []entry, configured []string) ([]string, error) {
	if len(configured) > 0 {
		architectures := append([]string(nil), configured...)
		for _, architecture := range architectures {
			if architecture == "" || architecture == noArchitecture || strings.ContainsAny(architecture, "/\\ \t") {
				return nil, fmt.Errorf("%q is not a client architecture", architecture)
			}
		}
		sort.Strings(architectures)
		return architectures, nil
	}
	seen := make(map[string]bool, len(entries))
	architectures := make([]string, 0, len(entries))
	for _, item := range entries {
		if item.pkg.Architecture == noArchitecture || seen[item.pkg.Architecture] {
			continue
		}
		seen[item.pkg.Architecture] = true
		architectures = append(architectures, item.pkg.Architecture)
	}
	if len(architectures) == 0 && len(entries) > 0 {
		// Every package runs anywhere, which says nothing about who is being
		// served. A client fetches its own architecture's index and would find
		// none, so the repository has to be told.
		return nil, fmt.Errorf("this repository holds only noarch packages, so its architectures must be configured")
	}
	sort.Strings(architectures)
	return architectures, nil
}

type entry struct {
	blob     domain.Blob
	pkg      Package
	location string
}

func collectEntries(blobs []domain.Blob) ([]entry, error) {
	entries := make([]entry, 0, len(blobs))
	occupied := make(map[string]string, len(blobs))
	for _, blob := range blobs {
		pkg, err := packageFromBlob(blob)
		if err != nil {
			return nil, err
		}
		// apk builds the download URL from the index entry, not from wherever the
		// file happens to sit: <arch>/<pkgname>-<pkgver>.apk. A package whose
		// filename differs — anything not produced by abuild — is reported as
		// "package mentioned in index not found", so the published name is
		// derived from identity rather than carried over from the artifact.
		location := path.Join(pkg.Architecture, pkg.Name+"-"+pkg.Version+".apk")
		if previous, taken := occupied[location]; taken {
			if previous != blob.SHA256 {
				return nil, fmt.Errorf("different bytes would occupy %q", location)
			}
			continue
		}
		occupied[location] = blob.SHA256
		entries = append(entries, entry{blob: blob, pkg: pkg, location: location})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].location < entries[right].location })
	return entries, nil
}

// packageFromBlob recovers what the index needs from a blob's facts. The
// control-stream checksum cannot be recomputed without the bytes, so it is
// carried through the lock and its absence is an error rather than a blank
// field: apk refuses an entry with no C: line.
func packageFromBlob(blob domain.Blob) (Package, error) {
	if !IsArtifactFilename(blob.Filename) {
		return Package{}, fmt.Errorf("apk artifact filename %q is unusable", blob.Filename)
	}
	if len(blob.SHA256) != sha256.Size*2 || blob.SHA256 != strings.ToLower(blob.SHA256) {
		return Package{}, fmt.Errorf("apk artifact %q has an invalid digest", blob.Filename)
	}
	if _, err := hex.DecodeString(blob.SHA256); err != nil {
		return Package{}, fmt.Errorf("apk artifact %q has an invalid digest", blob.Filename)
	}
	if !namePattern.MatchString(blob.Facts.Name) {
		return Package{}, fmt.Errorf("apk artifact %q has an unusable package name", blob.Filename)
	}
	if !versionPattern.MatchString(blob.Facts.Version) {
		return Package{}, fmt.Errorf("apk artifact %q has an unusable version", blob.Filename)
	}
	if blob.Facts.Architecture == "" {
		return Package{}, fmt.Errorf("apk artifact %q has no architecture", blob.Filename)
	}
	checksum := blob.Facts.Fields["checksum"]
	if !strings.HasPrefix(checksum, "Q1") || len(checksum) < 10 {
		return Package{}, fmt.Errorf("apk artifact %q has no control checksum, which apk requires", blob.Filename)
	}
	return Package{
		Name: blob.Facts.Name, Version: blob.Facts.Version, Architecture: blob.Facts.Architecture,
		Description: blob.Facts.Fields["description"], URL: blob.Facts.Fields["url"],
		License: blob.Facts.Fields["license"], Origin: blob.Facts.Fields["origin"],
		Maintainer: blob.Facts.Fields["maintainer"], BuildTime: parseInt(blob.Facts.Fields["build_time"]),
		InstalledSize: blob.Facts.InstalledSize, Size: blob.Size, Checksum: checksum,
		Provides: splitFields(blob.Facts.Fields["provides"]),
		Depends:  splitFields(blob.Facts.Fields["depends"]),
	}, nil
}

// renderIndex writes the APKINDEX body: one block per package, blank line
// separated, in the field order apk's own index generator uses.
func renderIndex(entries []entry) []byte {
	var document bytes.Buffer
	for index, item := range entries {
		if index > 0 {
			document.WriteByte('\n')
		}
		pkg := item.pkg
		writeField(&document, "C", pkg.Checksum)
		writeField(&document, "P", pkg.Name)
		writeField(&document, "V", pkg.Version)
		writeField(&document, "A", pkg.Architecture)
		writeField(&document, "S", strconv.FormatInt(pkg.Size, 10))
		writeField(&document, "I", strconv.FormatInt(pkg.InstalledSize, 10))
		writeField(&document, "T", pkg.Description)
		writeField(&document, "U", pkg.URL)
		writeField(&document, "L", pkg.License)
		writeField(&document, "o", pkg.Origin)
		writeField(&document, "m", pkg.Maintainer)
		if pkg.BuildTime > 0 {
			writeField(&document, "t", strconv.FormatInt(pkg.BuildTime, 10))
		}
		if len(pkg.Depends) > 0 {
			writeField(&document, "D", strings.Join(pkg.Depends, " "))
		}
		if len(pkg.Provides) > 0 {
			writeField(&document, "p", strings.Join(pkg.Provides, " "))
		}
	}
	return document.Bytes()
}

// writeField emits one "K:value" line, skipping an empty value and refusing to
// let a newline in a value forge a field.
func writeField(document *bytes.Buffer, key, value string) {
	if value == "" {
		return
	}
	value = strings.NewReplacer("\n", " ", "\r", " ").Replace(value)
	document.WriteString(key)
	document.WriteByte(':')
	document.WriteString(value)
	document.WriteByte('\n')
}

// indexArchive wraps the index in the tar.gz apk fetches. Timestamps and
// ownership are fixed so the same packages produce identical bytes.
func indexArchive(index []byte, generatedAt time.Time) ([]byte, error) {
	var expanded bytes.Buffer
	archive := tar.NewWriter(&expanded)
	if err := archive.WriteHeader(&tar.Header{
		Name: "APKINDEX", Mode: 0o644, Size: int64(len(index)),
		ModTime: generatedAt.UTC(), Typeflag: tar.TypeReg, Format: tar.FormatGNU,
	}); err != nil {
		return nil, err
	}
	if _, err := archive.Write(index); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.ModTime = generatedAt.UTC()
	writer.OS = 255
	if _, err := writer.Write(expanded.Bytes()); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}
