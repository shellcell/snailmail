package raw

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

// BuildOptions carries the inputs a raw render can depend on. Raw has no suite
// or architecture matrix; the generation time is here because the listing
// records it.
type BuildOptions struct {
	GeneratedAt time.Time
}

// Build renders a deterministic listing over the artifacts.
//
// Each artifact is published at <name>/<version>/<filename>, which is what
// makes identity recoverable from the tree: raw reads no metadata out of the
// bytes, so if identity lived only in the filename an operator override would
// be unverifiable once published. The path is the record.
func Build(blobs []domain.Blob, options BuildOptions) (domain.RepositoryArtifact, error) {
	if options.GeneratedAt.IsZero() {
		return domain.RepositoryArtifact{}, fmt.Errorf("generation time is required")
	}
	entries := make([]listingEntry, 0, len(blobs))
	occupied := make(map[string]string, len(blobs))
	for _, blob := range blobs {
		if err := validateBlob(blob); err != nil {
			return domain.RepositoryArtifact{}, err
		}
		artifactPath := path.Join(blob.Facts.Name, blob.Facts.Version, blob.Filename)
		if previous, taken := occupied[artifactPath]; taken && previous != blob.SHA256 {
			return domain.RepositoryArtifact{}, fmt.Errorf("different bytes would occupy %q", artifactPath)
		}
		if occupied[artifactPath] == blob.SHA256 {
			continue
		}
		occupied[artifactPath] = blob.SHA256
		entries = append(entries, listingEntry{blob: blob, path: artifactPath})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].path < entries[right].path })

	files := make([]domain.File, 0, len(entries)+2)
	var checksums bytes.Buffer
	for _, item := range entries {
		files = append(files, domain.File{
			Path: item.path, Size: item.blob.Size, SHA256: item.blob.SHA256, BlobSHA256: item.blob.SHA256,
		})
		// The sha256sum format: digest, two spaces, binary-mode marker, path.
		checksums.WriteString(item.blob.SHA256 + "  " + item.path + "\n")
	}
	files = append(files, domain.File{Path: "SHA256SUMS", Content: checksums.Bytes()})

	verification := make([]domain.VerificationCase, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, item := range entries {
		identity := item.blob.Facts.Name + "\x00" + item.blob.Facts.Version
		if seen[identity] {
			continue
		}
		seen[identity] = true
		verification = append(verification, domain.VerificationCase{
			Project: item.blob.Facts.Name, Version: item.blob.Facts.Version,
		})
	}
	return domain.RepositoryArtifact{
		Format:            FormatID,
		Files:             files,
		Install:           domain.InstallSpec{Kind: "raw", IndexPath: "SHA256SUMS"},
		VerificationCases: verification,
	}, nil
}

func validateBlob(blob domain.Blob) error {
	if !IsArtifactFilename(blob.Filename) {
		return fmt.Errorf("raw artifact filename %q is unusable", blob.Filename)
	}
	if !namePattern.MatchString(blob.Facts.Name) || !versionPattern.MatchString(blob.Facts.Version) {
		return fmt.Errorf("raw artifact %q has unusable identity %s@%s", blob.Filename, blob.Facts.Name, blob.Facts.Version)
	}
	if blob.Size < 0 || len(blob.SHA256) != sha256.Size*2 {
		return fmt.Errorf("raw artifact %q has an invalid size or digest", blob.Filename)
	}
	if _, err := hex.DecodeString(blob.SHA256); err != nil || blob.SHA256 != strings.ToLower(blob.SHA256) {
		return fmt.Errorf("raw artifact %q has an invalid digest", blob.Filename)
	}
	return nil
}

// listingEntry is one published artifact and where it sits in the tree.
type listingEntry struct {
	blob domain.Blob
	path string
}
