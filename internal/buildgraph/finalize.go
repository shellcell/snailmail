package buildgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

const (
	ManifestFilename = "snailmail.repository.json"
	ManifestSchema   = 2
)

func SupportedManifestSchema(schema int) bool {
	return schema == 1 || schema == ManifestSchema
}

type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type RepositoryManifest struct {
	SchemaVersion     int                       `json:"schema_version"`
	Format            string                    `json:"format"`
	GeneratedAt       string                    `json:"generated_at"`
	TreeSHA256        string                    `json:"tree_sha256"`
	Files             []ManifestFile            `json:"files"`
	Install           domain.InstallSpec        `json:"install"`
	VerificationCases []domain.VerificationCase `json:"verification_cases"`
	Signatures        []domain.Signature        `json:"signatures,omitempty"`
}

// Finalize validates and hashes a format artifact, then adds the management
// manifest. The management manifest intentionally does not hash itself.
func Finalize(artifact domain.RepositoryArtifact, generatedAt time.Time) (domain.RepositoryArtifact, RepositoryManifest, error) {
	if artifact.Format == "" {
		return domain.RepositoryArtifact{}, RepositoryManifest{}, errors.New("artifact format is required")
	}
	if generatedAt.IsZero() {
		return domain.RepositoryArtifact{}, RepositoryManifest{}, errors.New("generation time is required")
	}

	files := append([]domain.File(nil), artifact.Files...)
	for i := range files {
		if err := validateFile(&files[i]); err != nil {
			return domain.RepositoryArtifact{}, RepositoryManifest{}, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for i := 1; i < len(files); i++ {
		if files[i-1].Path == files[i].Path {
			return domain.RepositoryArtifact{}, RepositoryManifest{}, fmt.Errorf("duplicate artifact path %q", files[i].Path)
		}
	}

	manifestFiles := make([]ManifestFile, len(files))
	for i, file := range files {
		manifestFiles[i] = ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256}
	}
	manifest := RepositoryManifest{
		SchemaVersion:     ManifestSchema,
		Format:            artifact.Format,
		GeneratedAt:       generatedAt.UTC().Format(time.RFC3339),
		TreeSHA256:        TreeDigest(manifestFiles),
		Files:             manifestFiles,
		Install:           artifact.Install,
		VerificationCases: append([]domain.VerificationCase(nil), artifact.VerificationCases...),
		Signatures:        append([]domain.Signature(nil), artifact.Signatures...),
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return domain.RepositoryArtifact{}, RepositoryManifest{}, fmt.Errorf("encode repository manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestHash := sha256.Sum256(manifestBytes)
	files = append(files, domain.File{
		Path:    ManifestFilename,
		Size:    int64(len(manifestBytes)),
		SHA256:  hex.EncodeToString(manifestHash[:]),
		Content: manifestBytes,
	})

	artifact.Files = files
	return artifact, manifest, nil
}

// TreeDigest hashes a canonical sequence of path, size, and content digest.
func TreeDigest(files []ManifestFile) string {
	h := sha256.New()
	for _, file := range files {
		h.Write([]byte(file.Path))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(file.Size, 10)))
		h.Write([]byte{0})
		h.Write([]byte(file.SHA256))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validateFile(file *domain.File) error {
	if file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path || file.Path == "." || strings.HasPrefix(file.Path, "../") {
		return fmt.Errorf("unsafe artifact path %q", file.Path)
	}
	if file.Path == ManifestFilename {
		return fmt.Errorf("format output cannot reserve %q", ManifestFilename)
	}
	if strings.ContainsRune(file.Path, '\\') {
		return fmt.Errorf("artifact path %q contains a backslash", file.Path)
	}
	if file.BlobSHA256 == "" {
		file.Size = int64(len(file.Content))
		sum := sha256.Sum256(file.Content)
		file.SHA256 = hex.EncodeToString(sum[:])
	} else {
		if file.Content != nil {
			return fmt.Errorf("artifact file %q has content and a blob reference", file.Path)
		}
		if file.Size < 0 {
			return fmt.Errorf("artifact file %q has a negative size", file.Path)
		}
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("artifact file %q has an invalid SHA-256", file.Path)
		}
		if file.BlobSHA256 != file.SHA256 {
			return fmt.Errorf("artifact file %q content and blob digests differ", file.Path)
		}
	}
	return nil
}
