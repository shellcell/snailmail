package deb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

type SigningMaterial struct {
	Fingerprint         string
	PublicKey           []byte
	KeyringPath         string
	PublicKeyring       []byte
	TrustedFingerprints []string
	SignatureTime       time.Time
	InRelease           []byte
	ReleaseGPG          []byte
}

func ApplySigning(artifact domain.RepositoryArtifact, suite string, material SigningMaterial) (domain.RepositoryArtifact, error) {
	if artifact.Format != FormatID || !coordinatePattern.MatchString(suite) || material.SignatureTime.IsZero() ||
		path.IsAbs(material.KeyringPath) || path.Clean(material.KeyringPath) != material.KeyringPath || !strings.HasPrefix(material.KeyringPath, "keys/") || !strings.HasSuffix(material.KeyringPath, ".gpg") {
		return domain.RepositoryArtifact{}, errors.New("invalid Debian signing input")
	}
	identity, err := openpgpsigner.InspectPublic(material.PublicKey)
	if err != nil || identity.Fingerprint != material.Fingerprint || identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 {
		return domain.RepositoryArtifact{}, errors.New("Debian public key does not match signing identity")
	}
	keyringIdentities, err := openpgpsigner.InspectPublicKeyring(material.PublicKeyring)
	if err != nil || len(keyringIdentities) != len(material.TrustedFingerprints) {
		return domain.RepositoryArtifact{}, errors.New("Debian public keyring does not match trusted identities")
	}
	foundActive := false
	for index, trusted := range material.TrustedFingerprints {
		if keyringIdentities[index].Fingerprint != trusted {
			return domain.RepositoryArtifact{}, errors.New("Debian public keyring order does not match trusted identities")
		}
		foundActive = foundActive || trusted == material.Fingerprint
	}
	if !foundActive {
		return domain.RepositoryArtifact{}, errors.New("Debian active signer is absent from public keyring")
	}
	releasePath := path.Join("dists", suite, "Release")
	var release []byte
	for _, file := range artifact.Files {
		if file.Path == releasePath {
			release = file.Content
		}
		if file.Path == path.Join("dists", suite, "InRelease") || file.Path == path.Join("dists", suite, "Release.gpg") || file.Path == material.KeyringPath {
			return domain.RepositoryArtifact{}, fmt.Errorf("Debian unsigned artifact already contains signing path %q", file.Path)
		}
	}
	if len(release) == 0 || release[len(release)-1] != '\n' || bytes.Contains(release, []byte("\r")) {
		return domain.RepositoryArtifact{}, errors.New("Debian Release payload is not canonical LF-terminated text")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(release), "\n"), "\n") {
		if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
			return domain.RepositoryArtifact{}, errors.New("Debian Release payload contains trailing whitespace")
		}
	}
	requests := []struct {
		scheme, file string
		content      []byte
	}{
		{signer.SchemeOpenPGPCleartext, path.Join("dists", suite, "InRelease"), material.InRelease},
		{signer.SchemeOpenPGPDetached, path.Join("dists", suite, "Release.gpg"), material.ReleaseGPG},
	}
	payloadDigest := sha256.Sum256(release)
	for _, resolved := range requests {
		request := signer.Request{Scheme: resolved.scheme, Payload: release, CreatedAt: material.SignatureTime}
		response := signer.Response{Scheme: resolved.scheme, Fingerprint: material.Fingerprint, Content: resolved.content}
		if err := openpgpsigner.VerifyResponse(request, response, material.PublicKey, material.Fingerprint); err != nil {
			return domain.RepositoryArtifact{}, fmt.Errorf("verify Debian %s: %w", path.Base(resolved.file), err)
		}
		digest := sha256.Sum256(resolved.content)
		artifact.Files = append(artifact.Files, domain.File{Path: resolved.file, Content: append([]byte(nil), resolved.content...)})
		artifact.Signatures = append(artifact.Signatures, domain.Signature{
			Path: resolved.file, Scheme: resolved.scheme, Fingerprint: material.Fingerprint,
			PayloadSHA256: hex.EncodeToString(payloadDigest[:]), SHA256: hex.EncodeToString(digest[:]), CreatedAt: material.SignatureTime.UTC().Format(time.RFC3339),
		})
	}
	artifact.Files = append(artifact.Files, domain.File{Path: material.KeyringPath, Content: append([]byte(nil), material.PublicKeyring...)})
	artifact.Install.SigningKeyPath = material.KeyringPath
	artifact.Install.SigningFingerprint = material.Fingerprint
	artifact.Install.TrustedSigningFingerprints = append([]string(nil), material.TrustedFingerprints...)
	return artifact, nil
}

func ReleasePayload(artifact domain.RepositoryArtifact, suite string) ([]byte, error) {
	wanted := path.Join("dists", suite, "Release")
	for _, file := range artifact.Files {
		if file.Path == wanted && file.BlobSHA256 == "" && len(file.Content) != 0 {
			return append([]byte(nil), file.Content...), nil
		}
	}
	return nil, errors.New("Debian artifact is missing Release payload")
}
