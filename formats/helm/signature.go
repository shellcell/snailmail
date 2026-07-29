package helm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

// SigningMaterial is everything a signed Helm repository publishes.
//
// Provenance maps a chart's published path to the clear-signed document that
// covers it. Helm signs charts rather than the index, so there is one entry per
// chart rather than the single signature every other format produces.
type SigningMaterial struct {
	Fingerprint string
	// PublicKey is the binary key the signatures are checked against here.
	PublicKey []byte
	// PublicKeyring is the form a client installs. `helm verify --keyring` and
	// `helm install --verify --keyring` read a binary OpenPGP keyring, which is
	// the same shape apt takes and a different one from the armored key yum
	// imports.
	PublicKeyring []byte
	KeyringPath   string
	SignatureTime time.Time
	Provenance    map[string][]byte
}

// ApplySigning places each chart's provenance file and the key a client checks
// them with.
func ApplySigning(artifact domain.RepositoryArtifact, material SigningMaterial) (domain.RepositoryArtifact, error) {
	if artifact.Format != FormatID || material.SignatureTime.IsZero() || len(material.Provenance) == 0 {
		return domain.RepositoryArtifact{}, errors.New("invalid Helm signing input")
	}
	if path.IsAbs(material.KeyringPath) || path.Clean(material.KeyringPath) != material.KeyringPath ||
		!strings.HasPrefix(material.KeyringPath, "keys/") || !strings.HasSuffix(material.KeyringPath, ".gpg") {
		return domain.RepositoryArtifact{}, errors.New("Helm signing key must be published as a keyring under keys/")
	}
	charts := make(map[string]domain.File, len(artifact.Files))
	for _, file := range artifact.Files {
		if file.BlobSHA256 != "" && strings.HasSuffix(file.Path, ".tgz") {
			charts[file.Path] = file
		}
		if strings.HasSuffix(file.Path, ProvenanceSuffix) || file.Path == material.KeyringPath {
			return domain.RepositoryArtifact{}, fmt.Errorf("Helm unsigned artifact already contains signing path %q", file.Path)
		}
	}
	// Every chart must be covered. A repository where some charts are signed
	// and others are not is one where `helm install --verify` fails on exactly
	// the charts nobody checked, which reads as a broken repository rather than
	// as the partial signing it is.
	if len(charts) != len(material.Provenance) {
		return domain.RepositoryArtifact{}, fmt.Errorf("Helm repository has %d charts but %d provenance documents", len(charts), len(material.Provenance))
	}

	identity, err := openpgpsigner.InspectPublic(material.PublicKey)
	if err != nil || identity.Fingerprint != material.Fingerprint || identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 {
		return domain.RepositoryArtifact{}, errors.New("Helm public key does not match signing identity")
	}
	keyringIdentities, err := openpgpsigner.InspectPublicKeyring(material.PublicKeyring)
	if err != nil || len(keyringIdentities) == 0 {
		return domain.RepositoryArtifact{}, errors.New("Helm keyring is unreadable")
	}
	active := false
	for _, published := range keyringIdentities {
		active = active || published == identity
	}
	if !active {
		return domain.RepositoryArtifact{}, errors.New("Helm active signer is absent from the published keyring")
	}

	files := append([]domain.File(nil), artifact.Files...)
	signatures := make([]domain.Signature, 0, len(material.Provenance))
	paths := make([]string, 0, len(material.Provenance))
	for chart := range material.Provenance {
		paths = append(paths, chart)
	}
	sort.Strings(paths)
	for _, chart := range paths {
		if _, exists := charts[chart]; !exists {
			return domain.RepositoryArtifact{}, fmt.Errorf("Helm provenance names %q, which the repository does not publish", chart)
		}
		content := material.Provenance[chart]
		// The signature must verify before it is published. A chart carrying a
		// provenance file that does not check out is worse than one carrying
		// none: helm reports it as a failed verification, which reads as
		// tampering rather than as a signing mistake.
		payload, err := clearSignedBody(content)
		if err != nil {
			return domain.RepositoryArtifact{}, fmt.Errorf("Helm provenance for %q: %w", chart, err)
		}
		if err := openpgpsigner.VerifyResponse(
			signer.Request{Scheme: signer.SchemeOpenPGPCleartext, Payload: payload, CreatedAt: material.SignatureTime},
			signer.Response{Scheme: signer.SchemeOpenPGPCleartext, Fingerprint: material.Fingerprint, Content: content},
			material.PublicKey, material.Fingerprint,
		); err != nil {
			return domain.RepositoryArtifact{}, fmt.Errorf("Helm provenance for %q: %w", chart, err)
		}
		provenancePath := chart + ProvenanceSuffix
		files = append(files, domain.File{Path: provenancePath, Content: append([]byte(nil), content...)})
		digest := sha256.Sum256(content)
		payloadDigest := sha256.Sum256(payload)
		signatures = append(signatures, domain.Signature{
			Path: provenancePath, Scheme: signer.SchemeOpenPGPCleartext,
			Fingerprint: material.Fingerprint, PayloadSHA256: hex.EncodeToString(payloadDigest[:]),
			SHA256: hex.EncodeToString(digest[:]), CreatedAt: material.SignatureTime.UTC().Format(time.RFC3339),
		})
	}
	files = append(files, domain.File{Path: material.KeyringPath, Content: append([]byte(nil), material.PublicKeyring...)})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })

	signed := artifact
	signed.Files = files
	signed.Install.SigningKeyPath = material.KeyringPath
	signed.Install.SigningFingerprint = material.Fingerprint
	signed.Signatures = signatures
	return signed, nil
}

// clearSignedBody recovers the document a clear-signed message covers.
//
// It is what the signature was made over, recomputed from the published file so
// the check below is against the bytes a client will read rather than against
// whatever was passed alongside them.
func clearSignedBody(content []byte) ([]byte, error) {
	_, rest, found := bytes.Cut(content, []byte("\n\n"))
	if !found {
		return nil, errors.New("no clear-signed body")
	}
	body, _, found := bytes.Cut(rest, []byte("\n-----BEGIN PGP SIGNATURE-----"))
	if !found {
		return nil, errors.New("no signature block")
	}
	return body, nil
}
