package rpm

import (
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

// RepomdPath is the document every other index is reached through, and so the
// only one a signature needs to cover: repomd.xml carries the checksum of each
// index, and each index carries the checksum of every package.
const RepomdPath = "repodata/repomd.xml"

// SignaturePath is where a yum client looks for the detached signature when
// repo_gpgcheck is on.
const SignaturePath = RepomdPath + ".asc"

// SigningMaterial is everything needed to publish a signed repository.
type SigningMaterial struct {
	Fingerprint string
	// PublicKey is the OpenPGP binary form, used only to check that the
	// signature about to be published verifies under the advertised key.
	PublicKey []byte
	// PublicArmor is every trusted key in armored form, concatenated. gpgkey=
	// accepts several keys in one file, which is what lets a rotation serve the
	// successor alongside the key clients already hold. apt takes a binary
	// keyring instead; the keys are the same, the encoding is not.
	PublicArmor []byte
	// ArmorPath is where the armored keyring is published in the tree.
	ArmorPath     string
	SignatureTime time.Time
	// Signature is the detached armored signature over repomd.xml.
	Signature []byte
}

// RepomdPayload returns the bytes a signature must cover.
func RepomdPayload(artifact domain.RepositoryArtifact) ([]byte, error) {
	if artifact.Format != FormatID {
		return nil, fmt.Errorf("artifact format is %q, not %q", artifact.Format, FormatID)
	}
	for _, file := range artifact.Files {
		if file.Path == RepomdPath {
			return append([]byte(nil), file.Content...), nil
		}
	}
	return nil, errors.New("repository has no repodata/repomd.xml to sign")
}

// ApplySigning publishes the signature and the key a client verifies it with.
//
// Only repomd.xml is signed. That is the whole repository: nothing else is
// fetched without first appearing in it under a checksum, so a signature over
// it settles every byte reached through it.
//
// It does not sign the packages. A package signature lives in the package
// header and is made by whoever built it, which is why a yum client separates
// repo_gpgcheck from gpgcheck. Publishing a signed index while implying signed
// packages would be the more dangerous of the two mistakes.
func ApplySigning(artifact domain.RepositoryArtifact, material SigningMaterial) (domain.RepositoryArtifact, error) {
	if artifact.Format != FormatID || material.SignatureTime.IsZero() || len(material.Signature) == 0 {
		return domain.RepositoryArtifact{}, errors.New("invalid RPM signing input")
	}
	if path.IsAbs(material.ArmorPath) || path.Clean(material.ArmorPath) != material.ArmorPath ||
		!strings.HasPrefix(material.ArmorPath, "keys/") || !strings.HasSuffix(material.ArmorPath, ".asc") {
		return domain.RepositoryArtifact{}, errors.New("RPM signing key must be published as an armored key under keys/")
	}
	identity, err := openpgpsigner.InspectPublic(material.PublicKey)
	if err != nil || identity.Fingerprint != material.Fingerprint || identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 {
		return domain.RepositoryArtifact{}, errors.New("RPM public key does not match signing identity")
	}
	armorIdentities, err := openpgpsigner.InspectArmoredPublicKeyring(material.PublicArmor)
	if err != nil || len(armorIdentities) == 0 {
		return domain.RepositoryArtifact{}, errors.New("RPM armored keyring is unreadable")
	}
	active := false
	for _, armored := range armorIdentities {
		active = active || armored == identity
	}
	if !active {
		return domain.RepositoryArtifact{}, errors.New("RPM active signer is absent from the published keyring")
	}

	repomd, err := RepomdPayload(artifact)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	// The signature must verify before it is published: a repository carrying a
	// signature that does not check out is worse than an unsigned one, because
	// a client reports it as tampering.
	if err := openpgpsigner.VerifyResponse(
		signer.Request{Scheme: signer.SchemeOpenPGPDetached, Payload: repomd, CreatedAt: material.SignatureTime},
		signer.Response{Scheme: signer.SchemeOpenPGPDetached, Fingerprint: material.Fingerprint, Content: material.Signature},
		material.PublicKey, material.Fingerprint,
	); err != nil {
		return domain.RepositoryArtifact{}, err
	}

	files := make([]domain.File, 0, len(artifact.Files)+2)
	for _, file := range artifact.Files {
		if file.Path == SignaturePath || file.Path == material.ArmorPath {
			return domain.RepositoryArtifact{}, fmt.Errorf("RPM unsigned artifact already contains signing path %q", file.Path)
		}
		files = append(files, file)
	}
	files = append(files,
		domain.File{Path: SignaturePath, Content: append([]byte(nil), material.Signature...)},
		domain.File{Path: material.ArmorPath, Content: append([]byte(nil), material.PublicArmor...)},
	)
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })

	signed := artifact
	signed.Files = files
	signed.Install.SigningKeyPath = material.ArmorPath
	signed.Install.SigningFingerprint = material.Fingerprint
	digest := sha256.Sum256(material.Signature)
	signed.Signatures = []domain.Signature{{
		Path: SignaturePath, Scheme: signer.SchemeOpenPGPDetached,
		Fingerprint: material.Fingerprint, SHA256: hex.EncodeToString(digest[:]),
	}}
	return signed, nil
}
