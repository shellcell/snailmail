package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/signer"
	apkrsa "github.com/shellcell/snailmail/signer/apkrsa"
)

// keyNamePattern is what may appear in a signature entry's name. It becomes a
// filename in /etc/apk/keys on every machine that trusts this repository, so
// nothing that could escape a directory or confuse a shell belongs in it.
var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// SigningMaterial is everything needed to publish a signed index.
type SigningMaterial struct {
	Fingerprint string
	// PublicDER is the SubjectPublicKeyInfo used to check the signature before
	// it is published.
	PublicDER []byte
	// PublicPEM is the file a client installs into /etc/apk/keys.
	PublicPEM []byte
	// KeyName is the filename that key will have on a client, and the name that
	// goes into the signature entry. apk finds the key by this name and nothing
	// else, so it is the whole of the binding between index and key.
	KeyName       string
	SignatureTime time.Time
	// Signatures are the raw PKCS#1 v1.5 signatures, one per architecture index,
	// keyed by the index path they cover.
	Signatures map[string][]byte
}

// IndexPayloads returns the bytes each architecture's index signature covers.
//
// An Alpine index is signed by prepending a stream to it, so the payload is the
// whole unsigned APKINDEX.tar.gz rather than a document inside it.
func IndexPayloads(artifact domain.RepositoryArtifact) (map[string][]byte, error) {
	if artifact.Format != FormatID {
		return nil, fmt.Errorf("artifact format is %q, not %q", artifact.Format, FormatID)
	}
	payloads := make(map[string][]byte)
	for _, file := range artifact.Files {
		if path.Base(file.Path) == IndexFilename {
			payloads[file.Path] = append([]byte(nil), file.Content...)
		}
	}
	if len(payloads) == 0 {
		return nil, errors.New("repository has no APKINDEX.tar.gz to sign")
	}
	return payloads, nil
}

// ApplySigning prepends a signature stream to every architecture's index and
// publishes the public key clients must install.
//
// The signed index is the signature stream followed by the unsigned one. apk
// reads the first gzip member, takes the single entry it holds, and checks the
// signature in it against the key named by that entry's own filename. Nothing
// declares where the members divide, which is why the stream is built by hand
// rather than by a tar writer that would append an end-of-archive marker and
// leave apk reading padding as the start of the index.
func ApplySigning(artifact domain.RepositoryArtifact, material SigningMaterial) (domain.RepositoryArtifact, error) {
	if artifact.Format != FormatID || material.SignatureTime.IsZero() || len(material.Signatures) == 0 {
		return domain.RepositoryArtifact{}, errors.New("invalid Alpine signing input")
	}
	if !keyNamePattern.MatchString(material.KeyName) {
		return domain.RepositoryArtifact{}, fmt.Errorf("Alpine signing key name %q is unusable as a client filename", material.KeyName)
	}
	identity, err := apkrsa.InspectPublic(material.PublicPEM)
	if err != nil || identity.Fingerprint != material.Fingerprint {
		return domain.RepositoryArtifact{}, errors.New("Alpine public key does not match signing identity")
	}

	payloads, err := IndexPayloads(artifact)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	if len(payloads) != len(material.Signatures) {
		return domain.RepositoryArtifact{}, fmt.Errorf(
			"repository has %d indexes but %d signatures", len(payloads), len(material.Signatures))
	}

	keyPath := path.Join("keys", material.KeyName)
	files := make([]domain.File, 0, len(artifact.Files)+1)
	signatures := make([]domain.Signature, 0, len(payloads))
	for _, file := range artifact.Files {
		if file.Path == keyPath {
			return domain.RepositoryArtifact{}, fmt.Errorf("Alpine unsigned artifact already contains signing path %q", file.Path)
		}
		if path.Base(file.Path) != IndexFilename {
			files = append(files, file)
			continue
		}
		signature, exists := material.Signatures[file.Path]
		if !exists || len(signature) == 0 {
			return domain.RepositoryArtifact{}, fmt.Errorf("index %q has no signature", file.Path)
		}
		// Nothing unverifiable is published: an index carrying a signature that
		// does not check out is refused by every client as tampering.
		if err := apkrsa.VerifyResponse(
			signer.Request{Scheme: signer.SchemeAPKRSA256, Payload: payloads[file.Path], CreatedAt: material.SignatureTime},
			signer.Response{Scheme: signer.SchemeAPKRSA256, Fingerprint: material.Fingerprint, Content: signature},
			material.PublicDER, material.Fingerprint,
		); err != nil {
			return domain.RepositoryArtifact{}, fmt.Errorf("index %q: %w", file.Path, err)
		}
		stream, err := signatureStream(material.KeyName, signature, material.SignatureTime)
		if err != nil {
			return domain.RepositoryArtifact{}, err
		}
		signed := append(append([]byte(nil), stream...), file.Content...)
		files = append(files, domain.File{Path: file.Path, Content: signed})
		digest := sha256.Sum256(signature)
		signatures = append(signatures, domain.Signature{
			Path: file.Path, Scheme: signer.SchemeAPKRSA256,
			Fingerprint: material.Fingerprint, SHA256: hex.EncodeToString(digest[:]),
		})
	}
	files = append(files, domain.File{Path: keyPath, Content: append([]byte(nil), material.PublicPEM...)})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	sort.Slice(signatures, func(left, right int) bool { return signatures[left].Path < signatures[right].Path })

	signed := artifact
	signed.Files = files
	signed.Signatures = signatures
	signed.Install.SigningKeyPath = keyPath
	signed.Install.SigningFingerprint = material.Fingerprint
	return signed, nil
}

// signatureStream builds the gzip member apk reads first: a tar holding exactly
// one entry, named for the digest and the key, whose content is the signature.
//
// The archive deliberately has no end-of-archive marker. apk stops after the
// entry it wants and treats what follows as the next member, so the usual two
// zero blocks would be read as index data.
func signatureStream(keyName string, signature []byte, signatureTime time.Time) ([]byte, error) {
	var expanded bytes.Buffer
	archive := tar.NewWriter(&expanded)
	entry := ".SIGN.RSA256." + keyName
	if err := archive.WriteHeader(&tar.Header{
		Name: entry, Mode: 0o644, Size: int64(len(signature)),
		ModTime: signatureTime.UTC(), Typeflag: tar.TypeReg, Format: tar.FormatGNU,
	}); err != nil {
		return nil, err
	}
	if _, err := archive.Write(signature); err != nil {
		return nil, err
	}
	// Flush pads the entry to a block boundary without writing the trailer that
	// Close would add.
	if err := archive.Flush(); err != nil {
		return nil, err
	}

	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.ModTime = signatureTime.UTC()
	writer.OS = 255
	if _, err := writer.Write(expanded.Bytes()); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

// SignedKeyName derives the filename a client installs the key under. apk
// conventionally ends these in .rsa.pub, and the name is the only thing tying
// an index to the key that signed it.
func SignedKeyName(keyName string) string {
	if strings.HasSuffix(keyName, ".rsa.pub") {
		return keyName
	}
	return keyName + ".rsa.pub"
}
