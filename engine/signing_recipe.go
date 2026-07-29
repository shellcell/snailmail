package engine

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/apk"
	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/rpm"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
	apkrsa "github.com/shellcell/snailmail/signer/apkrsa"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

// signingRecipe is what a format signs and where the results go.
//
// It exists because formats do not agree on the shape of a signature. Debian
// signs one Release document twice, inline and detached, because apt accepts
// either. A yum repository signs repomd.xml once, detached. Without this the
// engine could only express the Debian shape, which is why it refused to sign
// anything else.
type signingRecipe struct {
	// payloadID names the node the signatures depend on, which is what ties a
	// reviewed signature to the document it was made over.
	payloadID string
	outputs   []signingOutput
}

type signingOutput struct {
	id     string
	scheme string
	path   string
	// payload is what this signature covers. Debian and rpm sign one document
	// however many signatures they make; an Alpine repository signs a separate
	// index per architecture, so the payload belongs to the output rather than
	// to the recipe.
	payload []byte
}

// signingShapeFor describes where a format's signatures go and what they are
// made over, without the payload. The shape follows from the repository alone,
// so a plan can be checked against it before anything is rebuilt.
func signingShapeFor(repository state.Repository) (signingRecipe, error) {
	switch repository.Format {
	case "deb":
		suite := path.Join("dists", repository.Suite)
		return signingRecipe{
			payloadID: "deb-release",
			outputs: []signingOutput{
				{id: "deb-inrelease", scheme: signer.SchemeOpenPGPCleartext, path: path.Join(suite, "InRelease")},
				{id: "deb-release-gpg", scheme: signer.SchemeOpenPGPDetached, path: path.Join(suite, "Release.gpg")},
			},
		}, nil
	case "apk":
		outputs := make([]signingOutput, 0, len(repository.Architectures))
		for _, architecture := range repository.Architectures {
			indexPath := path.Join(architecture, apk.IndexFilename)
			outputs = append(outputs, signingOutput{
				id: "apk-index-" + architecture, scheme: signer.SchemeAPKRSA256, path: indexPath,
			})
		}
		if len(outputs) == 0 {
			return signingRecipe{}, errors.New("an Alpine repository must serve at least one architecture to be signed")
		}
		return signingRecipe{payloadID: "apk-index", outputs: outputs}, nil
	case "rpm":
		return signingRecipe{
			payloadID: "rpm-repomd",
			outputs: []signingOutput{
				{id: "rpm-repomd-asc", scheme: signer.SchemeOpenPGPDetached, path: rpm.SignaturePath},
			},
		}, nil
	default:
		return signingRecipe{}, fmt.Errorf("repository signing is not implemented for format %q", repository.Format)
	}
}

// signingRecipeFor is the shape with the bytes those signatures must cover.
func signingRecipeFor(repository state.Repository, artifact domain.RepositoryArtifact) (signingRecipe, error) {
	recipe, err := signingShapeFor(repository)
	if err != nil {
		return signingRecipe{}, err
	}
	switch repository.Format {
	case "deb":
		payload, err := deb.ReleasePayload(artifact, repository.Suite)
		if err != nil {
			return signingRecipe{}, err
		}
		for index := range recipe.outputs {
			recipe.outputs[index].payload = payload
		}
	case "rpm":
		payload, err := rpm.RepomdPayload(artifact)
		if err != nil {
			return signingRecipe{}, err
		}
		for index := range recipe.outputs {
			recipe.outputs[index].payload = payload
		}
	case "apk":
		payloads, err := apk.IndexPayloads(artifact)
		if err != nil {
			return signingRecipe{}, err
		}
		for index, output := range recipe.outputs {
			payload, exists := payloads[output.path]
			if !exists {
				return signingRecipe{}, fmt.Errorf("repository has no index at %q to sign", output.path)
			}
			recipe.outputs[index].payload = payload
		}
	}
	return recipe, nil
}

// validateRecipeNodes checks planned signing responses against the recipe the
// repository's own configuration produces, so a plan cannot carry signatures
// for a shape the format does not have.
func validateRecipeNodes(nodes []state.SigningNode, recipe signingRecipe) error {
	if len(nodes) != len(recipe.outputs) {
		return fmt.Errorf("signing recipe has %d responses, want %d", len(nodes), len(recipe.outputs))
	}
	for index, node := range nodes {
		want := recipe.outputs[index]
		if node.ID != want.id || node.Kind != "sign" || node.Scheme != want.scheme || node.OutputPath != want.path {
			return errors.New("signing recipe has invalid node identity or dependencies")
		}
		if len(node.DependsOn) != 1 || node.DependsOn[0] != recipe.payloadID {
			return errors.New("signing recipe has invalid node identity or dependencies")
		}
		if path.IsAbs(node.OutputPath) || path.Clean(node.OutputPath) != node.OutputPath || strings.HasPrefix(node.OutputPath, "../") {
			return errors.New("signing recipe has an unsafe output path")
		}
	}
	return nil
}

// applyFormatSigning places the resolved signatures and the public material a
// client verifies them with.
func applyFormatSigning(repository state.Repository, artifact domain.RepositoryArtifact, key state.SigningKey, material signingInputs) (domain.RepositoryArtifact, error) {
	switch repository.Format {
	case "deb":
		return deb.ApplySigning(artifact, repository.Suite, deb.SigningMaterial{
			Fingerprint: key.Fingerprint, PublicKey: material.publicBinary,
			KeyringPath: repository.SigningKeyring, PublicKeyring: material.publicKeyring,
			TrustedFingerprints: material.trustedFingerprints, SignatureTime: material.signatureTime,
			InRelease: material.contents[0], ReleaseGPG: material.contents[1],
		})
	case "rpm":
		// A yum client imports an armored key, where apt takes a binary
		// keyring, so the published form differs even though the key does not.
		return rpm.ApplySigning(artifact, rpm.SigningMaterial{
			Fingerprint: key.Fingerprint, PublicKey: material.publicBinary,
			PublicArmor:   material.publicArmor,
			ArmorPath:     strings.TrimSuffix(repository.SigningKeyring, ".gpg") + ".asc",
			SignatureTime: material.signatureTime, Signature: material.contents[0],
		})
	case "apk":
		signatures := make(map[string][]byte, len(material.contents))
		for index, content := range material.contents {
			signatures[material.outputPaths[index]] = content
		}
		block, _ := pem.Decode(material.publicArmor)
		if block == nil {
			return domain.RepositoryArtifact{}, errors.New("invalid apk public key")
		}
		return apk.ApplySigning(artifact, apk.SigningMaterial{
			Fingerprint: key.Fingerprint, PublicDER: block.Bytes, PublicPEM: material.publicArmor,
			KeyName: path.Base(key.PublicArmorPath), SignatureTime: material.signatureTime, Signatures: signatures,
		})
	default:
		return domain.RepositoryArtifact{}, fmt.Errorf("repository signing is not implemented for format %q", repository.Format)
	}
}

// signingInputs is the material every format's signing needs, gathered once.
type signingInputs struct {
	publicBinary        []byte
	publicArmor         []byte
	publicKeyring       []byte
	trustedFingerprints []string
	signatureTime       time.Time
	contents            [][]byte
	// outputPaths pairs each signature with the file it covers, which a format
	// signing more than one document needs and one signing a single document
	// ignores.
	outputPaths []string
}

// knownPayloadIDs are the documents a format signs over. A plan checked without
// a recipe still may not name anything else: the dependency is what ties a
// reviewed signature to the bytes it was made over, so an unrecognised one
// would let a signature claim to cover input nobody reviewed.
// knownSchemes are the signature kinds any format may ask for.
var knownSchemes = map[string]bool{
	signer.SchemeOpenPGPCleartext: true,
	signer.SchemeOpenPGPDetached:  true,
	signer.SchemeAPKRSA256:        true,
}

var knownPayloadIDs = map[string]bool{
	"deb-release": true,
	"rpm-repomd":  true,
	"apk-index":   true,
}

// inspectPublicForms reads a committed public key, whichever kind it is.
//
// An OpenPGP key self-certifies when it was made and when it expires; a bare
// RSA key carries neither. The workspace records those dates for an apk key so
// rotation has something to reason about, but nothing in the published file
// attests to them — apk trusts a key until it is removed from the client, and
// no date changes that. They are taken from the recorded key here so the
// comparison that follows is about identity rather than about a claim the file
// never made.
func inspectPublicForms(key state.SigningKey, binary, armored []byte) (signer.Identity, error) {
	if key.Algorithm == signer.AlgorithmAPKRSA4096 {
		identity, err := apkrsa.InspectPublic(armored)
		if err != nil {
			return signer.Identity{}, err
		}
		createdAt, createdErr := time.Parse(time.RFC3339, key.CreatedAt)
		expiresAt, expiresErr := time.Parse(time.RFC3339, key.ExpiresAt)
		if createdErr != nil || expiresErr != nil {
			return signer.Identity{}, errors.New("apk signing key has unusable recorded dates")
		}
		identity.CreatedAt, identity.ExpiresAt = createdAt.UTC(), expiresAt.UTC()
		// The two committed forms are one file for an apk key, so they must be
		// the same bytes rather than two encodings of one key.
		if !bytes.Equal(binary, armored) {
			return signer.Identity{}, errors.New("apk public forms differ")
		}
		return identity, nil
	}
	inspectedBinary, binaryErr := openpgpsigner.InspectPublic(binary)
	inspectedArmor, armorErr := openpgpsigner.InspectArmoredPublic(armored)
	if binaryErr != nil || armorErr != nil || inspectedBinary != inspectedArmor {
		return signer.Identity{}, errors.New("committed public forms do not match")
	}
	return inspectedBinary, nil
}

// verifySignature checks a response under the algorithm that produced it.
func verifySignature(algorithm string, request signer.Request, response signer.Response, publicKey []byte, fingerprint string) error {
	if algorithm == signer.AlgorithmAPKRSA4096 {
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return errors.New("invalid apk verification key")
		}
		return apkrsa.VerifyResponse(request, response, block.Bytes, fingerprint)
	}
	return openpgpsigner.VerifyResponse(request, response, publicKey, fingerprint)
}

// signerMatchesPublic reports whether the private key that will sign is the one
// whose public form is committed.
//
// For OpenPGP that is the whole identity, dates included, because the key
// certifies them itself. A bare RSA key certifies nothing: the dates exist only
// in the manifest, so comparing them here would compare a record against
// itself and tell us nothing about the key.
func signerMatchesPublic(algorithm string, private, public signer.Identity) bool {
	if algorithm == signer.AlgorithmAPKRSA4096 {
		return private.Fingerprint == public.Fingerprint &&
			private.Algorithm == public.Algorithm && private.Bits == public.Bits
	}
	return private == public
}
