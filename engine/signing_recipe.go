package engine

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
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
// charts is the set of chart archives a Helm repository publishes, empty for
// every other format. Helm signs one provenance file per chart rather than one
// document per repository, so its shape is the only one that does not follow
// from the repository's configuration alone.
func signingShapeFor(repository state.Repository, published []string) (signingRecipe, error) {
	signing, err := formats.SignerFor(repository.Format)
	if err != nil {
		return signingRecipe{}, err
	}
	shape, err := signing.SigningShape(signingRepositoryView(repository), published)
	if err != nil {
		return signingRecipe{}, err
	}
	outputs := make([]signingOutput, 0, len(shape.Outputs))
	for _, output := range shape.Outputs {
		outputs = append(outputs, signingOutput{id: output.ID, scheme: output.Scheme, path: output.Path})
	}
	return signingRecipe{payloadID: shape.PayloadID, outputs: outputs}, nil
}

// signingRepositoryView is what a format needs to know about a repository to
// decide the shape of its signatures.
func signingRepositoryView(repository state.Repository) formats.Repository {
	return formats.Repository{
		Suite: repository.Suite, Component: repository.Component,
		Architectures: repository.Architectures, Signed: len(repository.SigningKeys) != 0,
	}
}

// signingRecipeFor is the shape with the bytes those signatures must cover.
func signingRecipeFor(repository state.Repository, artifact domain.RepositoryArtifact, sources map[string]string) (signingRecipe, error) {
	signing, err := formats.SignerFor(repository.Format)
	if err != nil {
		return signingRecipe{}, err
	}
	view := signingRepositoryView(repository)
	shape, err := signing.SigningShape(view, publishedArtifactPaths(artifact))
	if err != nil {
		return signingRecipe{}, err
	}
	payloads, err := signing.SigningPayloads(artifact, view, shape, storedContent(sources))
	if err != nil {
		return signingRecipe{}, err
	}
	outputs := make([]signingOutput, 0, len(shape.Outputs))
	for _, output := range shape.Outputs {
		payload, exists := payloads[output.Path]
		if !exists {
			return signingRecipe{}, fmt.Errorf("format %q produced no payload for %q", repository.Format, output.Path)
		}
		outputs = append(outputs, signingOutput{
			id: output.ID, scheme: output.Scheme, path: output.Path, payload: payload,
		})
	}
	return signingRecipe{payloadID: shape.PayloadID, outputs: outputs}, nil
}

// publishedArtifactPaths lists the files carrying artifact content, which is
// what a format signing each artifact rather than an index needs to know.
func publishedArtifactPaths(artifact domain.RepositoryArtifact) []string {
	paths := make([]string, 0, len(artifact.Files))
	for _, file := range artifact.Files {
		if file.BlobSHA256 != "" {
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

// storedContent reads a published artifact's bytes out of the workspace store,
// so a signature over them attests to what the lock pinned rather than to
// whatever was written into the staged tree.
func storedContent(sources map[string]string) formats.ArtifactContent {
	if sources == nil {
		return nil
	}
	return func(digest string) ([]byte, error) {
		name, stored := sources[digest]
		if !stored {
			return nil, fmt.Errorf("artifact sha256:%s has no stored content", digest)
		}
		return os.ReadFile(name)
	}
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
	signing, err := formats.SignerFor(repository.Format)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return signing.PlaceSignatures(artifact, signingRepositoryView(repository), formatSigningMaterial(repository, key, material))
}

// formatSigningMaterial gathers what every format's signing draws on, whichever
// parts of it that format actually publishes.
func formatSigningMaterial(repository state.Repository, key state.SigningKey, material signingInputs) formats.SigningMaterial {
	signatures := make(map[string][]byte, len(material.contents))
	for index, content := range material.contents {
		signatures[material.outputPaths[index]] = content
	}
	return formats.SigningMaterial{
		Fingerprint: key.Fingerprint, PublicBinary: material.publicBinary,
		PublicKeyring: material.publicKeyring, PublicArmor: material.publicArmor,
		KeyringPath: repository.SigningKeyring, PublicArmorPath: key.PublicArmorPath,
		TrustedFingerprints: material.trustedFingerprints, SignatureTime: material.signatureTime,
		Signatures: signatures,
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

// clientKeyPath is the file a client installs to verify this repository.
//
// It is not always the keyring the manifest records: apt installs the merged
// binary keyring, a yum client the armored form of the same keys, and apk the
// single key file it will hold in /etc/apk/keys under exactly that name.
func clientKeyPath(repository state.Repository, key state.SigningKey) string {
	signing, err := formats.SignerFor(repository.Format)
	if err != nil {
		return repository.SigningKeyring
	}
	return signing.ClientKeyPath(signingRepositoryView(repository), formats.SigningMaterial{
		KeyringPath: repository.SigningKeyring, PublicArmorPath: key.PublicArmorPath,
	})
}

// knownSigningNode reports whether a scheme and payload identifier are ones
// some registered format produces.
//
// It asks the formats rather than consulting a list kept beside them. The list
// this replaced had to be edited whenever a format gained a signing shape, and
// forgetting to do so rejected a valid plan with a message about node identity
// that named nothing an operator could act on — which is how it was found.
func knownSigningNode(scheme, payloadID string) bool {
	for _, name := range formats.Names() {
		signing, err := formats.SignerFor(name)
		if err != nil {
			continue
		}
		declared, schemes := signing.SigningNode()
		if declared != payloadID {
			continue
		}
		for _, candidate := range schemes {
			if candidate == scheme {
				return true
			}
		}
	}
	return false
}
