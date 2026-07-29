package engine

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/rpm"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
)

// signingRecipe is what a format signs and where the results go.
//
// It exists because formats do not agree on the shape of a signature. Debian
// signs one Release document twice, inline and detached, because apt accepts
// either. A yum repository signs repomd.xml once, detached. Without this the
// engine could only express the Debian shape, which is why it refused to sign
// anything else.
type signingRecipe struct {
	// payload is the bytes every signature covers.
	payload []byte
	// payloadID names the node the signatures depend on, which is what ties a
	// reviewed signature to the document it was made over.
	payloadID string
	outputs   []signingOutput
}

type signingOutput struct {
	id     string
	scheme string
	path   string
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
		recipe.payload, err = deb.ReleasePayload(artifact, repository.Suite)
	case "rpm":
		recipe.payload, err = rpm.RepomdPayload(artifact)
	}
	if err != nil {
		return signingRecipe{}, err
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
}

// knownPayloadIDs are the documents a format signs over. A plan checked without
// a recipe still may not name anything else: the dependency is what ties a
// reviewed signature to the bytes it was made over, so an unrecognised one
// would let a signature claim to cover input nobody reviewed.
var knownPayloadIDs = map[string]bool{
	"deb-release": true,
	"rpm-repomd":  true,
}
