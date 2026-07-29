package formats

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/apk"
	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/formats/rpm"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/signer"
)

// SigningOutput is one signature a format produces: which scheme makes it, and
// where it is published.
type SigningOutput struct {
	// ID names the node in a reviewed plan, so a signature can be tied to the
	// document it was made over.
	ID     string
	Scheme string
	Path   string
}

// SigningShape is where a format's signatures go, without the bytes they cover.
//
// It is derivable before anything is rebuilt, which is what lets a plan be
// checked against the shape its repository will produce.
type SigningShape struct {
	// PayloadID names the node every signature depends on.
	PayloadID string
	Outputs   []SigningOutput
}

// SigningMaterial is the key material and resolved signatures a format needs to
// place its signatures and the public form a client verifies them with.
type SigningMaterial struct {
	Fingerprint string
	// PublicBinary is the active key on its own; PublicKeyring is every trusted
	// key; PublicArmor is the armored export. Formats publish different ones:
	// apt installs a binary keyring, yum imports an armored key, apk holds a
	// bare RSA key by filename.
	PublicBinary        []byte
	PublicKeyring       []byte
	PublicArmor         []byte
	KeyringPath         string
	PublicArmorPath     string
	TrustedFingerprints []string
	SignatureTime       time.Time
	// Signatures maps an output path to the signature published there.
	Signatures map[string][]byte
}

// PublishedArtifact is a locked artifact as a format needs to see it to say
// where the artifact will be served from.
type PublishedArtifact struct {
	Filename string
	SHA256   string
}

// ArtifactContent opens the stored bytes of a published artifact by its digest.
//
// Only a format that signs each artifact rather than an index needs it: Helm's
// provenance is a document built from each chart's own content, where every
// other format signs bytes the render already holds.
type ArtifactContent func(digest string) ([]byte, error)

// Signer is implemented by formats that produce repository signatures.
//
// It is separate from Format because most formats do not sign, and a Format
// carrying four signing methods that five of six implementations answer
// emptily says less than an interface a format either satisfies or does not.
// ImplementsSigning reports whether a format satisfies this.
type Signer interface {
	// SigningShape describes where the signatures go. published lists the
	// artifact paths the repository serves, which a format signing each
	// artifact needs and one signing an index ignores.
	SigningShape(repository Repository, published []string) (SigningShape, error)
	// SigningPayloads returns the bytes each output covers, keyed by output
	// path. content reads a published artifact's stored bytes.
	SigningPayloads(artifact domain.RepositoryArtifact, repository Repository, shape SigningShape, content ArtifactContent) (map[string][]byte, error)
	// PlaceSignatures writes the signatures and the public material into the
	// artifact, verifying each one before it is published.
	PlaceSignatures(artifact domain.RepositoryArtifact, repository Repository, material SigningMaterial) (domain.RepositoryArtifact, error)
	// SigningNode names the payload every signature of this format depends on,
	// and the schemes those signatures are made with.
	//
	// A reviewed plan carries signing nodes, and a plan read before its
	// repository is rebuilt can only be checked against what the formats say
	// they produce. Declared rather than inferred: deriving it by calling
	// SigningShape with invented inputs meant a format whose shape depended on
	// something those inputs did not supply went silently unrecognised, and a
	// valid plan was refused with a message naming nothing an operator could
	// act on. TestDeclaredNodesMatchTheShapes holds the declaration to what the
	// shapes actually produce.
	SigningNode() (payloadID string, schemes []string)
	// PublishedPaths says where locked artifacts will be served from, for a
	// format whose signing shape depends on which artifacts there are.
	//
	// It exists because a plan is checked against the shape its repository will
	// produce, and that happens before anything is rebuilt — so a format
	// signing each artifact has to be able to name them from desired state
	// alone. Formats signing an index return nothing and ignore it.
	PublishedPaths(artifacts []PublishedArtifact) []string
	// ClientKeyPath is where a client of this format finds the key, which is
	// not always where the repository keeps its keyring: yum imports an armored
	// export, and apk holds a bare RSA key under the name its index names.
	ClientKeyPath(repository Repository, material SigningMaterial) string
}

// SignerFor returns the signing behaviour of a format, or reports that it has
// none.
func SignerFor(name string) (Signer, error) {
	selected, err := For(name)
	if err != nil {
		return nil, err
	}
	signer, ok := selected.(Signer)
	if !ok || !selected.ImplementsSigning() {
		return nil, &UnsignedFormatError{Format: name}
	}
	return signer, nil
}

// UnsignedFormatError reports that a format produces no repository signatures.
// It is a named type because the engine has to tell "this format cannot sign"
// apart from "this format does not exist".
type UnsignedFormatError struct{ Format string }

func (err *UnsignedFormatError) Error() string {
	return "repository signing is not implemented for format " + err.Format
}

// The payload each format signs over. Named once so the shape and the
// declaration below are the same string rather than two literals.
const (
	debPayloadID  = "deb-release"
	rpmPayloadID  = "rpm-repomd"
	apkPayloadID  = "apk-index"
	helmPayloadID = "helm-provenance"
)

// --- deb ---------------------------------------------------------------

func (debFormat) SigningShape(repository Repository, _ []string) (SigningShape, error) {
	// apt accepts either an inline or a detached signature over the same
	// Release document, and publishing both means a client of either vintage
	// can check the suite.
	suite := path.Join("dists", defaulted(repository.Suite, "stable"))
	return SigningShape{
		PayloadID: debPayloadID,
		Outputs: []SigningOutput{
			{ID: "deb-inrelease", Scheme: signer.SchemeOpenPGPCleartext, Path: path.Join(suite, "InRelease")},
			{ID: "deb-release-gpg", Scheme: signer.SchemeOpenPGPDetached, Path: path.Join(suite, "Release.gpg")},
		},
	}, nil
}

func (debFormat) SigningPayloads(artifact domain.RepositoryArtifact, repository Repository, shape SigningShape, _ ArtifactContent) (map[string][]byte, error) {
	// The suite comes from the repository rather than from the artifact: the
	// signature must cover the Release of the suite being published, not of
	// whatever a rendered tree happens to name.
	payload, err := deb.ReleasePayload(artifact, defaulted(repository.Suite, "stable"))
	if err != nil {
		return nil, err
	}
	payloads := make(map[string][]byte, len(shape.Outputs))
	for _, output := range shape.Outputs {
		payloads[output.Path] = payload
	}
	return payloads, nil
}

func (format debFormat) PlaceSignatures(artifact domain.RepositoryArtifact, repository Repository, material SigningMaterial) (domain.RepositoryArtifact, error) {
	suite := defaulted(repository.Suite, "stable")
	shape, err := format.SigningShape(repository, nil)
	if err != nil {
		return domain.RepositoryArtifact{}, err
	}
	return deb.ApplySigning(artifact, suite, deb.SigningMaterial{
		Fingerprint: material.Fingerprint, PublicKey: material.PublicBinary,
		KeyringPath: material.KeyringPath, PublicKeyring: material.PublicKeyring,
		TrustedFingerprints: material.TrustedFingerprints, SignatureTime: material.SignatureTime,
		InRelease:  material.Signatures[shape.Outputs[0].Path],
		ReleaseGPG: material.Signatures[shape.Outputs[1].Path],
	})
}

// apt accepts either an inline or a detached signature over the same document.
func (debFormat) SigningNode() (string, []string) {
	return debPayloadID, []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached}
}

func (debFormat) PublishedPaths([]PublishedArtifact) []string { return nil }

func (debFormat) ClientKeyPath(_ Repository, material SigningMaterial) string {
	return material.KeyringPath
}

// --- rpm ---------------------------------------------------------------

func (rpmFormat) SigningShape(Repository, []string) (SigningShape, error) {
	return SigningShape{
		PayloadID: rpmPayloadID,
		Outputs:   []SigningOutput{{ID: "rpm-repomd-asc", Scheme: signer.SchemeOpenPGPDetached, Path: rpm.SignaturePath}},
	}, nil
}

func (rpmFormat) SigningPayloads(artifact domain.RepositoryArtifact, _ Repository, shape SigningShape, _ ArtifactContent) (map[string][]byte, error) {
	payload, err := rpm.RepomdPayload(artifact)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{shape.Outputs[0].Path: payload}, nil
}

func (format rpmFormat) PlaceSignatures(artifact domain.RepositoryArtifact, _ Repository, material SigningMaterial) (domain.RepositoryArtifact, error) {
	return rpm.ApplySigning(artifact, rpm.SigningMaterial{
		Fingerprint: material.Fingerprint, PublicKey: material.PublicBinary,
		PublicArmor:   material.PublicArmor,
		ArmorPath:     rpmArmorPath(material.KeyringPath),
		SignatureTime: material.SignatureTime, Signature: material.Signatures[rpm.SignaturePath],
	})
}

// A yum client imports an armored key where apt takes a binary keyring, so the
// published form differs even though the key does not.
func (rpmFormat) SigningNode() (string, []string) {
	return rpmPayloadID, []string{signer.SchemeOpenPGPDetached}
}

func (rpmFormat) PublishedPaths([]PublishedArtifact) []string { return nil }

func (rpmFormat) ClientKeyPath(_ Repository, material SigningMaterial) string {
	return rpmArmorPath(material.KeyringPath)
}

func rpmArmorPath(keyringPath string) string {
	return strings.TrimSuffix(keyringPath, ".gpg") + ".asc"
}

// --- apk ---------------------------------------------------------------

func (apkFormat) SigningShape(repository Repository, _ []string) (SigningShape, error) {
	outputs := make([]SigningOutput, 0, len(repository.Architectures))
	for _, architecture := range repository.Architectures {
		outputs = append(outputs, SigningOutput{
			ID: "apk-index-" + architecture, Scheme: signer.SchemeAPKRSA256,
			Path: path.Join(architecture, apk.IndexFilename),
		})
	}
	if len(outputs) == 0 {
		return SigningShape{}, errors.New("an Alpine repository must serve at least one architecture to be signed")
	}
	return SigningShape{PayloadID: apkPayloadID, Outputs: outputs}, nil
}

func (apkFormat) SigningPayloads(artifact domain.RepositoryArtifact, _ Repository, shape SigningShape, _ ArtifactContent) (map[string][]byte, error) {
	payloads, err := apk.IndexPayloads(artifact)
	if err != nil {
		return nil, err
	}
	for _, output := range shape.Outputs {
		if _, exists := payloads[output.Path]; !exists {
			return nil, fmt.Errorf("repository has no index at %q to sign", output.Path)
		}
	}
	return payloads, nil
}

func (apkFormat) PlaceSignatures(artifact domain.RepositoryArtifact, _ Repository, material SigningMaterial) (domain.RepositoryArtifact, error) {
	block, _ := pem.Decode(material.PublicArmor)
	if block == nil {
		return domain.RepositoryArtifact{}, errors.New("invalid apk public key")
	}
	return apk.ApplySigning(artifact, apk.SigningMaterial{
		Fingerprint: material.Fingerprint, PublicDER: block.Bytes, PublicPEM: material.PublicArmor,
		KeyName: path.Base(material.PublicArmorPath), SignatureTime: material.SignatureTime,
		Signatures: material.Signatures,
	})
}

func (apkFormat) SigningNode() (string, []string) {
	return apkPayloadID, []string{signer.SchemeAPKRSA256}
}

func (apkFormat) PublishedPaths([]PublishedArtifact) []string { return nil }

// apk finds a key by the filename its index names, so the client path is the
// published key itself rather than a keyring.
func (apkFormat) ClientKeyPath(_ Repository, material SigningMaterial) string {
	return material.PublicArmorPath
}

// --- helm --------------------------------------------------------------

func (helmFormat) SigningShape(_ Repository, published []string) (SigningShape, error) {
	// One provenance file per chart, beside the archive it covers, which is
	// where `helm verify` and `helm install --verify` look for it. A repository
	// with no charts signs nothing, which is the ordinary state of one just set
	// up rather than a misconfiguration.
	outputs := make([]SigningOutput, 0, len(published))
	for _, chart := range published {
		outputs = append(outputs, SigningOutput{
			ID: "helm-provenance-" + chart, Scheme: signer.SchemeOpenPGPCleartext,
			Path: chart + helm.ProvenanceSuffix,
		})
	}
	return SigningShape{PayloadID: helmPayloadID, Outputs: outputs}, nil
}

func (helmFormat) SigningPayloads(artifact domain.RepositoryArtifact, repository Repository, shape SigningShape, content ArtifactContent) (map[string][]byte, error) {
	if content == nil {
		return nil, errors.New("Helm provenance needs each chart's stored content")
	}
	digests := make(map[string]string, len(artifact.Files))
	for _, file := range artifact.Files {
		if file.BlobSHA256 != "" {
			digests[file.Path] = file.BlobSHA256
		}
	}
	payloads := make(map[string][]byte, len(shape.Outputs))
	for _, output := range shape.Outputs {
		chart := strings.TrimSuffix(output.Path, helm.ProvenanceSuffix)
		digest, published := digests[chart]
		if !published {
			return nil, fmt.Errorf("repository has no chart at %q to sign", chart)
		}
		// The bytes come from the store rather than the staged tree: a
		// signature over the tree would attest to whatever was written there,
		// where this attests to what the lock pinned.
		stored, err := content(digest)
		if err != nil {
			return nil, err
		}
		payload, err := helm.ProvenancePayload(path.Base(chart), bytes.NewReader(stored), int64(len(stored)))
		if err != nil {
			return nil, err
		}
		payloads[output.Path] = payload
	}
	return payloads, nil
}

func (helmFormat) PlaceSignatures(artifact domain.RepositoryArtifact, _ Repository, material SigningMaterial) (domain.RepositoryArtifact, error) {
	provenance := make(map[string][]byte, len(material.Signatures))
	for outputPath, content := range material.Signatures {
		provenance[strings.TrimSuffix(outputPath, helm.ProvenanceSuffix)] = content
	}
	return helm.ApplySigning(artifact, helm.SigningMaterial{
		Fingerprint: material.Fingerprint, PublicKey: material.PublicBinary,
		PublicKeyring: material.PublicKeyring, KeyringPath: material.KeyringPath,
		SignatureTime: material.SignatureTime, Provenance: provenance,
	})
}

func (helmFormat) SigningNode() (string, []string) {
	return helmPayloadID, []string{signer.SchemeOpenPGPCleartext}
}

// A chart is served from a content-addressed directory, which is what makes a
// provenance file's path derivable from the lock alone. It must agree with what
// helm.Build lays out; TestPublishedPathsMatchTheRender holds them together.
func (helmFormat) PublishedPaths(artifacts []PublishedArtifact) []string {
	paths := make([]string, 0, len(artifacts))
	seen := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		published := helm.ChartPath(artifact.SHA256, artifact.Filename)
		if !seen[published] {
			seen[published] = true
			paths = append(paths, published)
		}
	}
	sort.Strings(paths)
	return paths
}

func (helmFormat) ClientKeyPath(_ Repository, material SigningMaterial) string {
	return material.KeyringPath
}
