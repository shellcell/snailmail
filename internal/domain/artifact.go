package domain

// PackageFacts are facts read from package bytes rather than supplied by a
// repository manifest.
type PackageFacts struct {
	Name           string
	Version        string
	Architecture   string
	InstalledSize  int64
	RequiresPython string
	Requirements   []string
	Fields         map[string]string
}

// Blob is a content-addressed package artifact. Acquisition and local storage
// locations belong to the application layer, not this value.
type Blob struct {
	Filename string
	Size     int64
	MD5      string
	SHA1     string
	SHA256   string
	Facts    PackageFacts
}

// File describes one immutable file in a generated repository. Exactly one of
// Content and BlobSHA256 supplies its bytes.
type File struct {
	Path       string
	Size       int64
	SHA256     string
	Content    []byte
	BlobSHA256 string
}

// VerificationCase describes one package version an ecosystem client must be
// able to install from a generated repository.
type VerificationCase struct {
	Project      string `json:"project,omitempty"`
	Package      string `json:"package,omitempty"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
}

// InstallSpec captures ecosystem operations independently of a deployment
// endpoint. Phase 0 only needs the PyPI simple-index path.
type InstallSpec struct {
	Kind                       string   `json:"kind"`
	IndexPath                  string   `json:"index_path,omitempty"`
	Suite                      string   `json:"suite,omitempty"`
	Component                  string   `json:"component,omitempty"`
	Architectures              []string `json:"architectures,omitempty"`
	SigningKeyPath             string   `json:"signing_key_path,omitempty"`
	SigningFingerprint         string   `json:"signing_fingerprint,omitempty"`
	TrustedSigningFingerprints []string `json:"trusted_signing_fingerprints,omitempty"`
}

type Signature struct {
	Path          string `json:"path"`
	Scheme        string `json:"scheme"`
	Fingerprint   string `json:"fingerprint"`
	PayloadSHA256 string `json:"payload_sha256"`
	SHA256        string `json:"sha256"`
	CreatedAt     string `json:"created_at"`
}

// RepositoryArtifact is deterministic format output before it is written to a
// host or local directory.
type RepositoryArtifact struct {
	Format            string
	Files             []File
	Install           InstallSpec
	VerificationCases []VerificationCase
	Signatures        []Signature
}
