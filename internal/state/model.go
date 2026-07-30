package state

import "time"

const (
	ManifestSchema   = 7
	LockSchema       = 2
	PlanSchema       = 10
	LedgerSchema     = 1
	DeploymentSchema = 2
)

type Manifest struct {
	SchemaVersion int                   `toml:"schema_version"`
	Workspace     Workspace             `toml:"workspace"`
	BlobStore     BlobStoreConfig       `toml:"blob_store"`
	Keys          map[string]SigningKey `toml:"key,omitempty"`
	Repositories  map[string]Repository `toml:"repo"`
}

type Workspace struct {
	Name string `toml:"name"`
	ID   string `toml:"id"`
	// Forge names the code-hosting service the state repository lives on. Empty
	// means forge.DefaultProvider, which is what every workspace written before
	// this field existed was implicitly using.
	Forge           string `toml:"forge,omitempty"`
	ForgeRepository string `toml:"forge_repository,omitempty"`
	// ForgeHost is a self-hosted or Enterprise instance. Empty means the
	// provider's own hostname.
	ForgeHost string `toml:"forge_host,omitempty"`
}

type BlobStoreConfig struct {
	Type         string `toml:"type" json:"type"`
	Bucket       string `toml:"bucket,omitempty" json:"bucket,omitempty"`
	Prefix       string `toml:"prefix,omitempty" json:"prefix,omitempty"`
	Region       string `toml:"region,omitempty" json:"region,omitempty"`
	Endpoint     string `toml:"endpoint,omitempty" json:"endpoint,omitempty"`
	UsePathStyle bool   `toml:"use_path_style,omitempty" json:"use_path_style,omitempty"`
}

type Repository struct {
	Format          string           `toml:"format"`
	Lock            string           `toml:"lock"`
	Host            HostConfig       `toml:"host"`
	Visibility      string           `toml:"visibility"`
	Gate            string           `toml:"gate"`
	ApprovalKeys    []string         `toml:"approval_keys,omitempty"`
	SigningKeys     []string         `toml:"signing_keys,omitempty"`
	SigningKeyring  string           `toml:"signing_keyring,omitempty"`
	SigningRotation *SigningRotation `toml:"signing_rotation,omitempty"`
	// Keep is how many recent publications collection retains beyond the live
	// revision and whatever a rollback depends on, which a host protects in any
	// case. Zero means unconfigured, and collect falls back to its own default.
	//
	// In the manifest rather than only a flag because collect is the one operation
	// here that deletes published bytes, and a policy living in whichever CI job
	// someone wrote is the one policy nobody reviews. Changing how much history a
	// repository keeps should be a diff, exactly like changing its gate or its
	// signing key.
	//
	// A count rather than an age, matching what the ledger-derived retention
	// already computes. An age is arguably what people mean by "a month of
	// rollback"; the ledger records publication times, so it can be added beside
	// this later without changing what a count means.
	Keep          int      `toml:"keep,omitempty"`
	Track         string   `toml:"track"`
	Suite         string   `toml:"suite,omitempty"`
	Component     string   `toml:"component,omitempty"`
	Architectures []string `toml:"architectures,omitempty"`
}

type SigningRotation struct {
	SuccessorKey          string `toml:"successor_key"`
	Phase                 string `toml:"phase"`
	MinimumRefreshSeconds int64  `toml:"minimum_refresh_seconds"`
}

type SigningKey struct {
	Algorithm         string `toml:"algorithm"`
	Usage             string `toml:"usage"`
	Fingerprint       string `toml:"fingerprint"`
	CreatedAt         string `toml:"created_at"`
	ExpiresAt         string `toml:"expires_at"`
	PublicKeyPath     string `toml:"public_key"`
	PublicKeySHA256   string `toml:"public_key_sha256"`
	PublicArmorPath   string `toml:"public_armor"`
	PublicArmorSHA256 string `toml:"public_armor_sha256"`
	Ref               KeyRef `toml:"ref"`
}

type KeyRef struct {
	Backend string `toml:"backend"`
	ID      string `toml:"id"`
}

type HostConfig struct {
	Type string `toml:"type" json:"type"`
	Path string `toml:"path,omitempty" json:"path,omitempty"`
	// Target is the ssh destination for an rsync host: a hostname, user@host, or
	// a name from ssh_config. Everything else about the connection — port, key,
	// jump host — belongs in ssh_config, because an operator already has a place
	// for it and a second one is a second place for it to be wrong.
	Target            string `toml:"target,omitempty" json:"target,omitempty"`
	Bucket            string `toml:"bucket,omitempty" json:"bucket,omitempty"`
	Prefix            string `toml:"prefix,omitempty" json:"prefix,omitempty"`
	Region            string `toml:"region,omitempty" json:"region,omitempty"`
	Endpoint          string `toml:"endpoint,omitempty" json:"endpoint,omitempty"`
	CanonicalEndpoint string `toml:"canonical_endpoint,omitempty" json:"canonical_endpoint,omitempty"`
	UsePathStyle      bool   `toml:"use_path_style,omitempty" json:"use_path_style,omitempty"`
	ReadAuth          string `toml:"read_auth,omitempty" json:"read_auth,omitempty"`
	CredentialBroker  string `toml:"credential_broker,omitempty" json:"credential_broker,omitempty"`
	Repository        string `toml:"repository,omitempty" json:"repository,omitempty"`
	Branch            string `toml:"branch,omitempty" json:"branch,omitempty"`
	PreviewRepository string `toml:"preview_repository,omitempty" json:"preview_repository,omitempty"`
	PreviewBranch     string `toml:"preview_branch,omitempty" json:"preview_branch,omitempty"`
	PreviewEndpoint   string `toml:"preview_endpoint,omitempty" json:"preview_endpoint,omitempty"`
}

type RepositoryLock struct {
	SchemaVersion  int              `toml:"schema_version"`
	Repository     string           `toml:"repository"`
	PackageVersion []PackageVersion `toml:"package_version"`
	Placement      []Placement      `toml:"placement"`
}

type PackageVersion struct {
	Package string       `toml:"package"`
	Version string       `toml:"version"`
	State   string       `toml:"state"`
	Blobs   []LockedBlob `toml:"blob"`
}

type LockedBlob struct {
	Filename     string `toml:"filename"`
	Architecture string `toml:"architecture,omitempty"`
	Size         int64  `toml:"size"`
	MD5          string `toml:"md5,omitempty"`
	SHA1         string `toml:"sha1,omitempty"`
	SHA256       string `toml:"sha256"`
	// Added is when this artifact entered the lock, RFC 3339. It is written once
	// and never rewritten, so it says when the bytes were published rather than
	// when the repository was last built — which is the question someone reading
	// a listing is actually asking. Locks written before this field existed have
	// no answer to give and leave it empty.
	Added  string          `toml:"added,omitempty"`
	Origin *ArtifactOrigin `toml:"origin,omitempty"`
}

type ArtifactOrigin struct {
	Kind string `toml:"kind"`
	URL  string `toml:"url"`
	// Provenance is how this artifact's SHA-256 was established.
	//
	// A digest is only worth what its source is worth, and a lock that cannot tell
	// one verified against a signed Release from one computed off bytes a mirror
	// happened to return is not the reviewable evidence the rest of this design
	// rests on. See PLAN.md §3.8.
	//
	// Empty in a lock written before this existed, which reads as ProvenanceOperator:
	// the only way to record an origin then was adopt, where a person supplied the
	// digest.
	Provenance DigestProvenance `toml:"provenance,omitempty"`
}

// DigestProvenance says how a recorded SHA-256 was established. The values are
// ordered by strength, so a workspace can state a floor rather than inspecting
// each artifact.
type DigestProvenance string

const (
	// ProvenanceSignedIndex means an index signature verified against a key the
	// operator supplied, and the digest came from within that signed document's
	// chain. Available where a format signs its index: deb and rpm.
	ProvenanceSignedIndex DigestProvenance = "signed-index"
	// ProvenanceIndexChain means the digest came from a document whose own digest
	// was stated by a root document — Packages named by Release, primary.xml named
	// by repomd.xml. Nothing is authenticated, but one document is the root of
	// trust instead of every entry, and truncation or corruption is caught.
	ProvenanceIndexChain DigestProvenance = "index-chain"
	// ProvenanceIndexStated means an index stated the digest and the fetched bytes
	// matched it. This is pip's model over HTTPS, and the strongest a PyPI or Helm
	// index supports.
	ProvenanceIndexStated DigestProvenance = "index-stated"
	// ProvenanceComputed means snailmail hashed what it downloaded and nobody
	// stated the digest in advance. It proves the download was self-consistent and
	// no more. Alpine needs it, because APKINDEX states a SHA-1 of a package's
	// control section rather than a digest of the file.
	ProvenanceComputed DigestProvenance = "computed"
	// ProvenanceOperator means a person supplied the digest, which is what adopt
	// has always required.
	ProvenanceOperator DigestProvenance = "operator"
)

// provenanceStrength orders the levels. Higher is stronger, so a minimum floor is
// a comparison rather than a set membership test.
var provenanceStrength = map[DigestProvenance]int{
	ProvenanceComputed:    1,
	ProvenanceIndexStated: 2,
	ProvenanceIndexChain:  3,
	ProvenanceOperator:    4,
	ProvenanceSignedIndex: 5,
}

// ValidProvenance reports whether a value is one snailmail records.
func ValidProvenance(provenance DigestProvenance) bool {
	_, known := provenanceStrength[provenance]
	return known
}

// AtLeast reports whether this provenance meets a floor.
func (provenance DigestProvenance) AtLeast(floor DigestProvenance) bool {
	return provenanceStrength[provenance] >= provenanceStrength[floor]
}

// DigestProvenanceOf reads how a blob's digest was established.
//
// An artifact with no origin was handed to snailmail directly, and one recorded
// before this field existed came through adopt, where a person supplied the
// digest. Both are ProvenanceOperator, so a lock always has an answer rather than
// a gap a reader has to interpret.
func DigestProvenanceOf(blob LockedBlob) DigestProvenance {
	if blob.Origin == nil || blob.Origin.Provenance == "" {
		return ProvenanceOperator
	}
	return blob.Origin.Provenance
}

type Placement struct {
	Package string `toml:"package"`
	Version string `toml:"version"`
	Track   string `toml:"track"`
	Distro  string `toml:"distro,omitempty"`
}

type PublicationRecord struct {
	SchemaVersion int      `json:"schema_version"`
	PlanID        string   `json:"plan_id"`
	ChangeID      string   `json:"change_id"`
	Repository    string   `json:"repository"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	BlobSHA256    []string `json:"blob_sha256"`
	TreeSHA256    string   `json:"tree_sha256"`
	RecordedAt    string   `json:"recorded_at"`
}

type DeploymentRecord struct {
	SchemaVersion                int      `json:"schema_version"`
	Repository                   string   `json:"repository"`
	PlanID                       string   `json:"plan_id"`
	ChangeID                     string   `json:"change_id"`
	TreeSHA256                   string   `json:"tree_sha256"`
	ManifestSHA256               string   `json:"manifest_sha256,omitempty"`
	NativeRevision               string   `json:"native_revision"`
	DeployedAt                   string   `json:"deployed_at"`
	ActiveSigningFingerprint     string   `json:"active_signing_fingerprint,omitempty"`
	TrustedSigningFingerprints   []string `json:"trusted_signing_fingerprints,omitempty"`
	SigningKeyringPath           string   `json:"signing_keyring_path,omitempty"`
	SigningRotationPhase         string   `json:"signing_rotation_phase,omitempty"`
	SigningMinimumRefreshSeconds int64    `json:"signing_minimum_refresh_seconds,omitempty"`
	TrustSince                   string   `json:"trust_since,omitempty"`
}

type Plan struct {
	SchemaVersion int         `json:"schema_version"`
	PlanID        string      `json:"plan_id"`
	Payload       PlanPayload `json:"payload"`
}

type PlanPayload struct {
	EngineVersion           string           `json:"engine_version"`
	GitRevision             string           `json:"git_revision"`
	ManifestSHA256          string           `json:"manifest_sha256"`
	WorkspaceID             string           `json:"workspace_id"`
	Forge                   string           `json:"forge,omitempty"`
	ForgeRepository         string           `json:"forge_repository,omitempty"`
	ForgeHost               string           `json:"forge_host,omitempty"`
	GeneratedAt             string           `json:"generated_at"`
	CreatedAt               string           `json:"created_at"`
	ExpiresAt               string           `json:"expires_at"`
	VerificationMode        string           `json:"verification_mode"`
	BlobStore               BlobStoreConfig  `json:"blob_store"`
	BlobStoreIdentitySHA256 string           `json:"blob_store_identity_sha256"`
	KnowledgeSHA256         string           `json:"knowledge_sha256"`
	Repositories            []PlanRepository `json:"repositories"`
}

type PlanRepository struct {
	Name                      string                   `json:"name"`
	Gate                      string                   `json:"gate"`
	ApprovalKeys              []string                 `json:"approval_keys,omitempty"`
	Format                    string                   `json:"format"`
	LockSHA256                string                   `json:"lock_sha256"`
	Host                      HostConfig               `json:"host"`
	Visibility                string                   `json:"visibility"`
	HostIdentitySHA256        string                   `json:"host_identity_sha256"`
	CanonicalEndpoint         string                   `json:"canonical_endpoint"`
	InstallDocSHA256          string                   `json:"install_doc_sha256,omitempty"`
	ObservedRevision          string                   `json:"observed_revision,omitempty"`
	ObservedPlanID            string                   `json:"observed_plan_id,omitempty"`
	ObservedChangeID          string                   `json:"observed_change_id,omitempty"`
	ObservedReleaseSHA256     string                   `json:"observed_release_sha256,omitempty"`
	ObservedManifestSHA256    string                   `json:"observed_manifest_sha256,omitempty"`
	ObservedRestoreID         string                   `json:"observed_restore_id,omitempty"`
	ObservedRestoreSHA256     string                   `json:"observed_restore_sha256,omitempty"`
	ObservedRestoreRootSHA256 string                   `json:"observed_restore_root_sha256,omitempty"`
	ObservedDeployment        DeploymentRecord         `json:"observed_deployment"`
	FaithfulPreview           bool                     `json:"faithful_preview"`
	ConditionalCommit         bool                     `json:"conditional_commit"`
	ConditionalRestore        bool                     `json:"conditional_restore"`
	PrivateRead               bool                     `json:"private_read"`
	CredentialBrokerIdentity  string                   `json:"credential_broker_identity,omitempty"`
	Signing                   []PlanSigning            `json:"signing,omitempty"`
	PublicationRecords        bool                     `json:"publication_records"`
	PublicationBindings       []PlanPublicationBinding `json:"publication_bindings,omitempty"`
	Acquisitions              []PlanAcquisition        `json:"acquisitions,omitempty"`
	ObservedTreeSHA256        string                   `json:"observed_tree_sha256,omitempty"`
	DesiredTreeSHA256         string                   `json:"desired_tree_sha256"`
	DesiredManifestSHA256     string                   `json:"desired_manifest_sha256,omitempty"`
	ChangeID                  string                   `json:"change_id"`
	Action                    string                   `json:"action"`
}

type PlanPublicationBinding struct {
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	BlobSHA256 []string `json:"blob_sha256"`
}

type PlanAcquisition struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	OriginURL string `json:"origin_url"`
}

type PlanSigning struct {
	KeyName               string          `json:"key_name"`
	Algorithm             string          `json:"algorithm"`
	Fingerprint           string          `json:"fingerprint"`
	PublicKeyPath         string          `json:"public_key_path"`
	PublicKeySHA256       string          `json:"public_key_sha256"`
	PublicArmorPath       string          `json:"public_armor_path"`
	PublicArmorSHA256     string          `json:"public_armor_sha256"`
	SignatureTime         string          `json:"signature_time"`
	RecipeSHA256          string          `json:"recipe_sha256"`
	KeyringPath           string          `json:"keyring_path"`
	KeyringSHA256         string          `json:"keyring_sha256"`
	TrustedKeys           []PlanPublicKey `json:"trusted_keys"`
	RotationPhase         string          `json:"rotation_phase,omitempty"`
	MinimumRefreshSeconds int64           `json:"minimum_refresh_seconds,omitempty"`
	Nodes                 []SigningNode   `json:"nodes"`
}

type PlanPublicKey struct {
	KeyName         string `json:"key_name"`
	Fingerprint     string `json:"fingerprint"`
	PublicKeyPath   string `json:"public_key_path"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type SigningNode struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	DependsOn     []string `json:"depends_on"`
	Scheme        string   `json:"scheme"`
	PayloadSHA256 string   `json:"payload_sha256"`
	OutputPath    string   `json:"output_path"`
	ContentSHA256 string   `json:"content_sha256"`
	Content       []byte   `json:"content"`
}

type InitOptions struct {
	Name            string
	Forge           string
	ForgeRepository string
	ForgeHost       string
}

type BlobStoreOptions struct {
	Type         string
	Bucket       string
	Prefix       string
	Region       string
	Endpoint     string
	UsePathStyle bool
}

type SetupOptions struct {
	Name              string
	Format            string
	Output            string
	HostType          string
	Gate              string
	ApprovalKeys      []string
	SigningKeys       []string
	AllowUnsigned     bool
	Keep              int
	Track             string
	Visibility        string
	Target            string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	CanonicalEndpoint string
	UsePathStyle      bool
	ReadAuth          string
	CredentialBroker  string
	Repository        string
	Branch            string
	PreviewRepository string
	PreviewBranch     string
	PreviewEndpoint   string
	Suite             string
	Component         string
	Architectures     []string
}

type PlanOptions struct {
	GeneratedAt time.Time
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
