package state

import "time"

const (
	ManifestSchema   = 5
	LockSchema       = 1
	PlanSchema       = 7
	LedgerSchema     = 1
	DeploymentSchema = 1
)

type Manifest struct {
	SchemaVersion int                   `toml:"schema_version"`
	Workspace     Workspace             `toml:"workspace"`
	BlobStore     BlobStoreConfig       `toml:"blob_store"`
	Keys          map[string]SigningKey `toml:"key,omitempty"`
	Repositories  map[string]Repository `toml:"repo"`
}

type Workspace struct {
	Name            string `toml:"name"`
	ID              string `toml:"id"`
	ForgeRepository string `toml:"forge_repository,omitempty"`
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
	Format        string     `toml:"format"`
	Lock          string     `toml:"lock"`
	Host          HostConfig `toml:"host"`
	Visibility    string     `toml:"visibility"`
	Gate          string     `toml:"gate"`
	ApprovalKeys  []string   `toml:"approval_keys,omitempty"`
	SigningKeys   []string   `toml:"signing_keys,omitempty"`
	Suite         string     `toml:"suite,omitempty"`
	Component     string     `toml:"component,omitempty"`
	Architectures []string   `toml:"architectures,omitempty"`
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
	Type              string `toml:"type" json:"type"`
	Path              string `toml:"path,omitempty" json:"path,omitempty"`
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
	SchemaVersion  int    `json:"schema_version"`
	Repository     string `json:"repository"`
	PlanID         string `json:"plan_id"`
	ChangeID       string `json:"change_id"`
	TreeSHA256     string `json:"tree_sha256"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	NativeRevision string `json:"native_revision"`
	DeployedAt     string `json:"deployed_at"`
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
	ForgeRepository         string           `json:"forge_repository,omitempty"`
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
	Name                      string           `json:"name"`
	Gate                      string           `json:"gate"`
	ApprovalKeys              []string         `json:"approval_keys,omitempty"`
	Format                    string           `json:"format"`
	LockSHA256                string           `json:"lock_sha256"`
	Host                      HostConfig       `json:"host"`
	Visibility                string           `json:"visibility"`
	HostIdentitySHA256        string           `json:"host_identity_sha256"`
	CanonicalEndpoint         string           `json:"canonical_endpoint"`
	InstallDocSHA256          string           `json:"install_doc_sha256,omitempty"`
	ObservedRevision          string           `json:"observed_revision,omitempty"`
	ObservedPlanID            string           `json:"observed_plan_id,omitempty"`
	ObservedChangeID          string           `json:"observed_change_id,omitempty"`
	ObservedReleaseSHA256     string           `json:"observed_release_sha256,omitempty"`
	ObservedManifestSHA256    string           `json:"observed_manifest_sha256,omitempty"`
	ObservedRestoreID         string           `json:"observed_restore_id,omitempty"`
	ObservedRestoreSHA256     string           `json:"observed_restore_sha256,omitempty"`
	ObservedRestoreRootSHA256 string           `json:"observed_restore_root_sha256,omitempty"`
	ObservedDeployment        DeploymentRecord `json:"observed_deployment"`
	FaithfulPreview           bool             `json:"faithful_preview"`
	ConditionalCommit         bool             `json:"conditional_commit"`
	ConditionalRestore        bool             `json:"conditional_restore"`
	PrivateRead               bool             `json:"private_read"`
	CredentialBrokerIdentity  string           `json:"credential_broker_identity,omitempty"`
	Signing                   []PlanSigning    `json:"signing,omitempty"`
	ObservedTreeSHA256        string           `json:"observed_tree_sha256,omitempty"`
	DesiredTreeSHA256         string           `json:"desired_tree_sha256"`
	DesiredManifestSHA256     string           `json:"desired_manifest_sha256,omitempty"`
	ChangeID                  string           `json:"change_id"`
	Action                    string           `json:"action"`
}

type PlanSigning struct {
	KeyName           string        `json:"key_name"`
	Algorithm         string        `json:"algorithm"`
	Fingerprint       string        `json:"fingerprint"`
	PublicKeyPath     string        `json:"public_key_path"`
	PublicKeySHA256   string        `json:"public_key_sha256"`
	PublicArmorPath   string        `json:"public_armor_path"`
	PublicArmorSHA256 string        `json:"public_armor_sha256"`
	SignatureTime     string        `json:"signature_time"`
	RecipeSHA256      string        `json:"recipe_sha256"`
	Nodes             []SigningNode `json:"nodes"`
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
	ForgeRepository string
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
	Visibility        string
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
