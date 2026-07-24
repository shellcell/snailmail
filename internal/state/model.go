package state

import "time"

const (
	ManifestSchema = 2
	LockSchema     = 1
	PlanSchema     = 3
	LedgerSchema   = 1
)

type Manifest struct {
	SchemaVersion int                   `toml:"schema_version"`
	Workspace     Workspace             `toml:"workspace"`
	Repositories  map[string]Repository `toml:"repo"`
}

type Workspace struct {
	Name string `toml:"name"`
}

type Repository struct {
	Format        string     `toml:"format"`
	Lock          string     `toml:"lock"`
	Host          HostConfig `toml:"host"`
	Visibility    string     `toml:"visibility"`
	Gate          string     `toml:"gate"`
	Suite         string     `toml:"suite,omitempty"`
	Component     string     `toml:"component,omitempty"`
	Architectures []string   `toml:"architectures,omitempty"`
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

type Plan struct {
	SchemaVersion int         `json:"schema_version"`
	PlanID        string      `json:"plan_id"`
	Payload       PlanPayload `json:"payload"`
}

type PlanPayload struct {
	EngineVersion    string           `json:"engine_version"`
	GitRevision      string           `json:"git_revision"`
	ManifestSHA256   string           `json:"manifest_sha256"`
	GeneratedAt      string           `json:"generated_at"`
	CreatedAt        string           `json:"created_at"`
	ExpiresAt        string           `json:"expires_at"`
	VerificationMode string           `json:"verification_mode"`
	Repositories     []PlanRepository `json:"repositories"`
}

type PlanRepository struct {
	Name                      string     `json:"name"`
	Format                    string     `json:"format"`
	LockSHA256                string     `json:"lock_sha256"`
	Host                      HostConfig `json:"host"`
	Visibility                string     `json:"visibility"`
	HostIdentitySHA256        string     `json:"host_identity_sha256"`
	CanonicalEndpoint         string     `json:"canonical_endpoint"`
	InstallDocSHA256          string     `json:"install_doc_sha256,omitempty"`
	ObservedRevision          string     `json:"observed_revision,omitempty"`
	ObservedPlanID            string     `json:"observed_plan_id,omitempty"`
	ObservedChangeID          string     `json:"observed_change_id,omitempty"`
	ObservedReleaseSHA256     string     `json:"observed_release_sha256,omitempty"`
	ObservedManifestSHA256    string     `json:"observed_manifest_sha256,omitempty"`
	ObservedRestoreID         string     `json:"observed_restore_id,omitempty"`
	ObservedRestoreSHA256     string     `json:"observed_restore_sha256,omitempty"`
	ObservedRestoreRootSHA256 string     `json:"observed_restore_root_sha256,omitempty"`
	FaithfulPreview           bool       `json:"faithful_preview"`
	ConditionalCommit         bool       `json:"conditional_commit"`
	ConditionalRestore        bool       `json:"conditional_restore"`
	ObservedTreeSHA256        string     `json:"observed_tree_sha256,omitempty"`
	DesiredTreeSHA256         string     `json:"desired_tree_sha256"`
	DesiredManifestSHA256     string     `json:"desired_manifest_sha256,omitempty"`
	ChangeID                  string     `json:"change_id"`
	Action                    string     `json:"action"`
}

type InitOptions struct {
	Name string
}

type SetupOptions struct {
	Name              string
	Format            string
	Output            string
	HostType          string
	Visibility        string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	CanonicalEndpoint string
	UsePathStyle      bool
	Suite             string
	Component         string
	Architectures     []string
}

type PlanOptions struct {
	GeneratedAt time.Time
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
