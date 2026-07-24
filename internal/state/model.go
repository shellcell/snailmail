package state

import "time"

const (
	ManifestSchema = 1
	LockSchema     = 1
	PlanSchema     = 1
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
	Format        string   `toml:"format"`
	Lock          string   `toml:"lock"`
	Output        string   `toml:"output"`
	Gate          string   `toml:"gate"`
	Suite         string   `toml:"suite,omitempty"`
	Component     string   `toml:"component,omitempty"`
	Architectures []string `toml:"architectures,omitempty"`
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
	EngineVersion  string           `json:"engine_version"`
	GitRevision    string           `json:"git_revision"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	GeneratedAt    string           `json:"generated_at"`
	CreatedAt      string           `json:"created_at"`
	ExpiresAt      string           `json:"expires_at"`
	Repositories   []PlanRepository `json:"repositories"`
}

type PlanRepository struct {
	Name               string `json:"name"`
	Format             string `json:"format"`
	LockSHA256         string `json:"lock_sha256"`
	Output             string `json:"output"`
	ObservedTreeSHA256 string `json:"observed_tree_sha256,omitempty"`
	DesiredTreeSHA256  string `json:"desired_tree_sha256"`
	ChangeID           string `json:"change_id"`
	Action             string `json:"action"`
}

type InitOptions struct {
	Name string
}

type SetupOptions struct {
	Name          string
	Format        string
	Output        string
	Suite         string
	Component     string
	Architectures []string
}

type PlanOptions struct {
	GeneratedAt time.Time
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
