package host

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type BasicCredential interface {
	Basic(context.Context) (string, string, error)
	Destroy()
}

type ClientAccess struct {
	Endpoint           string
	Routes             []ClientRoute
	PropagationTimeout time.Duration
	Credential         BasicCredential
}

type ClientRoute struct {
	URL    string
	Size   int64
	SHA256 string
}

type ReadScope struct {
	WorkspaceID  string   `json:"workspace_id"`
	Repository   string   `json:"repository"`
	HostIdentity string   `json:"host_identity"`
	Bucket       string   `json:"bucket"`
	Endpoint     string   `json:"endpoint"`
	PlanID       string   `json:"plan_id"`
	ChangeID     string   `json:"change_id"`
	StageID      string   `json:"stage_id,omitempty"`
	TreeSHA256   string   `json:"tree_sha256"`
	Prefixes     []string `json:"prefixes"`
}

type CredentialBroker interface {
	Issue(context.Context, ReadScope) (BasicCredential, error)
	Identity() string
}

type Repository struct {
	Name              string
	WorkspaceID       string
	HostIdentity      string
	Format            string
	Type              string
	Visibility        string
	WorkspaceRoot     string
	Path              string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	CanonicalEndpoint string
	UsePathStyle      bool
	ReadAuth          string
	CredentialBroker  string
	RemoteRepository  string
	Branch            string
	PreviewRepository string
	PreviewBranch     string
	PreviewEndpoint   string
}

type Capabilities struct {
	FaithfulPreview          bool
	ConditionalCommit        bool
	ConditionalRestore       bool
	PrivateRead              bool
	CredentialBrokerIdentity string
}

type PublishedRevision struct {
	NativeRevision    string
	TreeSHA256        string
	PlanID            string
	ChangeID          string
	RestoreID         string
	ReleaseSHA256     string
	ManifestSHA256    string
	RestoreSHA256     string
	RestoreRootSHA256 string
}

type File struct {
	Path   string
	Size   int64
	SHA256 string
}

type StageRequest struct {
	PlanID           string
	ChangeID         string
	PreviousRevision string
	Directory        string
	TreeSHA256       string
	Files            []File
	CommitPaths      []string
}

type StagedPublication struct {
	ID               string
	PlanID           string
	ChangeID         string
	PreviousRevision string
	PreviewEndpoint  string
	TreeSHA256       string
	Files            []File
	CommitPaths      []string
	Access           ClientAccess
}

type ExpectedRevision struct {
	NativeRevision    string
	TreeSHA256        string
	PlanID            string
	ChangeID          string
	ReleaseSHA256     string
	ManifestSHA256    string
	RestoreID         string
	RestoreSHA256     string
	RestoreRootSHA256 string
}

type RestoreRef struct {
	ID               string
	PlanID           string
	ChangeID         string
	FailedTree       string
	DescriptorSHA256 string
	RootSHA256       string
}

type CommitResult struct {
	Revision          PublishedRevision
	CanonicalEndpoint string
	RestoreRef        *RestoreRef
	Access            ClientAccess
}

type Host interface {
	Capabilities(context.Context, Repository) (Capabilities, error)
	Observe(context.Context, Repository) (PublishedRevision, error)
	ReadAccess(context.Context, Repository, PublishedRevision) (ClientAccess, error)
	Stage(context.Context, Repository, StageRequest) (StagedPublication, error)
	Commit(context.Context, Repository, StagedPublication, ExpectedRevision) (CommitResult, error)
	Restore(context.Context, Repository, RestoreRef, ExpectedRevision) (PublishedRevision, error)
	Abort(context.Context, Repository, StagedPublication) error
}

type Resolver interface {
	Resolve(context.Context, Repository) (Host, error)
}

type ErrorKind string

const (
	ErrorInvalidConfiguration ErrorKind = "invalid_configuration"
	ErrorInfrastructure       ErrorKind = "infrastructure_failure"
	ErrorStale                ErrorKind = "stale_plan"
	ErrorIndeterminate        ErrorKind = "indeterminate"
)

type Error struct {
	Kind                  ErrorKind
	Operation             string
	Retryable             bool
	EffectMayHaveOccurred bool
	Err                   error
}

func (err *Error) Error() string {
	if err.Err == nil {
		return fmt.Sprintf("%s: %s", err.Operation, err.Kind)
	}
	return fmt.Sprintf("%s: %v", err.Operation, err.Err)
}

func (err *Error) Unwrap() error {
	return err.Err
}

func IsKind(err error, kind ErrorKind) bool {
	var hostError *Error
	return errors.As(err, &hostError) && hostError.Kind == kind
}
