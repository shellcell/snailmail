package host

import (
	"context"
	"errors"
	"fmt"
)

type Repository struct {
	Name              string
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
}

type Capabilities struct {
	FaithfulPreview    bool
	ConditionalCommit  bool
	ConditionalRestore bool
	PrivateRead        bool
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
	PlanID      string
	ChangeID    string
	Directory   string
	TreeSHA256  string
	Files       []File
	CommitPaths []string
}

type StagedPublication struct {
	ID              string
	PlanID          string
	ChangeID        string
	PreviewEndpoint string
	TreeSHA256      string
	Files           []File
	CommitPaths     []string
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
}

type Host interface {
	Capabilities(context.Context, Repository) (Capabilities, error)
	Observe(context.Context, Repository) (PublishedRevision, error)
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
