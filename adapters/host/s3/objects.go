package s3host

import (
	"context"
	"errors"
	"io"
)

var (
	ErrNotFound     = errors.New("object not found")
	ErrPrecondition = errors.New("object precondition failed")
)

type Conditions struct {
	IfMatch     string
	IfNoneMatch bool
}

type ObjectInfo struct {
	ETag     string
	Size     int64
	SHA256   string
	Metadata map[string]string
}

type PutRequest struct {
	Key         string
	Body        io.Reader
	Size        int64
	SHA256      string
	ContentType string
	Metadata    map[string]string
	Conditions  Conditions
}

type ObjectClient interface {
	Head(context.Context, string) (ObjectInfo, error)
	Get(context.Context, string, int64) ([]byte, ObjectInfo, error)
	Put(context.Context, PutRequest) (ObjectInfo, error)
	CopyCreate(context.Context, string, string, int64, string) (ObjectInfo, error)
	Delete(context.Context, string, Conditions) error
}
