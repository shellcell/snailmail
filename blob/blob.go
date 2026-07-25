package blob

import (
	"context"
	"errors"
	"io"
)

var (
	ErrNotFound     = errors.New("blob not found")
	ErrPrecondition = errors.New("blob precondition failed")
)

type Ref struct {
	SHA256 string
	Size   int64
}

type Store interface {
	Put(context.Context, Ref, io.Reader) error
	Fetch(context.Context, Ref, io.Writer) error
}

type Configuration struct {
	Type         string
	WorkspaceID  string
	Bucket       string
	Prefix       string
	Region       string
	Endpoint     string
	UsePathStyle bool
}

type Resolver interface {
	Resolve(context.Context, Configuration) (Store, error)
}
