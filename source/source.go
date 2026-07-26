package source

import (
	"context"
	"errors"
)

var ErrLimit = errors.New("source response exceeds limit")

type Response struct {
	URL         string
	StatusCode  int
	ContentType string
	Body        []byte
}

type Fetcher interface {
	Fetch(context.Context, string, int64) (Response, error)
}
