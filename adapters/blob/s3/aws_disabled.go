//go:build nos3

package s3blob

import (
	"context"
	"errors"

	"github.com/shellcell/snailmail/blob"
)

// NewAWS reports that this build excludes S3 support. The protocol logic in
// this package is SDK-free and still compiled; only the AWS client is absent.
func NewAWS(_ context.Context, _ blob.Configuration) (*Store, error) {
	return nil, errors.New("this snailmail build was compiled without S3 support (nos3)")
}
