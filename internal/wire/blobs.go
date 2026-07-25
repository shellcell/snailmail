package wire

import (
	"context"
	"fmt"

	s3blob "github.com/shellcell/snailmail/adapters/blob/s3"
	"github.com/shellcell/snailmail/blob"
)

type BlobResolver struct{}

func NewBlobResolver() *BlobResolver {
	return &BlobResolver{}
}

func (resolver *BlobResolver) Resolve(ctx context.Context, configuration blob.Configuration) (blob.Store, error) {
	switch configuration.Type {
	case "local":
		return nil, nil
	case "s3":
		return s3blob.NewAWS(ctx, configuration)
	default:
		return nil, fmt.Errorf("unsupported blob store type %q", configuration.Type)
	}
}
