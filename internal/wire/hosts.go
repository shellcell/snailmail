package wire

import (
	"context"
	"fmt"

	localhost "github.com/shellcell/snailmail/adapters/host/local"
	s3host "github.com/shellcell/snailmail/adapters/host/s3"
	"github.com/shellcell/snailmail/host"
)

type HostResolver struct {
	local *localhost.Adapter
}

func NewHostResolver() *HostResolver {
	return &HostResolver{local: localhost.New()}
}

func (resolver *HostResolver) Resolve(ctx context.Context, repository host.Repository) (host.Host, error) {
	switch repository.Type {
	case "local":
		return resolver.local, nil
	case "s3":
		return s3host.NewAWS(ctx, repository)
	default:
		return nil, fmt.Errorf("unsupported host type %q", repository.Type)
	}
}
