package wire

import (
	"context"
	"fmt"
	"sync"

	commandcredential "github.com/shellcell/snailmail/adapters/credential/command"
	githubpages "github.com/shellcell/snailmail/adapters/host/githubpages"
	localhost "github.com/shellcell/snailmail/adapters/host/local"
	s3host "github.com/shellcell/snailmail/adapters/host/s3"
	"github.com/shellcell/snailmail/host"
)

type HostResolver struct {
	local       *localhost.Adapter
	brokerMutex sync.Mutex
	broker      *commandcredential.Broker
}

func NewHostResolver() *HostResolver {
	return &HostResolver{local: localhost.New()}
}

func (resolver *HostResolver) Resolve(ctx context.Context, repository host.Repository) (host.Host, error) {
	switch repository.Type {
	case "local":
		return resolver.local, nil
	case "s3":
		if repository.Visibility == "private" {
			broker, err := resolver.credentialBroker()
			if err != nil {
				return nil, err
			}
			return s3host.NewAWS(ctx, repository, broker)
		}
		return s3host.NewAWS(ctx, repository)
	case "github-pages":
		return githubpages.New(), nil
	default:
		return nil, fmt.Errorf("unsupported host type %q", repository.Type)
	}
}

func (resolver *HostResolver) credentialBroker() (*commandcredential.Broker, error) {
	resolver.brokerMutex.Lock()
	defer resolver.brokerMutex.Unlock()
	if resolver.broker != nil {
		return resolver.broker, nil
	}
	broker, err := commandcredential.NewFromEnvironment()
	if err != nil {
		return nil, err
	}
	resolver.broker = broker
	return broker, nil
}

func (resolver *HostResolver) Close() error {
	resolver.brokerMutex.Lock()
	defer resolver.brokerMutex.Unlock()
	if resolver.broker == nil {
		return nil
	}
	err := resolver.broker.Close()
	resolver.broker = nil
	return err
}
