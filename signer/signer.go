package signer

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("signing key not found")

const (
	AlgorithmOpenPGPRSA4096 = "openpgp-rsa4096"
	SchemeOpenPGPCleartext  = "openpgp-cleartext-v4"
	SchemeOpenPGPDetached   = "openpgp-detached-armored-v4"
)

type Ref struct {
	Backend string
	ID      string
}

type Identity struct {
	Fingerprint string
	Algorithm   string
	Bits        int
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type Request struct {
	Scheme    string
	Payload   []byte
	CreatedAt time.Time
}

type Response struct {
	Scheme      string
	Fingerprint string
	Content     []byte
}

type Signer interface {
	Identity(context.Context) (Identity, error)
	Sign(context.Context, Request) (Response, error)
	Close() error
}

type Resolver interface {
	Resolve(context.Context, Ref) (Signer, error)
}

type Generated struct {
	Identity     Identity
	PublicBinary []byte
	PublicArmor  []byte
}

type Generator interface {
	Generate(context.Context, Ref, string, time.Time, time.Duration) (Generated, error)
	Public(context.Context, Ref) (Generated, error)
	Delete(context.Context, Ref) error
}
