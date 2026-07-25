package openpgpsigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	protonopenpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/shellcell/snailmail/signer"
)

type Generated struct {
	Identity     signer.Identity
	PrivateArmor []byte
	PublicBinary []byte
	PublicArmor  []byte
}

type Local struct {
	entity   *protonopenpgp.Entity
	identity signer.Identity
	public   []byte
}

func Generate(name string, createdAt time.Time, expiresIn time.Duration, passphrase []byte) (Generated, error) {
	if name == "" || createdAt.IsZero() || expiresIn <= 0 || expiresIn > time.Duration(^uint32(0))*time.Second || len(passphrase) == 0 {
		return Generated{}, errors.New("name, creation time, bounded expiry, and passphrase are required")
	}
	deterministic := false
	configuration := &packet.Config{
		Rand: rand.Reader, Time: func() time.Time { return createdAt.UTC() }, DefaultHash: crypto.SHA256,
		DefaultCipher: packet.CipherAES256, RSABits: 4096, MinRSABits: 4096, Algorithm: packet.PubKeyAlgoRSA,
		KeyLifetimeSecs: uint32(expiresIn / time.Second), V6Keys: false, NonDeterministicSignaturesViaNotation: &deterministic,
	}
	entity, err := protonopenpgp.NewEntity(name, "snailmail repository signing", "", configuration)
	if err != nil {
		return Generated{}, fmt.Errorf("generate OpenPGP identity: %w", err)
	}
	identity, err := inspectEntity(entity)
	if err != nil {
		return Generated{}, err
	}
	publicBinary, publicArmor, err := serializePublic(entity)
	if err != nil {
		return Generated{}, err
	}
	if err := entity.EncryptPrivateKeys(passphrase, configuration); err != nil {
		return Generated{}, fmt.Errorf("encrypt OpenPGP private key: %w", err)
	}
	var privateArmor bytes.Buffer
	armored, err := armor.Encode(&privateArmor, protonopenpgp.PrivateKeyType, nil)
	if err != nil {
		return Generated{}, err
	}
	if err := entity.SerializePrivateWithoutSigning(armored, configuration); err != nil {
		_ = armored.Close()
		return Generated{}, fmt.Errorf("serialize encrypted OpenPGP private key: %w", err)
	}
	if err := armored.Close(); err != nil {
		return Generated{}, err
	}
	return Generated{Identity: identity, PrivateArmor: privateArmor.Bytes(), PublicBinary: publicBinary, PublicArmor: publicArmor}, nil
}

func Load(privateArmor, passphrase []byte) (*Local, error) {
	if len(privateArmor) == 0 || len(passphrase) == 0 {
		return nil, errors.New("encrypted private key and passphrase are required")
	}
	entities, err := protonopenpgp.ReadArmoredKeyRing(bytes.NewReader(privateArmor))
	if err != nil || len(entities) != 1 {
		return nil, errors.New("invalid encrypted OpenPGP private key")
	}
	entity := entities[0]
	if err := entity.DecryptPrivateKeys(passphrase); err != nil {
		return nil, errors.New("decrypt OpenPGP private key")
	}
	identity, err := inspectEntity(entity)
	if err != nil {
		return nil, err
	}
	public, _, err := serializePublic(entity)
	if err != nil {
		return nil, err
	}
	return &Local{entity: entity, identity: identity, public: public}, nil
}

func InspectPublic(content []byte) (signer.Identity, error) {
	entities, err := protonopenpgp.ReadKeyRing(bytes.NewReader(content))
	if err != nil || len(entities) != 1 {
		return signer.Identity{}, errors.New("invalid OpenPGP public keyring")
	}
	return inspectEntity(entities[0])
}

func InspectPublicKeyring(content []byte) ([]signer.Identity, error) {
	entities, err := protonopenpgp.ReadKeyRing(bytes.NewReader(content))
	if err != nil || len(entities) == 0 {
		return nil, errors.New("invalid OpenPGP public keyring")
	}
	identities := make([]signer.Identity, 0, len(entities))
	for _, entity := range entities {
		identity, err := inspectEntity(entity)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func ExtractPublicKey(content []byte, fingerprint string) ([]byte, error) {
	entities, err := protonopenpgp.ReadKeyRing(bytes.NewReader(content))
	if err != nil {
		return nil, errors.New("invalid OpenPGP public keyring")
	}
	for _, entity := range entities {
		identity, err := inspectEntity(entity)
		if err != nil {
			return nil, err
		}
		if identity.Fingerprint == fingerprint {
			binary, _, err := serializePublic(entity)
			return binary, err
		}
	}
	return nil, errors.New("OpenPGP public keyring does not contain fingerprint")
}

func InspectArmoredPublic(content []byte) (signer.Identity, error) {
	entities, err := protonopenpgp.ReadArmoredKeyRing(bytes.NewReader(content))
	if err != nil || len(entities) != 1 {
		return signer.Identity{}, errors.New("invalid armored OpenPGP public key")
	}
	return inspectEntity(entities[0])
}

func (local *Local) Identity(context.Context) (signer.Identity, error) {
	return local.identity, nil
}

func (local *Local) Public() (signer.Generated, error) {
	binary, armored, err := serializePublic(local.entity)
	if err != nil {
		return signer.Generated{}, err
	}
	return signer.Generated{Identity: local.identity, PublicBinary: binary, PublicArmor: armored}, nil
}

func (local *Local) Sign(ctx context.Context, request signer.Request) (signer.Response, error) {
	if err := ctx.Err(); err != nil {
		return signer.Response{}, err
	}
	if request.CreatedAt.IsZero() || !request.CreatedAt.Equal(request.CreatedAt.UTC().Truncate(time.Second)) || request.CreatedAt.Before(local.identity.CreatedAt) || !request.CreatedAt.Before(local.identity.ExpiresAt) {
		return signer.Response{}, errors.New("signature time is outside key validity")
	}
	deterministic := false
	configuration := &packet.Config{
		Time: func() time.Time { return request.CreatedAt.UTC() }, DefaultHash: crypto.SHA256,
		MinRSABits: 4096, NonDeterministicSignaturesViaNotation: &deterministic,
	}
	var output bytes.Buffer
	switch request.Scheme {
	case signer.SchemeOpenPGPCleartext:
		key, ok := local.entity.SigningKey(request.CreatedAt)
		if !ok || key.PrivateKey == nil {
			return signer.Response{}, errors.New("OpenPGP identity has no valid signing key")
		}
		writer, err := clearsign.Encode(&output, key.PrivateKey, configuration)
		if err != nil {
			return signer.Response{}, err
		}
		if _, err := writer.Write(request.Payload); err != nil {
			_ = writer.Close()
			return signer.Response{}, err
		}
		if err := writer.Close(); err != nil {
			return signer.Response{}, err
		}
	case signer.SchemeOpenPGPDetached:
		if err := protonopenpgp.ArmoredDetachSign(&output, local.entity, bytes.NewReader(request.Payload), configuration); err != nil {
			return signer.Response{}, err
		}
	default:
		return signer.Response{}, fmt.Errorf("unsupported signing scheme %q", request.Scheme)
	}
	response := signer.Response{Scheme: request.Scheme, Fingerprint: local.identity.Fingerprint, Content: output.Bytes()}
	if err := VerifyResponse(request, response, local.public, local.identity.Fingerprint); err != nil {
		return signer.Response{}, fmt.Errorf("verify generated signature: %w", err)
	}
	return response, nil
}

func (local *Local) Close() error {
	local.entity = nil
	return nil
}

func VerifyResponse(request signer.Request, response signer.Response, publicKey []byte, expectedFingerprint string) error {
	if request.Scheme != response.Scheme || response.Fingerprint != expectedFingerprint || len(response.Content) == 0 {
		return errors.New("signature response does not match its request")
	}
	keyring, err := protonopenpgp.ReadKeyRing(bytes.NewReader(publicKey))
	if err != nil || len(keyring) != 1 {
		return errors.New("invalid OpenPGP verification key")
	}
	configuration := &packet.Config{Time: func() time.Time { return request.CreatedAt.UTC() }, MinRSABits: 4096}
	var verified *protonopenpgp.Entity
	var signature *packet.Signature
	switch request.Scheme {
	case signer.SchemeOpenPGPCleartext:
		block, rest := clearsign.Decode(response.Content)
		if block == nil || len(rest) != 0 || !bytes.Equal(block.Plaintext, request.Payload) {
			return errors.New("clear signature payload does not match")
		}
		verified, err = block.VerifySignature(keyring, configuration)
		if err == nil {
			decoded, _ := clearsign.Decode(response.Content)
			signature, err = readSignature(decoded.ArmoredSignature.Body)
		}
	case signer.SchemeOpenPGPDetached:
		verified, err = protonopenpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(request.Payload), bytes.NewReader(response.Content), configuration)
		if err == nil {
			block, armorErr := armor.Decode(bytes.NewReader(response.Content))
			if armorErr != nil || block.Type != protonopenpgp.SignatureType {
				return errors.New("invalid armored detached signature")
			}
			signature, err = readSignature(block.Body)
		}
	default:
		return fmt.Errorf("unsupported signing scheme %q", request.Scheme)
	}
	if err != nil || verified == nil || hex.EncodeToString(verified.PrimaryKey.Fingerprint) != expectedFingerprint {
		return errors.New("OpenPGP signature verification failed")
	}
	if signature == nil || signature.Version != 4 || signature.Hash != crypto.SHA256 || !signature.CreationTime.Equal(request.CreatedAt.UTC()) {
		return errors.New("OpenPGP signature metadata does not match its request")
	}
	return nil
}

func inspectEntity(entity *protonopenpgp.Entity) (signer.Identity, error) {
	if entity == nil || entity.PrimaryKey == nil || entity.PrimaryKey.Version != 4 || entity.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoRSA {
		return signer.Identity{}, errors.New("OpenPGP identity must use an RSA v4 primary key")
	}
	bits, err := entity.PrimaryKey.BitLength()
	if err != nil || bits != 4096 {
		return signer.Identity{}, errors.New("OpenPGP identity must use RSA4096")
	}
	public, ok := entity.PrimaryKey.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 4096 {
		return signer.Identity{}, errors.New("OpenPGP identity has invalid RSA public material")
	}
	primary := entity.PrimaryIdentity()
	if primary == nil || primary.SelfSignature == nil || !primary.SelfSignature.FlagsValid || !primary.SelfSignature.FlagSign || primary.SelfSignature.KeyLifetimeSecs == nil || *primary.SelfSignature.KeyLifetimeSecs == 0 {
		return signer.Identity{}, errors.New("OpenPGP identity lacks bounded signing usage")
	}
	createdAt := entity.PrimaryKey.CreationTime.UTC()
	expiresAt := createdAt.Add(time.Duration(*primary.SelfSignature.KeyLifetimeSecs) * time.Second)
	return signer.Identity{
		Fingerprint: hex.EncodeToString(entity.PrimaryKey.Fingerprint), Algorithm: signer.AlgorithmOpenPGPRSA4096,
		Bits: int(bits), CreatedAt: createdAt, ExpiresAt: expiresAt,
	}, nil
}

func serializePublic(entity *protonopenpgp.Entity) ([]byte, []byte, error) {
	var binary bytes.Buffer
	if err := entity.Serialize(&binary); err != nil {
		return nil, nil, err
	}
	var armored bytes.Buffer
	writer, err := armor.Encode(&armored, protonopenpgp.PublicKeyType, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := entity.Serialize(writer); err != nil {
		_ = writer.Close()
		return nil, nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, nil, err
	}
	return binary.Bytes(), armored.Bytes(), nil
}

func readSignature(reader io.Reader) (*packet.Signature, error) {
	value, err := packet.Read(reader)
	if err != nil {
		return nil, err
	}
	signature, ok := value.(*packet.Signature)
	if !ok {
		return nil, errors.New("OpenPGP response does not contain a signature packet")
	}
	return signature, nil
}
