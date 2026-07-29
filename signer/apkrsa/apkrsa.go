// Package apkrsa implements the signing Alpine's apk requires.
//
// apk does not use OpenPGP. An index is signed with a bare PKCS#1 v1.5 RSA
// signature and verified against a public key the client already holds in
// /etc/apk/keys, identified by filename rather than by any identity inside the
// key. There is no certificate, no expiry, and no notion of a key signing
// itself: the file's presence is the entire trust decision.
//
// That is why this exists beside the OpenPGP signer rather than reusing it. The
// key material is the same kind of RSA, but everything wrapped around it is
// absent, and pretending otherwise would put an expiry into a format that has
// no way to honour it.
package apkrsa

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"crypto/pbkdf2"

	"github.com/shellcell/snailmail/signer"
)

const (
	keyBits = 4096

	// pbkdf2Iterations is deliberately expensive: the passphrase is the only
	// thing between a stolen key file and a signing oracle.
	pbkdf2Iterations = 600_000
	saltSize         = 16
	keySize          = 32

	privatePEMType = "SNAILMAIL ENCRYPTED APK PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
)

// Generated is a new key and the public forms that go with it.
type Generated struct {
	Identity signer.Identity
	// PublicBinary and PublicArmor are the same bytes. An apk key has exactly
	// one published form — the PEM file a client installs — and both fields
	// carry it so a caller written for two forms sees one consistent key rather
	// than two encodings that would each need their own digest and path.
	PublicBinary []byte
	PublicArmor  []byte
	// PrivateArmor is the encrypted private key, safe to write to disk.
	PrivateArmor []byte
}

// Generate creates a signing key and encrypts it under the passphrase.
//
// createdAt and expiresIn are recorded so the workspace can reason about a key
// the same way it does an OpenPGP one, and so rotation has dates to compare.
// apk itself enforces neither: a key stays trusted until it is removed from the
// client, which is a property of the format rather than a choice made here.
func Generate(createdAt time.Time, expiresIn time.Duration, passphrase []byte) (Generated, error) {
	if len(passphrase) < 24 {
		return Generated{}, errors.New("apk signing passphrase must be at least 24 bytes")
	}
	if createdAt.IsZero() || expiresIn <= 0 {
		return Generated{}, errors.New("apk signing key needs a creation time and a validity duration")
	}
	private, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return Generated{}, fmt.Errorf("generate apk signing key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return Generated{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return Generated{}, err
	}
	encrypted, err := encrypt(privateDER, passphrase)
	if err != nil {
		return Generated{}, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: publicDER})
	return Generated{
		Identity: signer.Identity{
			Fingerprint: Fingerprint(publicDER),
			Algorithm:   signer.AlgorithmAPKRSA4096,
			Bits:        keyBits,
			CreatedAt:   createdAt.UTC().Truncate(time.Second),
			ExpiresAt:   createdAt.UTC().Truncate(time.Second).Add(expiresIn),
		},
		PublicBinary: publicPEM,
		PublicArmor:  publicPEM,
		PrivateArmor: pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Bytes: encrypted}),
	}, nil
}

// Fingerprint identifies a key by its public bytes.
//
// Twenty bytes, to be the same shape as the OpenPGP fingerprints the workspace
// already records, taken from SHA-256 rather than SHA-1: this is an identifier
// and not a trust boundary — apk trusts the key file itself — but there is no
// reason to reach for a broken hash to produce one.
func Fingerprint(publicDER []byte) string {
	digest := sha256.Sum256(publicDER)
	return hex.EncodeToString(digest[:20])
}

// InspectPublic reads a PEM public key and reports what it is.
func InspectPublic(armored []byte) (signer.Identity, error) {
	block, _ := pem.Decode(armored)
	if block == nil || block.Type != publicPEMType {
		return signer.Identity{}, errors.New("invalid apk public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return signer.Identity{}, errors.New("invalid apk public key")
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != keyBits {
		return signer.Identity{}, fmt.Errorf("apk signing key must be a %d-bit RSA key", keyBits)
	}
	return signer.Identity{
		Fingerprint: Fingerprint(block.Bytes), Algorithm: signer.AlgorithmAPKRSA4096, Bits: keyBits,
	}, nil
}

// Local signs with a decrypted private key held in memory.
type Local struct {
	private      *rsa.PrivateKey
	identity     signer.Identity
	publicBinary []byte
	publicArmor  []byte
}

// Public returns the forms a workspace commits and a client installs.
func (local *Local) Public() (signer.Generated, error) {
	if local.private == nil {
		return signer.Generated{}, errors.New("apk signing key is closed")
	}
	return signer.Generated{
		Identity: local.identity, PublicBinary: local.publicBinary, PublicArmor: local.publicArmor,
	}, nil
}

// Open decrypts a stored private key.
func Open(privateArmor []byte, passphrase []byte, identity signer.Identity) (*Local, error) {
	block, _ := pem.Decode(privateArmor)
	if block == nil || block.Type != privatePEMType {
		return nil, errors.New("invalid apk private key")
	}
	privateDER, err := decrypt(block.Bytes, passphrase)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, errors.New("invalid apk private key")
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok || private.N.BitLen() != keyBits {
		return nil, fmt.Errorf("apk signing key must be a %d-bit RSA key", keyBits)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, err
	}
	if identity.Fingerprint != "" && identity.Fingerprint != Fingerprint(publicDER) {
		return nil, errors.New("apk private key does not match its recorded identity")
	}
	identity.Fingerprint = Fingerprint(publicDER)
	identity.Algorithm = signer.AlgorithmAPKRSA4096
	identity.Bits = keyBits
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: publicDER})
	return &Local{private: private, identity: identity, publicBinary: publicPEM, publicArmor: publicPEM}, nil
}

func (local *Local) Identity(context.Context) (signer.Identity, error) { return local.identity, nil }

// Sign produces the signature apk verifies: PKCS#1 v1.5 over a SHA-256 digest,
// which is what the .SIGN.RSA256 entry name declares.
func (local *Local) Sign(_ context.Context, request signer.Request) (signer.Response, error) {
	if request.Scheme != signer.SchemeAPKRSA256 {
		return signer.Response{}, fmt.Errorf("apk signer cannot produce scheme %q", request.Scheme)
	}
	if len(request.Payload) == 0 {
		return signer.Response{}, errors.New("apk signature payload is empty")
	}
	digest := sha256.Sum256(request.Payload)
	// PKCS#1 v1.5 is deterministic, which the plan relies on: the same payload
	// and key must produce the same bytes for a signature to be reviewable.
	signature, err := rsa.SignPKCS1v15(nil, local.private, crypto.SHA256, digest[:])
	if err != nil {
		return signer.Response{}, err
	}
	return signer.Response{
		Scheme: signer.SchemeAPKRSA256, Fingerprint: local.identity.Fingerprint, Content: signature,
	}, nil
}

func (local *Local) Close() error {
	local.private = nil
	return nil
}

// VerifyResponse checks a signature against the public key that will be
// published, so nothing unverifiable is ever written into a repository.
func VerifyResponse(request signer.Request, response signer.Response, publicDER []byte, expectedFingerprint string) error {
	if request.Scheme != response.Scheme || request.Scheme != signer.SchemeAPKRSA256 ||
		response.Fingerprint != expectedFingerprint || len(response.Content) == 0 {
		return errors.New("apk signature response does not match its request")
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return errors.New("invalid apk verification key")
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid apk verification key")
	}
	if Fingerprint(publicDER) != expectedFingerprint {
		return errors.New("apk verification key does not match the expected fingerprint")
	}
	digest := sha256.Sum256(request.Payload)
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], response.Content); err != nil {
		return errors.New("apk signature does not verify under the published key")
	}
	return nil
}

// encrypt wraps the private key under a passphrase-derived key.
func encrypt(plaintext, passphrase []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	block, err := newCipher(salt, passphrase)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, block.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := block.Seal(nil, nonce, plaintext, salt)
	return append(append(append([]byte(nil), salt...), nonce...), sealed...), nil
}

func decrypt(stored, passphrase []byte) ([]byte, error) {
	if len(stored) < saltSize+12 {
		return nil, errors.New("apk private key is truncated")
	}
	salt := stored[:saltSize]
	block, err := newCipher(salt, passphrase)
	if err != nil {
		return nil, err
	}
	nonceSize := block.NonceSize()
	if len(stored) < saltSize+nonceSize {
		return nil, errors.New("apk private key is truncated")
	}
	nonce := stored[saltSize : saltSize+nonceSize]
	plaintext, err := block.Open(nil, nonce, stored[saltSize+nonceSize:], salt)
	if err != nil {
		// The passphrase is wrong or the file was altered; which one is not
		// something to disclose.
		return nil, errors.New("apk private key could not be decrypted")
	}
	return plaintext, nil
}

func newCipher(salt, passphrase []byte) (cipher.AEAD, error) {
	derived, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
