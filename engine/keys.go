package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/shellcell/snailmail/internal/knowledge"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

type NewKeyRequest struct {
	Root      string
	Name      string
	Algorithm string
	CreatedAt time.Time
	ExpiresIn time.Duration
	Keys      signer.Generator
}

type NewKeyResult struct {
	Name        string
	Fingerprint string
	ExpiresAt   string
	Reference   string
}

type PublishKeyRequest struct {
	Root string
	Name string
	Keys signer.Generator
}

type KeyAuditFinding struct {
	Severity string
	Subject  string
	Message  string
}

type KeyAuditResult struct {
	Findings []KeyAuditFinding
}

func NewKey(ctx context.Context, request NewKeyRequest) (NewKeyResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return NewKeyResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return NewKeyResult{}, err
	}
	if err := state.ValidateRepositoryName(request.Name); err != nil {
		return NewKeyResult{}, fmt.Errorf("key name: %w", err)
	}
	if request.Algorithm == "" {
		request.Algorithm = signer.AlgorithmOpenPGPRSA4096
	}
	if request.Algorithm != signer.AlgorithmOpenPGPRSA4096 {
		return NewKeyResult{}, fmt.Errorf("unsupported signing algorithm %q", request.Algorithm)
	}
	if request.Keys == nil {
		return NewKeyResult{}, errors.New("signing key generator is required")
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now().UTC().Truncate(time.Second)
	}
	if request.ExpiresIn == 0 {
		request.ExpiresIn = 2 * 365 * 24 * time.Hour
	}
	if request.ExpiresIn < 24*time.Hour || request.ExpiresIn > 20*365*24*time.Hour {
		return NewKeyResult{}, errors.New("signing key expiry must be between one day and twenty years")
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return NewKeyResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return NewKeyResult{}, err
	}
	if _, exists := manifest.Keys[request.Name]; exists {
		return NewKeyResult{}, fmt.Errorf("signing key %q already exists", request.Name)
	}
	ref := signer.Ref{Backend: "file", ID: manifest.Workspace.ID + "/" + request.Name}
	generated, err := request.Keys.Public(ctx, ref)
	createdPrivate := false
	if errors.Is(err, signer.ErrNotFound) {
		generated, err = request.Keys.Generate(ctx, ref, request.Name, request.CreatedAt, request.ExpiresIn)
		createdPrivate = err == nil
	}
	if err != nil {
		return NewKeyResult{}, err
	}
	key, err := signingKeyFromGenerated(request.Name, ref, generated)
	if err != nil {
		if createdPrivate {
			_ = request.Keys.Delete(context.WithoutCancel(ctx), ref)
		}
		return NewKeyResult{}, err
	}
	if err := state.WriteSigningPublic(root, key, generated.PublicBinary, generated.PublicArmor); err != nil {
		return NewKeyResult{}, err
	}
	manifest.Keys[request.Name] = key
	if err := state.WriteManifest(root, manifest); err != nil {
		return NewKeyResult{}, err
	}
	return NewKeyResult{Name: request.Name, Fingerprint: key.Fingerprint, ExpiresAt: key.ExpiresAt, Reference: key.Ref.ID}, nil
}

func PublishKey(ctx context.Context, request PublishKeyRequest) (NewKeyResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return NewKeyResult{}, err
	}
	if request.Keys == nil {
		return NewKeyResult{}, errors.New("signing key backend is required")
	}
	if err := state.RequireGitRepository(root); err != nil {
		return NewKeyResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return NewKeyResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return NewKeyResult{}, err
	}
	key, exists := manifest.Keys[request.Name]
	if !exists {
		return NewKeyResult{}, fmt.Errorf("unknown signing key %q", request.Name)
	}
	generated, err := request.Keys.Public(ctx, signer.Ref{Backend: key.Ref.Backend, ID: key.Ref.ID})
	if err != nil {
		return NewKeyResult{}, err
	}
	expected, err := signingKeyFromGenerated(request.Name, signer.Ref{Backend: key.Ref.Backend, ID: key.Ref.ID}, generated)
	if err != nil {
		return NewKeyResult{}, err
	}
	if expected != key {
		return NewKeyResult{}, errors.New("private signing key identity differs from the workspace manifest")
	}
	if err := state.WriteSigningPublic(root, key, generated.PublicBinary, generated.PublicArmor); err != nil {
		return NewKeyResult{}, err
	}
	return NewKeyResult{Name: request.Name, Fingerprint: key.Fingerprint, ExpiresAt: key.ExpiresAt, Reference: key.Ref.ID}, nil
}

func AuditKeys(request PublishKeyRequest, now time.Time) (KeyAuditResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return KeyAuditResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return KeyAuditResult{}, err
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return KeyAuditResult{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var findings []KeyAuditFinding
	for _, name := range sortedSigningKeyNames(manifest.Keys) {
		key := manifest.Keys[name]
		binary, armored, loadErr := state.LoadSigningPublic(root, key)
		if loadErr != nil {
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "key/" + name, Message: loadErr.Error()})
			continue
		}
		binaryIdentity, binaryErr := openpgpsigner.InspectPublic(binary)
		armoredIdentity, armoredErr := openpgpsigner.InspectArmoredPublic(armored)
		if binaryErr != nil || armoredErr != nil || binaryIdentity != armoredIdentity || !identityMatchesState(binaryIdentity, key) {
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "key/" + name, Message: "public forms do not match the configured signing identity"})
			continue
		}
		expiresAt, _ := time.Parse(time.RFC3339, key.ExpiresAt)
		switch {
		case !now.Before(expiresAt):
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "key/" + name, Message: "signing key has expired"})
		case expiresAt.Sub(now) < 30*24*time.Hour:
			findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "key/" + name, Message: "signing key expires in less than 30 days"})
		}
	}
	for _, name := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[name]
		if repository.Format == "deb" && len(repository.SigningKeys) == 0 {
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: "Debian repository is unsigned"})
			continue
		}
		for _, signingKey := range repository.SigningKeys {
			key := manifest.Keys[signingKey]
			if !knowledge.Compatible(repository.Format, key.Algorithm) {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: "signing algorithm is incompatible with repository format"})
			}
		}
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Severity != findings[right].Severity {
			return findings[left].Severity < findings[right].Severity
		}
		if findings[left].Subject != findings[right].Subject {
			return findings[left].Subject < findings[right].Subject
		}
		return findings[left].Message < findings[right].Message
	})
	return KeyAuditResult{Findings: findings}, nil
}

func signingKeyFromGenerated(name string, ref signer.Ref, generated signer.Generated) (state.SigningKey, error) {
	if generated.Identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 || generated.Identity.Bits != 4096 || generated.Identity.Fingerprint == "" || generated.Identity.CreatedAt.IsZero() || !generated.Identity.ExpiresAt.After(generated.Identity.CreatedAt) {
		return state.SigningKey{}, errors.New("generated signing identity is invalid")
	}
	binaryIdentity, err := openpgpsigner.InspectPublic(generated.PublicBinary)
	if err != nil || binaryIdentity != generated.Identity {
		return state.SigningKey{}, errors.New("generated binary public key does not match its identity")
	}
	armorIdentity, err := openpgpsigner.InspectArmoredPublic(generated.PublicArmor)
	if err != nil || armorIdentity != generated.Identity {
		return state.SigningKey{}, errors.New("generated armored public key does not match its identity")
	}
	binaryDigest := sha256.Sum256(generated.PublicBinary)
	armorDigest := sha256.Sum256(generated.PublicArmor)
	return state.SigningKey{
		Algorithm: generated.Identity.Algorithm, Usage: "sign", Fingerprint: generated.Identity.Fingerprint,
		CreatedAt: generated.Identity.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: generated.Identity.ExpiresAt.UTC().Format(time.RFC3339),
		PublicKeyPath: "keys/" + name + ".gpg", PublicKeySHA256: hex.EncodeToString(binaryDigest[:]),
		PublicArmorPath: "keys/" + name + ".asc", PublicArmorSHA256: hex.EncodeToString(armorDigest[:]),
		Ref: state.KeyRef{Backend: ref.Backend, ID: ref.ID},
	}, nil
}

func sortedSigningKeyNames(keys map[string]state.SigningKey) []string {
	names := make([]string, 0, len(keys))
	for name := range keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
