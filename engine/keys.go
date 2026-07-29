package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/knowledge"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
	apkrsa "github.com/shellcell/snailmail/signer/apkrsa"
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
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
	Reference   string `json:"reference"`
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
	Findings  []KeyAuditFinding   `json:"findings"`
	Rotations []KeyRotationStatus `json:"rotations"`
}

type KeyRotationStatus struct {
	Repository      string
	Phase           string
	Deployed        bool
	Ready           bool
	EarliestAdvance string
}

type preparedSigningKey struct {
	key            state.SigningKey
	generated      signer.Generated
	createdPrivate bool
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
	if request.Algorithm != signer.AlgorithmOpenPGPRSA4096 && request.Algorithm != signer.AlgorithmAPKRSA4096 {
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
	prepared, err := prepareSigningKey(ctx, manifest, request.Name, signer.Algorithm(request.Algorithm), request.CreatedAt, request.ExpiresIn, request.Keys)
	if err != nil {
		return NewKeyResult{}, err
	}
	rollback, err := persistPreparedSigningKey(root, prepared)
	if err != nil {
		if prepared.createdPrivate {
			_ = request.Keys.Delete(context.WithoutCancel(ctx), signer.Ref{Backend: prepared.key.Ref.Backend, ID: prepared.key.Ref.ID})
		}
		return NewKeyResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollback()
			if prepared.createdPrivate {
				_ = request.Keys.Delete(context.WithoutCancel(ctx), signer.Ref{Backend: prepared.key.Ref.Backend, ID: prepared.key.Ref.ID})
			}
		}
	}()
	manifest.Keys[request.Name] = prepared.key
	if err := state.WriteManifest(root, manifest); err != nil {
		committed = manifestMatches(root, manifest)
		return NewKeyResult{}, err
	}
	committed = true
	return keyResult(request.Name, prepared.key), nil
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
	usedKeys := make(map[string]bool)
	for _, repository := range manifest.Repositories {
		_, trusted, _, _, _ := repositorySigningState(repository)
		for _, name := range trusted {
			usedKeys[name] = true
		}
	}
	var findings []KeyAuditFinding
	var rotationAuthorityErr error
	for _, repository := range manifest.Repositories {
		if repository.SigningRotation != nil {
			_, rotationAuthorityErr = state.RequireCleanGit(root)
			break
		}
	}
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
		case !now.Before(expiresAt) && usedKeys[name]:
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "key/" + name, Message: "active or trusted signing key has expired"})
		case !now.Before(expiresAt):
			findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "key/" + name, Message: "unused historical signing key has expired"})
		case usedKeys[name] && expiresAt.Sub(now) < 30*24*time.Hour:
			findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "key/" + name, Message: "signing key expires in less than 30 days"})
		}
	}
	var rotations []KeyRotationStatus
	for _, name := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[name]
		if repository.Format == "deb" && len(repository.SigningKeys) == 0 {
			findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: "Debian repository is unsigned"})
			continue
		}
		_, trustedKeys, _, _, _ := repositorySigningState(repository)
		for _, signingKey := range trustedKeys {
			key := manifest.Keys[signingKey]
			if !knowledge.Compatible(repository.Format, key.Algorithm) {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: "signing algorithm is incompatible with repository format"})
			}
		}
		if repository.SigningRotation != nil {
			status := KeyRotationStatus{Repository: name, Phase: repository.SigningRotation.Phase}
			if validityErr := validateRotationKeyValidity(repository, manifest.Keys, now); validityErr != nil {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: validityErr.Error()})
			}
			if rotationAuthorityErr != nil {
				findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "repo/" + name, Message: "rotation readiness is unavailable until authoritative state is committed"})
				rotations = append(rotations, status)
				continue
			}
			deployment, err := state.LoadDeployment(root, name)
			if err != nil {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: err.Error()})
			} else if desired, desiredErr := repositoryDeploymentSigningState(repository, manifest.Keys); desiredErr != nil {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: desiredErr.Error()})
			} else if !deploymentSigningMatches(deployment, desired) {
				findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "repo/" + name, Message: "rotation state has not been successfully deployed"})
			} else if trustSince, authorityErr := state.AuthoritativeDeploymentTrustSince(root, name, deployment); authorityErr != nil {
				findings = append(findings, KeyAuditFinding{Severity: "error", Subject: "repo/" + name, Message: authorityErr.Error()})
			} else {
				status.Deployed = true
				earliest := trustSince.Add(time.Duration(deployment.SigningMinimumRefreshSeconds) * time.Second)
				status.EarliestAdvance = earliest.UTC().Format(time.RFC3339)
				status.Ready = !now.Before(earliest)
				if status.Ready {
					findings = append(findings, KeyAuditFinding{Severity: "warning", Subject: "repo/" + name, Message: "rotation is ready to advance"})
				}
			}
			rotations = append(rotations, status)
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
	return KeyAuditResult{Findings: findings, Rotations: rotations}, nil
}

func signingKeyFromGenerated(name string, ref signer.Ref, generated signer.Generated) (state.SigningKey, error) {
	if (generated.Identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 && generated.Identity.Algorithm != signer.AlgorithmAPKRSA4096) || generated.Identity.Bits != 4096 || generated.Identity.Fingerprint == "" || generated.Identity.CreatedAt.IsZero() || !generated.Identity.ExpiresAt.After(generated.Identity.CreatedAt) {
		return state.SigningKey{}, errors.New("generated signing identity is invalid")
	}
	if generated.Identity.Algorithm == signer.AlgorithmAPKRSA4096 {
		// An apk key has one published form and it carries no dates, so only
		// what the file actually attests to is compared.
		armorIdentity, err := apkrsa.InspectPublic(generated.PublicArmor)
		if err != nil || armorIdentity.Fingerprint != generated.Identity.Fingerprint ||
			armorIdentity.Algorithm != generated.Identity.Algorithm || armorIdentity.Bits != generated.Identity.Bits {
			return state.SigningKey{}, errors.New("generated apk public key does not match its identity")
		}
		// One published form, so the two recorded forms must be the same bytes.
		if !bytes.Equal(generated.PublicBinary, generated.PublicArmor) {
			return state.SigningKey{}, errors.New("apk public forms differ")
		}
	} else {
		binaryIdentity, err := openpgpsigner.InspectPublic(generated.PublicBinary)
		if err != nil || binaryIdentity != generated.Identity {
			return state.SigningKey{}, errors.New("generated binary public key does not match its identity")
		}
		armorIdentity, err := openpgpsigner.InspectArmoredPublic(generated.PublicArmor)
		if err != nil || armorIdentity != generated.Identity {
			return state.SigningKey{}, errors.New("generated armored public key does not match its identity")
		}
	}
	binaryDigest := sha256.Sum256(generated.PublicBinary)
	armorDigest := sha256.Sum256(generated.PublicArmor)
	return state.SigningKey{
		Algorithm: generated.Identity.Algorithm, Usage: "sign", Fingerprint: generated.Identity.Fingerprint,
		CreatedAt: generated.Identity.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: generated.Identity.ExpiresAt.UTC().Format(time.RFC3339),
		PublicKeyPath: publicKeyPath(name, generated.Identity.Algorithm), PublicKeySHA256: hex.EncodeToString(binaryDigest[:]),
		PublicArmorPath: publicArmorPath(name, generated.Identity.Algorithm), PublicArmorSHA256: hex.EncodeToString(armorDigest[:]),
		Ref: state.KeyRef{Backend: ref.Backend, ID: ref.ID},
	}, nil
}

// publicKeyPath and publicArmorPath name the committed public forms. An apk key
// has one form rather than two, and the name it is published under is what a
// client will hold in /etc/apk/keys, so it carries apk's own convention.
func publicKeyPath(name, algorithm string) string {
	if algorithm == signer.AlgorithmAPKRSA4096 {
		return "keys/" + name + ".rsa.pub"
	}
	return "keys/" + name + ".gpg"
}

func publicArmorPath(name, algorithm string) string {
	if algorithm == signer.AlgorithmAPKRSA4096 {
		return "keys/" + name + ".rsa.pub"
	}
	return "keys/" + name + ".asc"
}

func prepareSigningKey(ctx context.Context, manifest state.Manifest, name string, algorithm signer.Algorithm, createdAt time.Time, expiresIn time.Duration, keys signer.Generator) (preparedSigningKey, error) {
	ref := signer.Ref{Backend: "file", ID: manifest.Workspace.ID + "/" + name}
	generated, err := keys.Public(ctx, ref)
	createdPrivate := false
	if errors.Is(err, signer.ErrNotFound) {
		generated, err = keys.Generate(ctx, ref, algorithm, name, createdAt, expiresIn)
		createdPrivate = err == nil
	}
	if err != nil {
		return preparedSigningKey{}, err
	}
	key, err := signingKeyFromGenerated(name, ref, generated)
	if err != nil {
		if createdPrivate {
			_ = keys.Delete(context.WithoutCancel(ctx), ref)
		}
		return preparedSigningKey{}, err
	}
	return preparedSigningKey{key: key, generated: generated, createdPrivate: createdPrivate}, nil
}

func persistPreparedSigningKey(root string, prepared preparedSigningKey) (func(), error) {
	var created []string
	for _, relative := range []string{prepared.key.PublicKeyPath, prepared.key.PublicArmorPath} {
		name, err := state.WorkspacePath(root, relative)
		if err != nil {
			return func() {}, err
		}
		if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
			created = append(created, name)
		} else if err != nil {
			return func() {}, err
		}
	}
	rollback := func() {
		for _, name := range created {
			_ = os.Remove(name)
		}
	}
	if err := state.WriteSigningPublic(root, prepared.key, prepared.generated.PublicBinary, prepared.generated.PublicArmor); err != nil {
		rollback()
		return func() {}, err
	}
	return rollback, nil
}

func keyResult(name string, key state.SigningKey) NewKeyResult {
	return NewKeyResult{Name: name, Fingerprint: key.Fingerprint, ExpiresAt: key.ExpiresAt, Reference: key.Ref.ID}
}

func manifestMatches(root string, expected state.Manifest) bool {
	actual, err := state.LoadManifest(root)
	return err == nil && reflect.DeepEqual(actual, expected)
}

func sortedSigningKeyNames(keys map[string]state.SigningKey) []string {
	names := make([]string, 0, len(keys))
	for name := range keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type AttachKeyRequest struct {
	Root       string
	Repository string
	Key        string
}

type AttachKeyResult struct {
	Repository  string `json:"repository"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Keyring     string `json:"keyring"`
}

// AttachKey signs a repository that was configured without a key.
//
// Starting unsigned and adding signing once a key exists is the ordinary
// adoption path, and it had no command: setup only creates repositories, and
// rotate needs a current key to replace, so an unsigned repository could never
// become signed except by editing the manifest by hand.
//
// Replacing a key that is already in use is deliberately not this operation.
// Clients trust what they have already fetched, so a live key changes through
// rotation, which serves both keys for an overlap before retiring the old one.
func AttachKey(request AttachKeyRequest) (AttachKeyResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return AttachKeyResult{}, err
	}
	if err := state.RequireGitRepository(root); err != nil {
		return AttachKeyResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return AttachKeyResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return AttachKeyResult{}, err
	}
	repository, exists := manifest.Repositories[request.Repository]
	if !exists {
		return AttachKeyResult{}, fmt.Errorf("repository %q is not configured", request.Repository)
	}
	key, exists := manifest.Keys[request.Key]
	if !exists {
		return AttachKeyResult{}, fmt.Errorf("unknown signing key %q", request.Key)
	}
	selected, err := formats.For(repository.Format)
	if err != nil {
		return AttachKeyResult{}, err
	}
	if !selected.ImplementsSigning() {
		return AttachKeyResult{}, fmt.Errorf("snailmail does not produce repository signatures for format %q", repository.Format)
	}
	if len(repository.SigningKeys) != 0 {
		return AttachKeyResult{}, fmt.Errorf(
			"repository %q is already signed by %s; use `snailmail keys rotate` so clients keep trusting it through the change",
			request.Repository, strings.Join(repository.SigningKeys, ", "))
	}
	if key.PublicKeyPath == "" {
		return AttachKeyResult{}, fmt.Errorf("signing key %q has no published public form; run `snailmail keys publish %s` first", request.Key, request.Key)
	}
	// The keyring is what a client installs, so it is derived from the key the
	// workspace already recorded rather than asked for a second time.
	repository.SigningKeys = []string{request.Key}
	repository.SigningKeyring = key.PublicKeyPath
	manifest.Repositories[request.Repository] = repository
	if err := state.WriteManifest(root, manifest); err != nil {
		return AttachKeyResult{}, err
	}
	return AttachKeyResult{
		Repository: request.Repository, Key: request.Key,
		Fingerprint: key.Fingerprint, Keyring: key.PublicKeyPath,
	}, nil
}
