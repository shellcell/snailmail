package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shellcell/snailmail/forge"
	"github.com/shellcell/snailmail/internal/jsonstrict"
)

const ApprovalSchema = 1

type Requirement struct {
	Policy          string
	PlanID          string
	Repository      string
	GitRevision     string
	Root            string
	Now             time.Time
	ForgeRepository string
	ApprovalKeys    []string
}

type Evaluator interface {
	Authorize(context.Context, Requirement) error
}

type Approval struct {
	PlanID     string `json:"plan_id"`
	Repository string `json:"repository"`
	Approver   string `json:"approver"`
	ExpiresAt  string `json:"expires_at"`
	Signature  string `json:"signature"`
}

type ApprovalFile struct {
	SchemaVersion int        `json:"schema_version"`
	Approvals     []Approval `json:"approvals"`
}

type DefaultEvaluator struct {
	approvalFile string
	forges       forge.Resolver
}

// NewDefaultEvaluator builds an evaluator that reads merged-PR evidence through
// forges. A nil resolver refuses PR gates rather than allowing them.
func NewDefaultEvaluator(approvalFile string, forges forge.Resolver) *DefaultEvaluator {
	return &DefaultEvaluator{approvalFile: approvalFile, forges: forges}
}

func (evaluator *DefaultEvaluator) Authorize(ctx context.Context, requirement Requirement) error {
	switch requirement.Policy {
	case "auto":
		return nil
	case "pr":
		return evaluator.requireMergedPR(ctx, requirement)
	case "approval":
		return evaluator.requireApproval(requirement)
	default:
		return fmt.Errorf("unsupported publication gate %q", requirement.Policy)
	}
}

func (evaluator *DefaultEvaluator) requireApproval(requirement Requirement) error {
	if evaluator.approvalFile == "" {
		return errors.New("approval gate requires an approval evidence file")
	}
	evidence, err := LoadApprovals(evaluator.approvalFile)
	if err != nil {
		return fmt.Errorf("load approval evidence: %w", err)
	}
	for _, approval := range evidence.Approvals {
		if approval.PlanID != requirement.PlanID || approval.Repository != requirement.Repository || approval.Approver == "" {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, approval.ExpiresAt)
		if err == nil && requirement.Now.Before(expiresAt) && verifyApproval(approval, requirement.ApprovalKeys) {
			return nil
		}
	}
	return fmt.Errorf("repository %q lacks unexpired approval bound to plan %s", requirement.Repository, requirement.PlanID)
}

func (evaluator *DefaultEvaluator) requireMergedPR(ctx context.Context, requirement Requirement) error {
	return verifyMergedPR(ctx, evaluator.forges, requirement.Root, requirement.ForgeRepository, requirement.GitRevision)
}

type PrivateKeyFile struct {
	SchemaVersion int    `json:"schema_version"`
	PrivateKey    string `json:"private_key"`
}

func GenerateApprovalKey(filename string) (string, error) {
	if _, err := os.Lstat(filename); err == nil {
		return "", errors.New("refusing to overwrite approval private key")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	content, err := json.MarshalIndent(PrivateKeyFile{SchemaVersion: ApprovalSchema, PrivateKey: base64.StdEncoding.EncodeToString(privateKey)}, "", "  ")
	if err != nil {
		return "", err
	}
	content = append(content, '\n')
	if err := writePrivateFile(filename, content); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

func SignApproval(filename, planID, repository, expiresAt string) (Approval, string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return Approval{}, "", err
	}
	var keyFile PrivateKeyFile
	if err := jsonstrict.Decode(content, &keyFile, 1<<20); err != nil || keyFile.SchemaVersion != ApprovalSchema {
		return Approval{}, "", errors.New("invalid approval private key file")
	}
	decoded, err := base64.StdEncoding.DecodeString(keyFile.PrivateKey)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return Approval{}, "", errors.New("invalid approval private key")
	}
	privateKey := ed25519.PrivateKey(decoded)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	approval := Approval{
		PlanID: planID, Repository: repository, Approver: approvalKeyID(publicKey), ExpiresAt: expiresAt,
	}
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, approvalMessage(approval)))
	clear(decoded)
	return approval, base64.StdEncoding.EncodeToString(publicKey), nil
}

func verifyApproval(approval Approval, allowedKeys []string) bool {
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	for _, encoded := range allowedKeys {
		publicKey, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && len(publicKey) == ed25519.PublicKeySize && approval.Approver == approvalKeyID(publicKey) && ed25519.Verify(publicKey, approvalMessage(approval), signature) {
			return true
		}
	}
	return false
}

func approvalMessage(approval Approval) []byte {
	return []byte("snailmail-approval/v1\x00" + approval.PlanID + "\x00" + approval.Repository + "\x00" + approval.Approver + "\x00" + approval.ExpiresAt)
}

func approvalKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return fmt.Sprintf("ed25519:%x", digest[:])
}

// verifyMergedPR proves that a revision reached the default branch through a
// merged pull request. Every failure to read review state is a refusal:
// ARCHITECTURE §18 requires an unavailable provider to render unknown and never
// silently authorize.
func verifyMergedPR(ctx context.Context, forges forge.Resolver, root, forgeRepository, revision string) error {
	if forgeRepository == "" {
		return errors.New("PR gate has no reviewed forge repository")
	}
	if forges == nil {
		return errors.New("PR gate has no configured forge")
	}
	target := forge.Repository{Name: forgeRepository, WorkingDirectory: root}
	provider, err := forges.Resolve(ctx, target)
	if err != nil {
		return fmt.Errorf("PR gate could not select a forge: %w", err)
	}
	repository, err := provider.Repository(ctx, target)
	if err != nil {
		return errors.New("PR gate could not identify the state repository")
	}
	pullRequests, err := provider.PullRequestsForRevision(ctx, target, revision)
	if err != nil {
		return errors.New("PR gate could not query review evidence")
	}
	for _, pullRequest := range pullRequests {
		if pullRequest.Number <= 0 || !pullRequest.Merged || pullRequest.BaseBranch != repository.DefaultBranch {
			continue
		}
		// A merged pull request is not enough on its own: the revision must
		// still be reachable from the default branch, so a later force-push
		// cannot leave stale review evidence standing.
		ancestry, err := provider.RevisionAncestry(ctx, target, revision, repository.DefaultBranch)
		if err == nil && ancestry.Contains && ancestry.MergeBase == revision {
			return nil
		}
	}
	return fmt.Errorf("Git revision %s was not merged through a PR into %s", revision, repository.DefaultBranch)
}

func LoadApprovals(filename string) (ApprovalFile, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return ApprovalFile{}, err
	}
	var evidence ApprovalFile
	if err := jsonstrict.Decode(content, &evidence, 1<<20); err != nil {
		return ApprovalFile{}, err
	}
	if evidence.SchemaVersion != ApprovalSchema {
		return ApprovalFile{}, errors.New("unsupported approval evidence schema")
	}
	return evidence, nil
}

func WriteApprovals(filename string, evidence ApprovalFile) error {
	evidence.SchemaVersion = ApprovalSchema
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writePrivateFile(filename, encoded)
}

func writePrivateFile(filename string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".snailmail-approval-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}

func decodeJSON(content []byte, destination any) error {
	return jsonstrict.DecodeAllowUnknown(content, destination, 1<<20)
}
