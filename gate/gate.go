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
	"os/exec"
	"path/filepath"
	"time"

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
}

func NewDefaultEvaluator(approvalFile string) *DefaultEvaluator {
	return &DefaultEvaluator{approvalFile: approvalFile}
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
	return verifyMergedPR(ctx, requirement.Root, requirement.ForgeRepository, requirement.GitRevision)
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

func verifyMergedPR(ctx context.Context, root, forgeRepository, revision string) error {
	if forgeRepository == "" {
		return errors.New("PR gate has no reviewed forge repository")
	}
	view := exec.CommandContext(ctx, "gh", "api", "--hostname", "github.com", "repos/"+forgeRepository)
	view.Dir = root
	output, err := view.Output()
	if err != nil {
		return errors.New("PR gate requires an authenticated GitHub repository")
	}
	var repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := decodeJSON(output, &repository); err != nil || repository.FullName != forgeRepository || repository.DefaultBranch == "" {
		return errors.New("PR gate could not identify the GitHub state repository")
	}
	request := exec.CommandContext(ctx, "gh", "api", "--hostname", "github.com", "-H", "Accept: application/vnd.github+json", "repos/"+forgeRepository+"/commits/"+revision+"/pulls")
	request.Dir = root
	output, err = request.Output()
	if err != nil {
		return errors.New("PR gate could not query review evidence")
	}
	var pullRequests []struct {
		Number   int     `json:"number"`
		MergedAt *string `json:"merged_at"`
		Base     struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := decodeJSON(output, &pullRequests); err != nil {
		return errors.New("PR gate received invalid review evidence")
	}
	for _, pullRequest := range pullRequests {
		if pullRequest.Number > 0 && pullRequest.MergedAt != nil && *pullRequest.MergedAt != "" && pullRequest.Base.Ref == repository.DefaultBranch {
			compare := exec.CommandContext(ctx, "gh", "api", "--hostname", "github.com", "repos/"+forgeRepository+"/compare/"+revision+"..."+repository.DefaultBranch)
			compare.Dir = root
			comparison, compareErr := compare.Output()
			var result struct {
				Status          string `json:"status"`
				MergeBaseCommit struct {
					SHA string `json:"sha"`
				} `json:"merge_base_commit"`
			}
			if compareErr == nil && decodeJSON(comparison, &result) == nil && (result.Status == "ahead" || result.Status == "identical") && result.MergeBaseCommit.SHA == revision {
				return nil
			}
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
