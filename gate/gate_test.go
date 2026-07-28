package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	githubforge "github.com/shellcell/snailmail/adapters/forge/github"
	plainforge "github.com/shellcell/snailmail/adapters/forge/plain"
)

func TestApprovalEvidenceBindsPlanRepositoryAndExpiry(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "approvals.json")
	keyFile := filepath.Join(t.TempDir(), "approval-key.json")
	publicKey, err := GenerateApprovalKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC)
	approval, _, err := SignApproval(keyFile, strings.Repeat("a", 64), "python", now.Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	evidence := ApprovalFile{Approvals: []Approval{approval}}
	if err := WriteApprovals(filename, evidence); err != nil {
		t.Fatal(err)
	}
	evaluator := NewDefaultEvaluator(filename, nil)
	requirement := Requirement{Policy: "approval", PlanID: strings.Repeat("a", 64), Repository: "python", Now: now, ApprovalKeys: []string{publicKey}}
	if err := evaluator.Authorize(context.Background(), requirement); err != nil {
		t.Fatal(err)
	}
	tampered := evidence
	tampered.Approvals = append([]Approval(nil), evidence.Approvals...)
	tampered.Approvals[0].Approver = "ed25519:" + strings.Repeat("0", 64)
	if err := WriteApprovals(filename, tampered); err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(context.Background(), requirement); err == nil {
		t.Fatal("tampered approval signature was accepted")
	}
	if err := WriteApprovals(filename, evidence); err != nil {
		t.Fatal(err)
	}
	requirement.Repository = "debian"
	if err := evaluator.Authorize(context.Background(), requirement); err == nil {
		t.Fatal("approval was reused for another repository")
	}
	requirement.Repository = "python"
	requirement.Now = now.Add(2 * time.Hour)
	if err := evaluator.Authorize(context.Background(), requirement); err == nil {
		t.Fatal("expired approval was accepted")
	}
}

func TestPRGateRequiresMergedDefaultBranchReview(t *testing.T) {
	directory := t.TempDir()
	helper := filepath.Join(directory, "gh")
	script := `#!/bin/sh
case "$*" in
  *"/pulls")
  printf '%s\n' '[{"number":12,"title":"publish","merged_at":"2026-07-25T00:00:00Z","base":{"ref":"main","sha":"abc"}}]'
  exit 0
  ;;
  *"compare/"*)
  printf '%s\n' '{"status":"ahead","ahead_by":1,"merge_base_commit":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
  ;;
  *)
  printf '%s\n' '{"id":1,"full_name":"shellcell/state","default_branch":"main","html_url":"https://github.com/shellcell/state"}'
  ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	evaluator := NewDefaultEvaluator("", githubforge.NewResolver())
	if err := evaluator.Authorize(context.Background(), Requirement{
		Policy: "pr", GitRevision: strings.Repeat("b", 40), Root: directory, ForgeRepository: "shellcell/state",
	}); err != nil {
		t.Fatal(err)
	}
}

// A gate with no configured forge must refuse rather than pass: review evidence
// that cannot be read is unknown, and ARCHITECTURE §18 forbids collapsing
// unknown into success.
func TestPRGateRefusesWithoutAForge(t *testing.T) {
	evaluator := NewDefaultEvaluator("", nil)
	err := evaluator.Authorize(context.Background(), Requirement{
		Policy: "pr", GitRevision: strings.Repeat("b", 40), Root: t.TempDir(), ForgeRepository: "shellcell/state",
	})
	if err == nil {
		t.Fatal("a PR gate with no forge authorized publication")
	}
}

// A remote with no review API must refuse for the same reason.
func TestPRGateRefusesOnAForgeWithoutReviewAPI(t *testing.T) {
	evaluator := NewDefaultEvaluator("", plainforge.NewResolver())
	err := evaluator.Authorize(context.Background(), Requirement{
		Policy: "pr", GitRevision: strings.Repeat("b", 40), Root: t.TempDir(), ForgeRepository: "example/state",
	})
	if err == nil {
		t.Fatal("a PR gate against a plain remote authorized publication")
	}
}
