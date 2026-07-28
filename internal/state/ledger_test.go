package state

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLedgerRejectsUnknownAndInvalidRecords(t *testing.T) {
	valid := `{"schema_version":1,"plan_id":"` + strings.Repeat("a", 64) + `","change_id":"python:` + strings.Repeat("b", 12) + `","repository":"python","package":"demo","version":"1.2.3","blob_sha256":["` + strings.Repeat("c", 64) + `"],"tree_sha256":"` + strings.Repeat("b", 64) + `","recorded_at":"2026-07-26T12:00:00Z"}`
	records, err := parseLedger(strings.NewReader(valid + "\n"))
	if err != nil || len(records) != 1 {
		t.Fatalf("valid ledger records=%#v err=%v", records, err)
	}
	if err := ValidatePublicationHistory("python", records); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicationHistory("other", records); err == nil {
		t.Fatal("publication history accepted the wrong repository")
	}
	unknown := strings.TrimSuffix(valid, "}") + `,"unexpected":true}`
	if _, err := parseLedger(strings.NewReader(unknown + "\n")); err == nil {
		t.Fatal("publication ledger accepted an unknown field")
	}
	invalidTimestamp := strings.Replace(valid, "2026-07-26T12:00:00Z", "later", 1)
	if _, err := parseLedger(strings.NewReader(invalidTimestamp + "\n")); err == nil {
		t.Fatal("publication ledger accepted an invalid timestamp")
	}
}

func TestLoadLedgerHistoryRejectsMutationAndRemoval(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string, string, string) error
	}{
		{name: "mutation", mutate: func(_, name, content string) error {
			return os.WriteFile(name, []byte(strings.Replace(content, "12:00:00Z", "12:00:01Z", 1)), 0o644)
		}},
		{name: "removal", mutate: func(_, name, _ string) error { return os.Remove(name) }},
		{name: "historical duplicate", mutate: func(root, name, content string) error {
			if err := os.WriteFile(name, []byte(content+content), 0o644); err != nil {
				return err
			}
			if output, err := exec.Command("git", "-C", root, "add", "publications/python.jsonl").CombinedOutput(); err != nil {
				return fmt.Errorf("git add duplicate: %w: %s", err, output)
			}
			if output, err := exec.Command("git", "-C", root, "-c", "user.name=Snailmail", "-c", "user.email=snailmail@example.invalid", "commit", "-m", "duplicate").CombinedOutput(); err != nil {
				return fmt.Errorf("git commit duplicate: %w: %s", err, output)
			}
			return os.WriteFile(name, []byte(content), 0o644)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if output, err := exec.Command("git", "init", "-b", "main", root).CombinedOutput(); err != nil {
				t.Fatalf("git init: %v: %s", err, output)
			}
			directory := filepath.Join(root, "publications")
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			content := `{"schema_version":1,"plan_id":"` + strings.Repeat("a", 64) + `","change_id":"python:` + strings.Repeat("b", 12) + `","repository":"python","package":"demo","version":"1.2.3","blob_sha256":["` + strings.Repeat("c", 64) + `"],"tree_sha256":"` + strings.Repeat("b", 64) + `","recorded_at":"2026-07-26T12:00:00Z"}` + "\n"
			name := filepath.Join(directory, "python.jsonl")
			if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("git", "-C", root, "add", "publications/python.jsonl")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git add: %v: %s", err, output)
			}
			command = exec.Command("git", "-C", root, "-c", "user.name=Snailmail", "-c", "user.email=snailmail@example.invalid", "commit", "-m", "publish")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git commit: %v: %s", err, output)
			}
			if err := test.mutate(root, name, content); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadLedgerHistory(root, "python"); err == nil {
				t.Fatal("immutable publication history change was accepted")
			}
		})
	}
}

func TestPublicationRecordIdentityIncludesAuditFields(t *testing.T) {
	record := PublicationRecord{
		Repository: "python", PlanID: strings.Repeat("a", 64), ChangeID: "python:" + strings.Repeat("b", 12),
		Package: "demo", Version: "1.2.3", BlobSHA256: []string{strings.Repeat("c", 64)},
		TreeSHA256: strings.Repeat("b", 64), RecordedAt: "2026-07-26T12:00:00Z",
	}
	changed := record
	changed.RecordedAt = "2026-07-26T12:00:01Z"
	if recordIdentity(record) == recordIdentity(changed) {
		t.Fatal("publication identity ignored its audit timestamp")
	}
}

// recordIdentity distinguishes two records by every field a ledger line
// carries; it exists for these assertions, not for production use.
func recordIdentity(record PublicationRecord) string {
	return record.Repository + "\x00" + record.PlanID + "\x00" + record.ChangeID + "\x00" + record.Package + "\x00" + record.Version + "\x00" + strings.Join(record.BlobSHA256, ",") + "\x00" + record.TreeSHA256 + "\x00" + record.RecordedAt
}
