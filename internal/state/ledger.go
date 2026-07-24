package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func LoadLedger(root, repository string) ([]PublicationRecord, error) {
	name, err := ledgerPath(root, repository)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseLedger(file)
}

func LoadLedgerHistory(root, repository string) ([]PublicationRecord, error) {
	records, err := LoadLedger(root, repository)
	if err != nil {
		return nil, err
	}
	relative := filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))
	treePath, err := workspaceGitPath(root, relative)
	if err != nil {
		return nil, err
	}
	output, err := gitOutput(root, "log", "--all", "--format=%H", "--diff-filter=AM", "--", ":(top,literal)"+treePath)
	if err != nil {
		return nil, fmt.Errorf("read publication history: %w", err)
	}
	seen := make(map[string]bool)
	for _, record := range records {
		seen[recordIdentity(record)] = true
	}
	for _, revision := range strings.Fields(output) {
		content, err := execGitShow(root, revision, treePath)
		if err != nil {
			return nil, fmt.Errorf("read publication ledger at %s: %w", revision, err)
		}
		historical, err := parseLedger(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		for _, record := range historical {
			if !seen[recordIdentity(record)] {
				records = append(records, record)
				seen[recordIdentity(record)] = true
			}
		}
	}
	return records, nil
}

func parseLedger(reader io.Reader) ([]PublicationRecord, error) {
	var records []PublicationRecord
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var record PublicationRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode publication ledger: %w", err)
		}
		if record.SchemaVersion != LedgerSchema {
			return nil, fmt.Errorf("unsupported publication ledger schema")
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func recordIdentity(record PublicationRecord) string {
	return record.PlanID + "\x00" + record.ChangeID + "\x00" + record.Package + "\x00" + record.Version + "\x00" + strings.Join(record.BlobSHA256, ",")
}

func execGitShow(root, revision, treePath string) ([]byte, error) {
	return gitCommand(root, "show", revision+":"+treePath).Output()
}

func ValidatePublishedBindings(lock RepositoryLock, records []PublicationRecord) error {
	bindings := make(map[string][]string)
	for _, record := range records {
		key := record.Package + "\x00" + record.Version
		digests := append([]string(nil), record.BlobSHA256...)
		sort.Strings(digests)
		if existing := bindings[key]; existing != nil && !equalStrings(existing, digests) {
			return fmt.Errorf("publication ledger has conflicting binding for %s@%s", record.Package, record.Version)
		}
		bindings[key] = digests
	}
	lockBindings := make(map[string][]string)
	for _, packageVersion := range lock.PackageVersion {
		key := packageVersion.Package + "\x00" + packageVersion.Version
		lockBindings[key] = blobDigests(packageVersion)
		published := bindings[key]
		if published == nil {
			continue
		}
		current := blobDigests(packageVersion)
		if !equalStrings(published, current) {
			return fmt.Errorf("published package %s@%s cannot change bytes", packageVersion.Package, packageVersion.Version)
		}
	}
	for key := range bindings {
		if lockBindings[key] == nil {
			parts := strings.SplitN(key, "\x00", 2)
			return fmt.Errorf("published package %s@%s cannot be removed from the lock", parts[0], parts[1])
		}
	}
	return nil
}

func AppendPublicationRecords(root, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) error {
	existing, err := LoadLedger(root, repository)
	if err != nil {
		return err
	}
	records, err := updatedPublicationRecords(existing, repository, planID, changeID, treeSHA, recordedAt, lock)
	if err != nil {
		return err
	}
	content, err := encodeLedger(records)
	if err != nil {
		return err
	}
	name, err := ledgerPath(root, repository)
	if err != nil {
		return err
	}
	return atomicWrite(name, content, 0o644)
}

// PreparePublicationRecords accepts only the reviewed base ledger or the exact
// already-prepared retry bytes, avoiding mutation when unrelated records exist.
func PreparePublicationRecords(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) error {
	expectedContent, err := expectedPublicationLedger(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt, lock)
	if err != nil {
		return err
	}
	baseContent, err := publicationLedgerAtRevision(root, baseRevision, repository)
	if err != nil {
		return err
	}
	name, err := ledgerPath(root, repository)
	if err != nil {
		return err
	}
	actualContent, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		actualContent = nil
	} else if err != nil {
		return err
	}
	if bytes.Equal(actualContent, expectedContent) {
		return nil
	}
	if !bytes.Equal(actualContent, baseContent) {
		return fmt.Errorf("publication ledger %q differs from the reviewed base", repository)
	}
	return atomicWrite(name, expectedContent, 0o644)
}

func ValidatePreparedPublicationLedger(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) error {
	expectedContent, err := expectedPublicationLedger(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt, lock)
	if err != nil {
		return err
	}
	name, err := ledgerPath(root, repository)
	if err != nil {
		return err
	}
	actualContent, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	return comparePublicationLedger(repository, expectedContent, actualContent)
}

func ValidateCommittedPublicationLedger(root, baseRevision, committedRevision, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) error {
	expectedContent, err := expectedPublicationLedger(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt, lock)
	if err != nil {
		return err
	}
	relative := filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))
	treePath, err := workspaceGitPath(root, relative)
	if err != nil {
		return err
	}
	actualContent, err := execGitShow(root, committedRevision, treePath)
	if err != nil {
		return fmt.Errorf("read committed publication ledger %q: %w", repository, err)
	}
	return comparePublicationLedger(repository, expectedContent, actualContent)
}

func expectedPublicationLedger(root, baseRevision, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) ([]byte, error) {
	content, err := publicationLedgerAtRevision(root, baseRevision, repository)
	if err != nil {
		return nil, err
	}
	var baseRecords []PublicationRecord
	if len(content) != 0 {
		baseRecords, err = parseLedger(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
	}
	expected, err := updatedPublicationRecords(baseRecords, repository, planID, changeID, treeSHA, recordedAt, lock)
	if err != nil {
		return nil, err
	}
	return encodeLedger(expected)
}

func publicationLedgerAtRevision(root, revision, repository string) ([]byte, error) {
	relative := filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))
	treePath, err := workspaceGitPath(root, relative)
	if err != nil {
		return nil, err
	}
	listed, err := gitOutput(root, "ls-tree", "--name-only", "--full-tree", revision, "--", ":(top,literal)"+treePath)
	if err != nil {
		return nil, err
	}
	if listed == "" {
		return nil, nil
	}
	return execGitShow(root, revision, treePath)
}

func comparePublicationLedger(repository string, expectedContent, actualContent []byte) error {
	if !bytes.Equal(expectedContent, actualContent) {
		return fmt.Errorf("committed publication ledger %q does not match plan", repository)
	}
	return nil
}

func updatedPublicationRecords(existing []PublicationRecord, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) ([]PublicationRecord, error) {
	seen := make(map[string]PublicationRecord)
	for _, record := range existing {
		seen[record.PlanID+"\x00"+record.ChangeID+"\x00"+record.Package+"\x00"+record.Version] = record
	}
	records := append([]PublicationRecord(nil), existing...)
	for _, packageVersion := range lock.PackageVersion {
		key := planID + "\x00" + changeID + "\x00" + packageVersion.Package + "\x00" + packageVersion.Version
		candidate := PublicationRecord{
			SchemaVersion: LedgerSchema,
			PlanID:        planID, ChangeID: changeID, Repository: repository,
			Package: packageVersion.Package, Version: packageVersion.Version,
			BlobSHA256: blobDigests(packageVersion), TreeSHA256: treeSHA, RecordedAt: recordedAt,
		}
		if previous, exists := seen[key]; exists {
			if !publicationRecordEqual(previous, candidate) {
				return nil, fmt.Errorf("publication record %s is not idempotent", key)
			}
			continue
		}
		records = append(records, candidate)
	}
	return records, nil
}

func encodeLedger(records []PublicationRecord) ([]byte, error) {
	var content []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		content = append(content, line...)
		content = append(content, '\n')
	}
	return content, nil
}

func publicationRecordEqual(left, right PublicationRecord) bool {
	return left.SchemaVersion == right.SchemaVersion && left.PlanID == right.PlanID && left.ChangeID == right.ChangeID &&
		left.Repository == right.Repository && left.Package == right.Package && left.Version == right.Version &&
		left.TreeSHA256 == right.TreeSHA256 && left.RecordedAt == right.RecordedAt && equalStrings(left.BlobSHA256, right.BlobSHA256)
}

func blobDigests(packageVersion PackageVersion) []string {
	digests := make([]string, 0, len(packageVersion.Blobs))
	for _, blob := range packageVersion.Blobs {
		digests = append(digests, blob.SHA256)
	}
	sort.Strings(digests)
	return digests
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ledgerPath(root, repository string) (string, error) {
	return WorkspacePath(root, filepath.ToSlash(filepath.Join("publications", repository+".jsonl")))
}
