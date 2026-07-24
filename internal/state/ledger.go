package state

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func LoadLedger(root, repository string) ([]PublicationRecord, error) {
	name := ledgerPath(root, repository)
	file, err := os.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var records []PublicationRecord
	scanner := bufio.NewScanner(file)
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
	for _, packageVersion := range lock.PackageVersion {
		key := packageVersion.Package + "\x00" + packageVersion.Version
		published := bindings[key]
		if published == nil {
			continue
		}
		current := blobDigests(packageVersion)
		if !equalStrings(published, current) {
			return fmt.Errorf("published package %s@%s cannot change bytes", packageVersion.Package, packageVersion.Version)
		}
	}
	return nil
}

func AppendPublicationRecords(root, repository, planID, changeID, treeSHA, recordedAt string, lock RepositoryLock) error {
	existing, err := LoadLedger(root, repository)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, record := range existing {
		seen[record.PlanID+"\x00"+record.ChangeID+"\x00"+record.Package+"\x00"+record.Version] = true
	}
	records := append([]PublicationRecord(nil), existing...)
	for _, packageVersion := range lock.PackageVersion {
		key := planID + "\x00" + changeID + "\x00" + packageVersion.Package + "\x00" + packageVersion.Version
		if seen[key] {
			continue
		}
		records = append(records, PublicationRecord{
			SchemaVersion: LedgerSchema,
			PlanID:        planID, ChangeID: changeID, Repository: repository,
			Package: packageVersion.Package, Version: packageVersion.Version,
			BlobSHA256: blobDigests(packageVersion), TreeSHA256: treeSHA, RecordedAt: recordedAt,
		})
	}
	var content []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			return err
		}
		content = append(content, line...)
		content = append(content, '\n')
	}
	return atomicWrite(ledgerPath(root, repository), content, 0o644)
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

func ledgerPath(root, repository string) string {
	return filepath.Join(root, "publications", repository+".jsonl")
}
