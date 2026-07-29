package state

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/jsonstrict"

	"github.com/shellcell/snailmail/internal/hexdigest"
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
	return LoadLedgerHistoryContext(context.Background(), root, repository)
}

// LoadLedgerHistoryContext replays the publication history reachable from HEAD.
// Scoping to the current history is deliberate: a record that only ever existed
// on an abandoned branch or an old tag was never part of this line of history,
// and folding those in reported perfectly good ledgers as having "removed an
// immutable record".
func LoadLedgerHistoryContext(ctx context.Context, root, repository string) ([]PublicationRecord, error) {
	return loadLedgerHistoryContext(ctx, root, repository, "HEAD")
}

func LoadLedgerHistoryAtRevisionContext(ctx context.Context, root, repository, revision string) ([]PublicationRecord, error) {
	decoded, err := hex.DecodeString(revision)
	if err != nil || (len(decoded) != 20 && len(decoded) != 32) || revision != strings.ToLower(revision) {
		return nil, errors.New("invalid publication history revision")
	}
	return loadLedgerHistoryContext(ctx, root, repository, revision)
}

func loadLedgerHistoryContext(ctx context.Context, root, repository, revision string) ([]PublicationRecord, error) {
	records, err := LoadLedger(root, repository)
	if err != nil {
		return nil, err
	}
	current := make(map[string]PublicationRecord, len(records))
	all := make(map[string]PublicationRecord, len(records))
	for _, record := range records {
		key := publicationRecordKey(record)
		if _, exists := current[key]; exists {
			return nil, errors.New("publication ledger contains a duplicate record key")
		}
		current[key] = record
		all[key] = record
	}
	relative := filepath.ToSlash(filepath.Join("publications", repository+".jsonl"))
	treePath, err := workspaceGitPath(root, relative)
	if err != nil {
		return nil, err
	}
	output, err := gitOutputContext(ctx, root, "log", revision, "--format=%H", "--diff-filter=AM", "--", ":(top,literal)"+treePath)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A workspace can record artifacts before its first commit, and naming a
		// revision fails outright on an unborn HEAD where a whole-repository walk
		// would simply have been empty.
		if _, verifyErr := gitOutputContext(ctx, root, "rev-parse", "--verify", "--quiet", revision+"^{commit}"); verifyErr != nil {
			return records, nil
		}
		return nil, fmt.Errorf("read publication history: %w", err)
	}
	commits := strings.Fields(output)
	revspecs := make([]string, 0, len(commits))
	for _, commit := range commits {
		revspecs = append(revspecs, commit+":"+treePath)
	}
	// One cat-file batch instead of a `git show` process per historical commit,
	// which grew without bound as a workspace accumulated publications.
	objects, err := catFileBatch(ctx, root, revspecs)
	if err != nil {
		return nil, fmt.Errorf("read publication history: %w", err)
	}
	replayed := make(map[string]bool, len(objects))
	for index, object := range objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if object.id == "" {
			return nil, fmt.Errorf("read publication ledger at %s", commits[index])
		}
		// Successive commits often carry identical ledger bytes; parsing each
		// distinct blob once keeps the replay linear in content, not commits.
		if replayed[object.id] {
			continue
		}
		replayed[object.id] = true
		historical, err := parseLedger(bytes.NewReader(object.content))
		if err != nil {
			return nil, err
		}
		historicalKeys := make(map[string]bool, len(historical))
		for _, record := range historical {
			key := publicationRecordKey(record)
			if historicalKeys[key] {
				return nil, errors.New("publication ledger history contains a duplicate record key")
			}
			historicalKeys[key] = true
			if existing, exists := all[key]; exists {
				if !publicationRecordEqual(existing, record) {
					return nil, errors.New("publication ledger history changed an immutable record")
				}
			} else {
				records = append(records, record)
				all[key] = record
			}
		}
	}
	keys := make([]string, 0, len(all))
	for key := range all {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, exists := current[key]; !exists {
			return nil, errors.New("publication ledger removed an immutable record")
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
		if err := jsonstrict.Decode(scanner.Bytes(), &record, 4<<20); err != nil {
			return nil, fmt.Errorf("decode publication ledger: %w", err)
		}
		if err := validatePublicationRecord(record, ""); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func publicationRecordKey(record PublicationRecord) string {
	return record.PlanID + "\x00" + record.ChangeID + "\x00" + record.Package + "\x00" + record.Version
}

func execGitShow(root, revision, treePath string) ([]byte, error) {
	return execGitShowContext(context.Background(), root, revision, treePath)
}

func execGitShowContext(ctx context.Context, root, revision, treePath string) ([]byte, error) {
	return gitCommandContext(ctx, root, "show", revision+":"+treePath).Output()
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
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if lockBindings[key] == nil {
			parts := strings.SplitN(key, "\x00", 2)
			return fmt.Errorf("published package %s@%s cannot be removed from the lock", parts[0], parts[1])
		}
	}
	return nil
}

func ValidatePublicationHistory(repository string, records []PublicationRecord) error {
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if err := validatePublicationRecord(record, repository); err != nil {
			return err
		}
		key := publicationRecordKey(record)
		if seen[key] {
			return errors.New("publication ledger contains a duplicate record key")
		}
		seen[key] = true
	}
	return nil
}

func validatePublicationRecord(record PublicationRecord, repository string) error {
	if record.SchemaVersion != LedgerSchema {
		return errors.New("unsupported publication ledger schema")
	}
	if record.Repository == "" || (repository != "" && record.Repository != repository) ||
		!hexdigest.ValidSHA256(record.PlanID) || !hexdigest.ValidSHA256(record.TreeSHA256) ||
		record.ChangeID != record.Repository+":"+record.TreeSHA256[:12] ||
		record.Package == "" || record.Version == "" || len(record.BlobSHA256) == 0 {
		return errors.New("invalid publication ledger record")
	}
	previous := ""
	for _, digest := range record.BlobSHA256 {
		if !hexdigest.ValidSHA256(digest) || (previous != "" && digest <= previous) {
			return errors.New("invalid publication ledger blob binding")
		}
		previous = digest
	}
	if _, err := time.Parse(time.RFC3339, record.RecordedAt); err != nil {
		return errors.New("invalid publication ledger timestamp")
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
