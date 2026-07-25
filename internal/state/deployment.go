package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/internal/jsonstrict"
)

func LoadDeployment(root, repository string) (DeploymentRecord, error) {
	name, err := deploymentPath(root, repository)
	if err != nil {
		return DeploymentRecord{}, err
	}
	content, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return DeploymentRecord{}, nil
	}
	if err != nil {
		return DeploymentRecord{}, err
	}
	var record DeploymentRecord
	if err := jsonstrict.Decode(content, &record, 1<<20); err != nil {
		return DeploymentRecord{}, err
	}
	if err := ValidateDeploymentRecord(record, repository); err != nil {
		return DeploymentRecord{}, err
	}
	canonical, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return DeploymentRecord{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(content, canonical) {
		return DeploymentRecord{}, errors.New("deployment record is not canonical")
	}
	return record, nil
}

func CommitDeployments(root, planID, baseRevision string, records []DeploymentRecord) (revision string, resultErr error) {
	if len(records) == 0 {
		return baseRevision, nil
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Repository < records[right].Repository })
	paths := make([]string, 0, len(records))
	type priorFile struct {
		name    string
		content []byte
		existed bool
	}
	priors := make([]priorFile, 0, len(records))
	defer func() {
		if resultErr == nil {
			return
		}
		for _, prior := range priors {
			if prior.existed {
				if err := atomicWrite(prior.name, prior.content, 0o644); err != nil {
					resultErr = fmt.Errorf("%v; restore deployment record: %w", resultErr, err)
				}
			} else if err := os.Remove(prior.name); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = fmt.Errorf("%v; remove deployment record: %w", resultErr, err)
			}
		}
	}()
	for index, record := range records {
		if index > 0 && records[index-1].Repository == record.Repository {
			return "", errors.New("duplicate deployment record")
		}
		record.SchemaVersion = DeploymentSchema
		if err := ValidateRepositoryName(record.Repository); err != nil {
			return "", errors.New("invalid deployment record")
		}
		if err := ValidateDeploymentRecord(record, record.Repository); err != nil {
			return "", err
		}
		content, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return "", err
		}
		content = append(content, '\n')
		name, err := deploymentPath(root, record.Repository)
		if err != nil {
			return "", err
		}
		existing, readErr := os.ReadFile(name)
		if readErr == nil && bytes.Equal(existing, content) {
			continue
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return "", readErr
		}
		priors = append(priors, priorFile{name: name, content: append([]byte(nil), existing...), existed: readErr == nil})
		if err := atomicWrite(name, content, 0o644); err != nil {
			return "", err
		}
		paths = append(paths, filepath.ToSlash(filepath.Join("deployments", record.Repository+".json")))
	}
	if len(paths) == 0 {
		return baseRevision, nil
	}
	return commitManagedPaths(root, planID, baseRevision, paths, "record snailmail deployments")
}

func validDeploymentIdentity(record DeploymentRecord) bool {
	return validSHA256(record.PlanID) && validSHA256(record.TreeSHA256) &&
		(record.ManifestSHA256 == "" || validSHA256(record.ManifestSHA256)) && record.NativeRevision != "" &&
		record.ChangeID == record.Repository+":"+record.TreeSHA256[:12]
}

func ValidateDeploymentRecord(record DeploymentRecord, repository string) error {
	if record.SchemaVersion == 0 && record.Repository == "" && record.PlanID == "" && record.ChangeID == "" && record.TreeSHA256 == "" && record.ManifestSHA256 == "" &&
		record.NativeRevision == "" && record.DeployedAt == "" && record.ActiveSigningFingerprint == "" && record.SigningKeyringPath == "" &&
		len(record.TrustedSigningFingerprints) == 0 && record.SigningRotationPhase == "" && record.SigningMinimumRefreshSeconds == 0 && record.TrustSince == "" {
		return nil
	}
	if (record.SchemaVersion != 1 && record.SchemaVersion != DeploymentSchema) || record.Repository != repository || !validDeploymentIdentity(record) || !validDeploymentSigning(record) {
		return errors.New("invalid deployment record")
	}
	if _, err := time.Parse(time.RFC3339, record.DeployedAt); err != nil {
		return errors.New("invalid deployment timestamp")
	}
	return nil
}

func validDeploymentSigning(record DeploymentRecord) bool {
	if record.SchemaVersion == 1 {
		return record.ActiveSigningFingerprint == "" && len(record.TrustedSigningFingerprints) == 0 && record.SigningKeyringPath == "" && record.SigningRotationPhase == "" && record.SigningMinimumRefreshSeconds == 0 && record.TrustSince == ""
	}
	if record.ActiveSigningFingerprint == "" {
		return len(record.TrustedSigningFingerprints) == 0 && record.SigningKeyringPath == "" && record.SigningRotationPhase == "" && record.SigningMinimumRefreshSeconds == 0 && record.TrustSince == ""
	}
	if !fingerprintPattern.MatchString(record.ActiveSigningFingerprint) || len(record.TrustedSigningFingerprints) == 0 ||
		validateRelativePath(record.SigningKeyringPath) != nil || !strings.HasPrefix(record.SigningKeyringPath, "keys/") || !strings.HasSuffix(record.SigningKeyringPath, ".gpg") ||
		(record.SigningRotationPhase != "" && record.SigningRotationPhase != "introducing" && record.SigningRotationPhase != "activated") {
		return false
	}
	if (record.SigningRotationPhase == "" && record.SigningMinimumRefreshSeconds != 0) ||
		(record.SigningRotationPhase != "" && record.SigningMinimumRefreshSeconds < MinimumSigningRefreshSeconds) {
		return false
	}
	if (record.SigningRotationPhase == "" && (len(record.TrustedSigningFingerprints) != 1 || record.ActiveSigningFingerprint != record.TrustedSigningFingerprints[0])) ||
		(record.SigningRotationPhase == "introducing" && (len(record.TrustedSigningFingerprints) != 2 || record.ActiveSigningFingerprint != record.TrustedSigningFingerprints[0])) ||
		(record.SigningRotationPhase == "activated" && (len(record.TrustedSigningFingerprints) != 2 || record.ActiveSigningFingerprint != record.TrustedSigningFingerprints[1])) {
		return false
	}
	foundActive := false
	seen := make(map[string]bool)
	for _, fingerprint := range record.TrustedSigningFingerprints {
		if !fingerprintPattern.MatchString(fingerprint) || seen[fingerprint] {
			return false
		}
		seen[fingerprint] = true
		foundActive = foundActive || fingerprint == record.ActiveSigningFingerprint
	}
	if !foundActive {
		return false
	}
	_, err := time.Parse(time.RFC3339, record.TrustSince)
	return err == nil
}

func commitManagedPaths(root, planID, baseRevision string, relativePaths []string, subject string) (string, error) {
	headRef, err := symbolicHead(root)
	if err != nil {
		return "", err
	}
	current, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || current != baseRevision {
		return "", errors.New("stale plan: Git changed before deployment commit")
	}
	indexPath, err := resolveGitPath(root, "index")
	if err != nil {
		return "", err
	}
	releaseIndex, err := acquireGitLock(indexPath + ".lock")
	if err != nil {
		return "", errors.New("Git index is busy")
	}
	defer releaseIndex()
	status, err := gitStatusOutput(root)
	if err != nil {
		return "", err
	}
	allowed := make(map[string]bool, len(relativePaths))
	gitPaths := make(map[string]bool, len(relativePaths))
	for _, relative := range relativePaths {
		allowed[relative] = true
		gitPath, err := workspaceGitPath(root, relative)
		if err != nil {
			return "", err
		}
		gitPaths[gitPath] = true
	}
	authoritative, err := authoritativePaths(root)
	if err != nil {
		return "", err
	}
	if err := validateGitStatus(status, allowed, authoritative); err != nil {
		return "", err
	}
	if err := requireAuthoritativeFilesCommitted(root, baseRevision, authoritative, allowed); err != nil {
		return "", err
	}
	backupIndex, err := copyGitIndex(indexPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(backupIndex)
	temporaryIndex, err := copyGitIndex(indexPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(temporaryIndex)
	indexEnvironment := replaceEnvironment(os.Environ(), "GIT_INDEX_FILE", temporaryIndex)
	arguments := append([]string{"add", "--"}, relativePaths...)
	if _, err := gitOutputEnv(root, indexEnvironment, arguments...); err != nil {
		return "", fmt.Errorf("stage deployment records: %w", err)
	}
	tree, err := gitOutputEnv(root, indexEnvironment, "write-tree")
	if err != nil {
		return "", err
	}
	if err := validatePublicationTree(root, baseRevision, tree, gitPaths); err != nil {
		return "", err
	}
	message := subject + "\n\nSnailmail-Plan: " + planID + "\n"
	command := gitCommand(root, "commit-tree", tree, "-p", baseRevision)
	command.Stdin = strings.NewReader(message)
	command.Env = replaceEnvironment(indexEnvironment,
		"GIT_AUTHOR_NAME", "snailmail", "GIT_AUTHOR_EMAIL", "snailmail@localhost",
		"GIT_COMMITTER_NAME", "snailmail", "GIT_COMMITTER_EMAIL", "snailmail@localhost",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("create deployment commit: %w: %s", err, strings.TrimSpace(string(output)))
	}
	commit := strings.TrimSpace(string(output))
	if err := os.Rename(temporaryIndex, indexPath); err != nil {
		return "", restoreGitIndex(backupIndex, indexPath, err)
	}
	if err := syncStateDirectory(filepath.Dir(indexPath)); err != nil {
		return "", restoreGitIndex(backupIndex, indexPath, err)
	}
	if err := gitRun(root, "update-ref", headRef, commit, baseRevision); err != nil {
		return "", restoreGitIndex(backupIndex, indexPath, err)
	}
	confirmedRef, refErr := symbolicHead(root)
	confirmedHead, headErr := gitOutput(root, "rev-parse", "HEAD")
	if refErr != nil || headErr != nil || confirmedRef != headRef || confirmedHead != commit {
		if rollbackErr := gitRun(root, "update-ref", headRef, baseRevision, commit); rollbackErr != nil {
			return "", fmt.Errorf("Git branch changed during deployment commit and rollback failed: %w", rollbackErr)
		}
		return "", restoreGitIndex(backupIndex, indexPath, errors.New("Git branch changed during deployment commit"))
	}
	return commit, nil
}

func deploymentPath(root, repository string) (string, error) {
	if err := ValidateRepositoryName(repository); err != nil {
		return "", err
	}
	return WorkspacePath(root, filepath.ToSlash(filepath.Join("deployments", repository+".json")))
}
