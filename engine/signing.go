package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/deb"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

type deploymentSigningState struct {
	active         string
	trusted        []string
	keyring        string
	phase          string
	minimumRefresh int64
}

func applyRepositorySigning(ctx context.Context, root string, repository state.Repository, keys map[string]state.SigningKey, artifact domain.RepositoryArtifact, signatureTime time.Time, planned []state.PlanSigning, resolver signer.Resolver) (domain.RepositoryArtifact, []state.PlanSigning, error) {
	activeKeyName, trustedKeyNames, rotationPhase, minimumRefresh, err := repositorySigningState(repository)
	if err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	if activeKeyName == "" {
		if len(planned) != 0 {
			return domain.RepositoryArtifact{}, nil, errors.New("plan contains signing nodes for an unsigned repository")
		}
		return artifact, nil, nil
	}
	if len(planned) > 1 {
		return domain.RepositoryArtifact{}, nil, errors.New("Debian repository has more than one active signer")
	}
	if repository.Format != "deb" {
		return domain.RepositoryArtifact{}, nil, fmt.Errorf("repository signing is not implemented for format %q", repository.Format)
	}
	key, exists := keys[activeKeyName]
	if !exists {
		return domain.RepositoryArtifact{}, nil, fmt.Errorf("unknown signing key %q", activeKeyName)
	}
	var publicKeyring []byte
	trustedPlanKeys := make([]state.PlanPublicKey, 0, len(trustedKeyNames))
	trustedFingerprints := make([]string, 0, len(trustedKeyNames))
	var publicBinary []byte
	var binaryIdentity signer.Identity
	for _, trustedKeyName := range trustedKeyNames {
		trustedKey, exists := keys[trustedKeyName]
		if !exists {
			return domain.RepositoryArtifact{}, nil, fmt.Errorf("unknown trusted signing key %q", trustedKeyName)
		}
		binary, armored, err := state.LoadSigningPublic(root, trustedKey)
		if err != nil {
			return domain.RepositoryArtifact{}, nil, err
		}
		inspectedBinary, binaryErr := openpgpsigner.InspectPublic(binary)
		inspectedArmor, armorErr := openpgpsigner.InspectArmoredPublic(armored)
		if binaryErr != nil || armorErr != nil || inspectedBinary != inspectedArmor || !identityMatchesState(inspectedBinary, trustedKey) {
			return domain.RepositoryArtifact{}, nil, errors.New("committed public forms do not match the configured signing identity")
		}
		publicKeyring = append(publicKeyring, binary...)
		trustedPlanKeys = append(trustedPlanKeys, state.PlanPublicKey{
			KeyName: trustedKeyName, Fingerprint: trustedKey.Fingerprint,
			PublicKeyPath: trustedKey.PublicKeyPath, PublicKeySHA256: trustedKey.PublicKeySHA256,
		})
		trustedFingerprints = append(trustedFingerprints, trustedKey.Fingerprint)
		if trustedKeyName == activeKeyName {
			publicBinary = binary
			binaryIdentity = inspectedBinary
		}
	}
	keyringDigest := sha256.Sum256(publicKeyring)
	if len(publicBinary) == 0 {
		return domain.RepositoryArtifact{}, nil, errors.New("active signer is absent from trusted keyring")
	}
	if signatureTime.Before(binaryIdentity.CreatedAt) || !signatureTime.Before(binaryIdentity.ExpiresAt) {
		return domain.RepositoryArtifact{}, nil, errors.New("signature time is outside signing key validity")
	}
	release, err := deb.ReleasePayload(artifact, repository.Suite)
	if err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	payloadDigest := sha256.Sum256(release)
	var resolved *state.PlanSigning
	if len(planned) == 1 {
		copyPlanned := planned[0]
		resolved = &copyPlanned
	} else {
		if resolver == nil {
			return domain.RepositoryArtifact{}, nil, errors.New("signer resolver is required to plan a signed repository")
		}
		selected, err := resolver.Resolve(ctx, signer.Ref{Backend: key.Ref.Backend, ID: key.Ref.ID})
		if err != nil {
			return domain.RepositoryArtifact{}, nil, err
		}
		defer selected.Close()
		identity, err := selected.Identity(ctx)
		if err != nil || identity != binaryIdentity {
			return domain.RepositoryArtifact{}, nil, errors.New("private signer identity differs from committed public key")
		}
		resolved = &state.PlanSigning{
			KeyName: activeKeyName, Algorithm: key.Algorithm, Fingerprint: key.Fingerprint,
			PublicKeyPath: key.PublicKeyPath, PublicKeySHA256: key.PublicKeySHA256,
			PublicArmorPath: key.PublicArmorPath, PublicArmorSHA256: key.PublicArmorSHA256,
			SignatureTime: signatureTime.UTC().Format(time.RFC3339), KeyringPath: repository.SigningKeyring,
			KeyringSHA256: hex.EncodeToString(keyringDigest[:]), TrustedKeys: trustedPlanKeys,
			RotationPhase: rotationPhase, MinimumRefreshSeconds: minimumRefresh,
		}
		for index, scheme := range []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached} {
			request := signer.Request{Scheme: scheme, Payload: release, CreatedAt: signatureTime}
			response, err := selected.Sign(ctx, request)
			if err != nil {
				return domain.RepositoryArtifact{}, nil, err
			}
			repeated, err := selected.Sign(ctx, request)
			if err != nil || !reflect.DeepEqual(response, repeated) {
				return domain.RepositoryArtifact{}, nil, errors.New("signer does not produce deterministic responses")
			}
			if err := openpgpsigner.VerifyResponse(request, response, publicBinary, key.Fingerprint); err != nil {
				return domain.RepositoryArtifact{}, nil, err
			}
			contentDigest := sha256.Sum256(response.Content)
			ids := []string{"deb-inrelease", "deb-release-gpg"}
			outputs := []string{"dists/" + repository.Suite + "/InRelease", "dists/" + repository.Suite + "/Release.gpg"}
			resolved.Nodes = append(resolved.Nodes, state.SigningNode{
				ID: ids[index], Kind: "sign", DependsOn: []string{"deb-release"}, Scheme: scheme, OutputPath: outputs[index], PayloadSHA256: hex.EncodeToString(payloadDigest[:]),
				ContentSHA256: hex.EncodeToString(contentDigest[:]), Content: append([]byte(nil), response.Content...),
			})
		}
		resolved.RecipeSHA256 = signingRecipeDigest(*resolved)
	}
	if err := validatePlannedSigning(*resolved, activeKeyName, key, trustedPlanKeys, repository.SigningKeyring, rotationPhase, minimumRefresh, repository.Suite, signatureTime, release, publicBinary, publicKeyring); err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	signed, err := deb.ApplySigning(artifact, repository.Suite, deb.SigningMaterial{
		Fingerprint: key.Fingerprint, PublicKey: publicBinary,
		KeyringPath: repository.SigningKeyring, PublicKeyring: publicKeyring, TrustedFingerprints: trustedFingerprints, SignatureTime: signatureTime,
		InRelease: resolved.Nodes[0].Content, ReleaseGPG: resolved.Nodes[1].Content,
	})
	if err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	copyResolved := *resolved
	copyResolved.TrustedKeys = append([]state.PlanPublicKey(nil), resolved.TrustedKeys...)
	copyResolved.Nodes = append([]state.SigningNode(nil), resolved.Nodes...)
	for index := range copyResolved.Nodes {
		copyResolved.Nodes[index].DependsOn = append([]string(nil), resolved.Nodes[index].DependsOn...)
		copyResolved.Nodes[index].Content = append([]byte(nil), resolved.Nodes[index].Content...)
	}
	return signed, []state.PlanSigning{copyResolved}, nil
}

func validatePlannedSigning(planned state.PlanSigning, keyName string, key state.SigningKey, trustedKeys []state.PlanPublicKey, keyringPath, rotationPhase string, minimumRefresh int64, suite string, generatedAt time.Time, release, publicBinary, publicKeyring []byte) error {
	keyringDigest := sha256.Sum256(publicKeyring)
	if planned.KeyName != keyName || planned.Algorithm != key.Algorithm || planned.Fingerprint != key.Fingerprint ||
		planned.PublicKeyPath != key.PublicKeyPath || planned.PublicKeySHA256 != key.PublicKeySHA256 ||
		planned.PublicArmorPath != key.PublicArmorPath || planned.PublicArmorSHA256 != key.PublicArmorSHA256 ||
		planned.SignatureTime != generatedAt.UTC().Format(time.RFC3339) || planned.KeyringPath != keyringPath || planned.KeyringSHA256 != hex.EncodeToString(keyringDigest[:]) ||
		!reflect.DeepEqual(planned.TrustedKeys, trustedKeys) || planned.RotationPhase != rotationPhase || planned.MinimumRefreshSeconds != minimumRefresh {
		return errors.New("planned signing identity or response set does not match repository configuration")
	}
	if err := validateSigningRecipeMetadata(planned, suite); err != nil {
		return err
	}
	payloadDigest := sha256.Sum256(release)
	for index, scheme := range []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached} {
		node := planned.Nodes[index]
		contentDigest := sha256.Sum256(node.Content)
		if node.Scheme != scheme || node.PayloadSHA256 != hex.EncodeToString(payloadDigest[:]) || node.ContentSHA256 != hex.EncodeToString(contentDigest[:]) {
			return errors.New("planned signing response digest does not match its content")
		}
		if err := openpgpsigner.VerifyResponse(
			signer.Request{Scheme: scheme, Payload: release, CreatedAt: generatedAt},
			signer.Response{Scheme: scheme, Fingerprint: key.Fingerprint, Content: node.Content}, publicBinary, key.Fingerprint,
		); err != nil {
			return fmt.Errorf("planned signing response: %w", err)
		}
	}
	return nil
}

func identityMatchesState(identity signer.Identity, key state.SigningKey) bool {
	createdAt, createdErr := time.Parse(time.RFC3339, key.CreatedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, key.ExpiresAt)
	return createdErr == nil && expiresErr == nil && identity.Algorithm == key.Algorithm && identity.Fingerprint == key.Fingerprint &&
		identity.CreatedAt.Equal(createdAt) && identity.ExpiresAt.Equal(expiresAt) && identity.Bits == 4096
}

func signingContentsEqual(left, right []state.PlanSigning) bool {
	if len(left) != len(right) {
		return false
	}
	for signingIndex := range left {
		leftSigning, rightSigning := left[signingIndex], right[signingIndex]
		if leftSigning.KeyName != rightSigning.KeyName || leftSigning.Algorithm != rightSigning.Algorithm || leftSigning.Fingerprint != rightSigning.Fingerprint ||
			leftSigning.PublicKeyPath != rightSigning.PublicKeyPath || leftSigning.PublicKeySHA256 != rightSigning.PublicKeySHA256 ||
			leftSigning.PublicArmorPath != rightSigning.PublicArmorPath || leftSigning.PublicArmorSHA256 != rightSigning.PublicArmorSHA256 ||
			leftSigning.SignatureTime != rightSigning.SignatureTime || leftSigning.RecipeSHA256 != rightSigning.RecipeSHA256 ||
			leftSigning.KeyringPath != rightSigning.KeyringPath || leftSigning.KeyringSHA256 != rightSigning.KeyringSHA256 ||
			!reflect.DeepEqual(leftSigning.TrustedKeys, rightSigning.TrustedKeys) || leftSigning.RotationPhase != rightSigning.RotationPhase ||
			leftSigning.MinimumRefreshSeconds != rightSigning.MinimumRefreshSeconds || len(leftSigning.Nodes) != len(rightSigning.Nodes) {
			return false
		}
		for nodeIndex := range leftSigning.Nodes {
			leftNode, rightNode := leftSigning.Nodes[nodeIndex], rightSigning.Nodes[nodeIndex]
			if leftNode.ID != rightNode.ID || leftNode.Kind != rightNode.Kind || !reflect.DeepEqual(leftNode.DependsOn, rightNode.DependsOn) || leftNode.Scheme != rightNode.Scheme ||
				leftNode.PayloadSHA256 != rightNode.PayloadSHA256 || leftNode.OutputPath != rightNode.OutputPath || leftNode.ContentSHA256 != rightNode.ContentSHA256 || !bytes.Equal(leftNode.Content, rightNode.Content) {
				return false
			}
		}
	}
	return true
}

func signingRecipeDigest(signing state.PlanSigning) string {
	type recipeNode struct {
		ID, Kind, Scheme, PayloadSHA256, OutputPath, ContentSHA256 string
		DependsOn                                                  []string
	}
	recipe := struct {
		KeyName, Algorithm, Fingerprint, PublicKeyPath, PublicKeySHA256 string
		PublicArmorPath, PublicArmorSHA256, SignatureTime               string
		KeyringPath, KeyringSHA256, RotationPhase                       string
		MinimumRefreshSeconds                                           int64
		TrustedKeys                                                     []state.PlanPublicKey
		Nodes                                                           []recipeNode
	}{
		KeyName: signing.KeyName, Algorithm: signing.Algorithm, Fingerprint: signing.Fingerprint,
		PublicKeyPath: signing.PublicKeyPath, PublicKeySHA256: signing.PublicKeySHA256,
		PublicArmorPath: signing.PublicArmorPath, PublicArmorSHA256: signing.PublicArmorSHA256, SignatureTime: signing.SignatureTime,
		KeyringPath: signing.KeyringPath, KeyringSHA256: signing.KeyringSHA256, RotationPhase: signing.RotationPhase,
		MinimumRefreshSeconds: signing.MinimumRefreshSeconds, TrustedKeys: append([]state.PlanPublicKey(nil), signing.TrustedKeys...),
	}
	for _, node := range signing.Nodes {
		recipe.Nodes = append(recipe.Nodes, recipeNode{
			ID: node.ID, Kind: node.Kind, DependsOn: append([]string(nil), node.DependsOn...), Scheme: node.Scheme,
			PayloadSHA256: node.PayloadSHA256, OutputPath: node.OutputPath, ContentSHA256: node.ContentSHA256,
		})
	}
	content, err := json.Marshal(recipe)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func validateSigningRecipeMetadata(signing state.PlanSigning, suite string) error {
	if len(signing.Nodes) != 2 || signing.RecipeSHA256 != signingRecipeDigest(signing) || !validSHA256(signing.KeyringSHA256) ||
		path.IsAbs(signing.KeyringPath) || path.Clean(signing.KeyringPath) != signing.KeyringPath || !strings.HasPrefix(signing.KeyringPath, "keys/") || !strings.HasSuffix(signing.KeyringPath, ".gpg") || len(signing.TrustedKeys) == 0 {
		return errors.New("signing recipe digest does not match its nodes")
	}
	if (signing.RotationPhase == "" && (signing.MinimumRefreshSeconds != 0 || len(signing.TrustedKeys) != 1)) ||
		((signing.RotationPhase == "introducing" || signing.RotationPhase == "activated") && (signing.MinimumRefreshSeconds < state.MinimumSigningRefreshSeconds || len(signing.TrustedKeys) != 2)) ||
		(signing.RotationPhase != "" && signing.RotationPhase != "introducing" && signing.RotationPhase != "activated") {
		return errors.New("signing recipe has invalid rotation trust state")
	}
	foundActive := false
	seenKeys := make(map[string]bool)
	for _, trusted := range signing.TrustedKeys {
		if trusted.KeyName == "" || seenKeys[trusted.KeyName] || !validFingerprint(trusted.Fingerprint) || !validSHA256(trusted.PublicKeySHA256) ||
			trusted.PublicKeyPath == "" {
			return errors.New("signing recipe has invalid trusted key")
		}
		seenKeys[trusted.KeyName] = true
		foundActive = foundActive || trusted.KeyName == signing.KeyName && trusted.Fingerprint == signing.Fingerprint
	}
	if !foundActive {
		return errors.New("signing recipe trust set omits active signer")
	}
	if suite == "" {
		firstDirectory := path.Dir(signing.Nodes[0].OutputPath)
		if path.Base(signing.Nodes[0].OutputPath) != "InRelease" || path.Dir(signing.Nodes[1].OutputPath) != firstDirectory || path.Base(signing.Nodes[1].OutputPath) != "Release.gpg" ||
			path.IsAbs(firstDirectory) || path.Clean(firstDirectory) != firstDirectory || !strings.HasPrefix(firstDirectory, "dists/") {
			return errors.New("signing recipe has invalid Debian output paths")
		}
	} else if signing.Nodes[0].OutputPath != "dists/"+suite+"/InRelease" || signing.Nodes[1].OutputPath != "dists/"+suite+"/Release.gpg" {
		return errors.New("signing recipe output paths do not match Debian suite")
	}
	ids := []string{"deb-inrelease", "deb-release-gpg"}
	schemes := []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached}
	for index, node := range signing.Nodes {
		if node.ID != ids[index] || node.Kind != "sign" || !reflect.DeepEqual(node.DependsOn, []string{"deb-release"}) || node.Scheme != schemes[index] {
			return errors.New("signing recipe has invalid node identity or dependencies")
		}
	}
	return nil
}

func repositorySigningState(repository state.Repository) (active string, trusted []string, phase string, minimumRefresh int64, err error) {
	if len(repository.SigningKeys) == 0 {
		return "", nil, "", 0, nil
	}
	if len(repository.SigningKeys) != 1 || repository.SigningKeyring == "" {
		return "", nil, "", 0, errors.New("repository has invalid signing state")
	}
	active = repository.SigningKeys[0]
	trusted = []string{active}
	if rotation := repository.SigningRotation; rotation != nil {
		trusted = append(trusted, rotation.SuccessorKey)
		phase = rotation.Phase
		minimumRefresh = rotation.MinimumRefreshSeconds
		if phase == "activated" {
			active = rotation.SuccessorKey
		}
	}
	return active, trusted, phase, minimumRefresh, nil
}

func repositoryDeploymentSigningState(repository state.Repository, keys map[string]state.SigningKey) (deploymentSigningState, error) {
	activeKey, trustedKeys, phase, _, err := repositorySigningState(repository)
	if err != nil || activeKey == "" {
		return deploymentSigningState{}, err
	}
	active, exists := keys[activeKey]
	if !exists {
		return deploymentSigningState{}, fmt.Errorf("unknown active signing key %q", activeKey)
	}
	_, _, _, minimumRefresh, _ := repositorySigningState(repository)
	result := deploymentSigningState{active: active.Fingerprint, keyring: repository.SigningKeyring, phase: phase, minimumRefresh: minimumRefresh}
	for _, name := range trustedKeys {
		key, exists := keys[name]
		if !exists {
			return deploymentSigningState{}, fmt.Errorf("unknown trusted signing key %q", name)
		}
		result.trusted = append(result.trusted, key.Fingerprint)
	}
	return result, nil
}

func validateRotationKeyValidity(repository state.Repository, keys map[string]state.SigningKey, at time.Time) error {
	rotation := repository.SigningRotation
	if rotation == nil {
		return nil
	}
	minimum := time.Duration(rotation.MinimumRefreshSeconds) * time.Second
	base, baseExists := keys[repository.SigningKeys[0]]
	successor, successorExists := keys[rotation.SuccessorKey]
	baseExpires, baseErr := time.Parse(time.RFC3339, base.ExpiresAt)
	successorCreated, createdErr := time.Parse(time.RFC3339, successor.CreatedAt)
	successorExpires, successorErr := time.Parse(time.RFC3339, successor.ExpiresAt)
	if !baseExists || !successorExists || baseErr != nil || createdErr != nil || successorErr != nil {
		return errors.New("signing rotation key validity is invalid")
	}
	switch rotation.Phase {
	case "introducing":
		if baseExpires.Before(at.Add(minimum+2*time.Hour)) || successorCreated.After(at.Add(minimum)) || successorExpires.Before(at.Add(2*minimum+2*time.Hour)) {
			return errors.New("signing keys cannot remain valid through introduction and overlap")
		}
	case "activated":
		if successorExpires.Before(at.Add(minimum + 2*time.Hour)) {
			return errors.New("successor signing key cannot remain valid through activated overlap")
		}
	}
	return nil
}

func validateRepositorySigningTransition(repository state.Repository, keys map[string]state.SigningKey, deployment state.DeploymentRecord, observed host.PublishedRevision, at time.Time) error {
	desired, err := repositoryDeploymentSigningState(repository, keys)
	if err != nil {
		return err
	}
	if err := validateRotationKeyValidity(repository, keys, at); err != nil {
		return err
	}
	if deployment.NativeRevision == "" {
		if desired.phase != "" {
			return errors.New("signing rotation requires a deployed stable signing state")
		}
		return nil
	}
	if deploymentSigningMatches(deployment, desired) {
		return nil
	}
	if deployment.NativeRevision != observed.NativeRevision || deployment.TreeSHA256 != observed.TreeSHA256 ||
		(deployment.ManifestSHA256 != "" && observed.ManifestSHA256 != "" && deployment.ManifestSHA256 != observed.ManifestSHA256) {
		return fmt.Errorf("deployed signing state no longer matches the canonical repository (receipt native %q tree %q, observed native %q tree %q)",
			deployment.NativeRevision, deployment.TreeSHA256, observed.NativeRevision, observed.TreeSHA256)
	}
	if desired.active == "" {
		return errors.New("removing repository signing is not an authorized transition")
	}
	if deployment.ActiveSigningFingerprint != "" && deployment.SigningKeyringPath != desired.keyring {
		return errors.New("repository signing keyring path cannot change after deployment")
	}
	if deployment.ActiveSigningFingerprint == "" && desired.phase == "" {
		return nil
	}
	transitionReady := func() bool {
		trustSince, parseErr := time.Parse(time.RFC3339, deployment.TrustSince)
		return parseErr == nil && deployment.SigningMinimumRefreshSeconds >= state.MinimumSigningRefreshSeconds &&
			!at.Before(trustSince.Add(time.Duration(deployment.SigningMinimumRefreshSeconds)*time.Second))
	}
	switch desired.phase {
	case "introducing":
		if deployment.SigningRotationPhase == "" && deployment.SigningMinimumRefreshSeconds == 0 &&
			deployment.ActiveSigningFingerprint == desired.active && reflect.DeepEqual(deployment.TrustedSigningFingerprints, desired.trusted[:1]) {
			return nil
		}
	case "activated":
		if deployment.SigningRotationPhase == "introducing" && deployment.SigningMinimumRefreshSeconds == desired.minimumRefresh &&
			len(desired.trusted) == 2 && deployment.ActiveSigningFingerprint == desired.trusted[0] && desired.active == desired.trusted[1] &&
			reflect.DeepEqual(deployment.TrustedSigningFingerprints, desired.trusted) && transitionReady() {
			return nil
		}
	case "":
		if deployment.SigningRotationPhase == "activated" && len(deployment.TrustedSigningFingerprints) == 2 && len(desired.trusted) == 1 &&
			deployment.ActiveSigningFingerprint == desired.active && desired.trusted[0] == desired.active &&
			deployment.TrustedSigningFingerprints[1] == desired.active && transitionReady() {
			return nil
		}
	}
	return errors.New("repository signing change skips a required deployed rotation phase or refresh window")
}

func deploymentRecordFor(planned state.PlanRepository, previous state.DeploymentRecord, observed host.PublishedRevision, signing deploymentSigningState, nativeRevision, planID, deployedAt string, now time.Time) state.DeploymentRecord {
	record := state.DeploymentRecord{
		Repository: planned.Name, PlanID: planID, ChangeID: planned.ChangeID,
		TreeSHA256: planned.DesiredTreeSHA256, ManifestSHA256: planned.DesiredManifestSHA256,
		NativeRevision: nativeRevision, DeployedAt: deployedAt,
		ActiveSigningFingerprint: signing.active, TrustedSigningFingerprints: append([]string(nil), signing.trusted...),
		SigningKeyringPath: signing.keyring, SigningRotationPhase: signing.phase, SigningMinimumRefreshSeconds: signing.minimumRefresh,
	}
	if signing.active != "" {
		continuousPublication := previous.NativeRevision == observed.NativeRevision && previous.TreeSHA256 == observed.TreeSHA256 &&
			(observed.ManifestSHA256 == "" || previous.ManifestSHA256 == observed.ManifestSHA256)
		if continuousPublication && previous.ActiveSigningFingerprint == signing.active && reflect.DeepEqual(previous.TrustedSigningFingerprints, signing.trusted) && previous.SigningKeyringPath == signing.keyring &&
			previous.SigningRotationPhase == signing.phase && previous.SigningMinimumRefreshSeconds == signing.minimumRefresh && previous.TrustSince != "" {
			record.TrustSince = previous.TrustSince
		} else {
			record.TrustSince = now.UTC().Truncate(time.Second).Format(time.RFC3339)
		}
	}
	return record
}
