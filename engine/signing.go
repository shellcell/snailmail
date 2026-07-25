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
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/signer"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

func applyRepositorySigning(ctx context.Context, root string, repository state.Repository, keys map[string]state.SigningKey, artifact domain.RepositoryArtifact, signatureTime time.Time, planned []state.PlanSigning, resolver signer.Resolver) (domain.RepositoryArtifact, []state.PlanSigning, error) {
	if len(repository.SigningKeys) == 0 {
		if len(planned) != 0 {
			return domain.RepositoryArtifact{}, nil, errors.New("plan contains signing nodes for an unsigned repository")
		}
		return artifact, nil, nil
	}
	if len(repository.SigningKeys) != 1 || len(planned) > 1 {
		return domain.RepositoryArtifact{}, nil, errors.New("dual-sign rotation is not implemented yet")
	}
	if repository.Format != "deb" {
		return domain.RepositoryArtifact{}, nil, fmt.Errorf("repository signing is not implemented for format %q", repository.Format)
	}
	keyName := repository.SigningKeys[0]
	key, exists := keys[keyName]
	if !exists {
		return domain.RepositoryArtifact{}, nil, fmt.Errorf("unknown signing key %q", keyName)
	}
	publicBinary, publicArmor, err := state.LoadSigningPublic(root, key)
	if err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	binaryIdentity, binaryErr := openpgpsigner.InspectPublic(publicBinary)
	armorIdentity, armorErr := openpgpsigner.InspectArmoredPublic(publicArmor)
	if binaryErr != nil || armorErr != nil || binaryIdentity != armorIdentity || !identityMatchesState(binaryIdentity, key) {
		return domain.RepositoryArtifact{}, nil, errors.New("committed public forms do not match the configured signing identity")
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
			KeyName: keyName, Algorithm: key.Algorithm, Fingerprint: key.Fingerprint,
			PublicKeyPath: key.PublicKeyPath, PublicKeySHA256: key.PublicKeySHA256,
			PublicArmorPath: key.PublicArmorPath, PublicArmorSHA256: key.PublicArmorSHA256,
			SignatureTime: signatureTime.UTC().Format(time.RFC3339),
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
	if err := validatePlannedSigning(*resolved, keyName, key, repository.Suite, signatureTime, release, publicBinary); err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	signed, err := deb.ApplySigning(artifact, repository.Suite, deb.SigningMaterial{
		KeyName: keyName, Fingerprint: key.Fingerprint, PublicKey: publicBinary, SignatureTime: signatureTime,
		InRelease: resolved.Nodes[0].Content, ReleaseGPG: resolved.Nodes[1].Content,
	})
	if err != nil {
		return domain.RepositoryArtifact{}, nil, err
	}
	copyResolved := *resolved
	copyResolved.Nodes = append([]state.SigningNode(nil), resolved.Nodes...)
	for index := range copyResolved.Nodes {
		copyResolved.Nodes[index].DependsOn = append([]string(nil), resolved.Nodes[index].DependsOn...)
		copyResolved.Nodes[index].Content = append([]byte(nil), resolved.Nodes[index].Content...)
	}
	return signed, []state.PlanSigning{copyResolved}, nil
}

func validatePlannedSigning(planned state.PlanSigning, keyName string, key state.SigningKey, suite string, generatedAt time.Time, release, publicBinary []byte) error {
	if planned.KeyName != keyName || planned.Algorithm != key.Algorithm || planned.Fingerprint != key.Fingerprint ||
		planned.PublicKeyPath != key.PublicKeyPath || planned.PublicKeySHA256 != key.PublicKeySHA256 ||
		planned.PublicArmorPath != key.PublicArmorPath || planned.PublicArmorSHA256 != key.PublicArmorSHA256 ||
		planned.SignatureTime != generatedAt.UTC().Format(time.RFC3339) {
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
			leftSigning.SignatureTime != rightSigning.SignatureTime || leftSigning.RecipeSHA256 != rightSigning.RecipeSHA256 || len(leftSigning.Nodes) != len(rightSigning.Nodes) {
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
		Nodes                                                           []recipeNode
	}{
		KeyName: signing.KeyName, Algorithm: signing.Algorithm, Fingerprint: signing.Fingerprint,
		PublicKeyPath: signing.PublicKeyPath, PublicKeySHA256: signing.PublicKeySHA256,
		PublicArmorPath: signing.PublicArmorPath, PublicArmorSHA256: signing.PublicArmorSHA256, SignatureTime: signing.SignatureTime,
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
	if len(signing.Nodes) != 2 || signing.RecipeSHA256 != signingRecipeDigest(signing) {
		return errors.New("signing recipe digest does not match its nodes")
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
