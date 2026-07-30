package s3host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/listing"

	"github.com/shellcell/snailmail/internal/hexdigest"
)

var changeIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-f0-9]{12}$`)

const (
	maximumMetadataSize = 16 << 20
	maximumFiles        = 20_000
	maximumTreeBytes    = 4 << 30
)

type Adapter struct {
	client ObjectClient
	broker host.CredentialBroker
}

func New(client ObjectClient, brokers ...host.CredentialBroker) *Adapter {
	adapter := &Adapter{client: client}
	if len(brokers) != 0 {
		adapter.broker = brokers[0]
	}
	return adapter
}

func (adapter *Adapter) Capabilities(_ context.Context, repository host.Repository) (host.Capabilities, error) {
	if err := adapter.validateRepository(repository); err != nil {
		return host.Capabilities{}, err
	}
	// Resolved here as well as at every operation, so a repository this host cannot
	// commit atomically is refused when it is configured rather than when a
	// publication is attempted. A signed yum repository is the case that matters:
	// it switches two objects, and finding that out at apply time means finding it
	// out after the tree has been built.
	if _, err := singleRootPath(repository); err != nil {
		return host.Capabilities{}, err
	}
	capabilities := host.Capabilities{FaithfulPreview: true, ConditionalCommit: true, ConditionalRestore: true, PrivateRead: adapter.broker != nil}
	if adapter.broker != nil {
		capabilities.CredentialBrokerIdentity = adapter.broker.Identity()
	}
	return capabilities, nil
}

func (adapter *Adapter) Observe(ctx context.Context, repository host.Repository) (host.PublishedRevision, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if err := adapter.validateRepository(repository); err != nil {
		return host.PublishedRevision{}, err
	}
	root, err := adapter.client.Head(ctx, objectKey(repository, rootPath))
	if errors.Is(err, ErrNotFound) {
		return host.PublishedRevision{}, nil
	}
	if err != nil {
		return host.PublishedRevision{}, infrastructure("observe S3 root", err)
	}
	revision := host.PublishedRevision{
		NativeRevision:    root.ETag,
		TreeSHA256:        root.Metadata["tree-sha256"],
		PlanID:            root.Metadata["plan-id"],
		ChangeID:          root.Metadata["change-id"],
		RestoreID:         root.Metadata["restore-id"],
		ReleaseSHA256:     root.Metadata["release-sha256"],
		ManifestSHA256:    root.Metadata["manifest-sha256"],
		RestoreSHA256:     root.Metadata["restore-sha256"],
		RestoreRootSHA256: root.Metadata["restore-root-sha256"],
	}
	if revision.TreeSHA256 == "" && revision.PlanID == "" && revision.ChangeID == "" && revision.RestoreID == "" {
		if hasReservedMetadata(root.Metadata) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 repository", Err: errors.New("root has incomplete publication metadata")}
		}
		return host.PublishedRevision{NativeRevision: root.ETag}, nil
	}
	if !hexdigest.ValidSHA256(revision.TreeSHA256) || !hexdigest.ValidSHA256(revision.PlanID) || !changeIDPattern.MatchString(revision.ChangeID) || !validIdentifier(revision.RestoreID) ||
		!hexdigest.ValidSHA256(revision.RestoreSHA256) || (revision.RestoreRootSHA256 != "" && !hexdigest.ValidSHA256(revision.RestoreRootSHA256)) ||
		root.Metadata["release-id"] != revision.TreeSHA256 || !hexdigest.ValidSHA256(revision.ReleaseSHA256) || !hexdigest.ValidSHA256(revision.ManifestSHA256) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 repository", Err: errors.New("root metadata has no valid publication identity")}
	}
	descriptor, descriptorDigest, err := adapter.loadRelease(ctx, repository, revision.TreeSHA256)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 release", Err: errors.New("bound release descriptor is missing")}
		}
		return host.PublishedRevision{}, err
	}
	if descriptor.TreeSHA256 != revision.TreeSHA256 || revision.ReleaseSHA256 != descriptorDigest {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 repository", Err: errors.New("root and immutable release identities differ")}
	}
	manifestContent, manifestInfo, err := adapter.client.Get(ctx, publicationManifestKey(repository, revision.ManifestSHA256), maximumMetadataSize)
	if errors.Is(err, ErrNotFound) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 manifest", Err: errors.New("bound publication manifest is missing")}
	}
	if err != nil {
		return host.PublishedRevision{}, infrastructure("read S3 publication manifest", err)
	}
	if manifestInfo.SHA256 != revision.ManifestSHA256 || digestBytes(manifestContent) != revision.ManifestSHA256 {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 manifest", Err: errors.New("publication manifest is missing or corrupt")}
	}
	var manifest buildgraph.RepositoryManifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil || validatePublishedManifest(repository, manifestContent, manifest, descriptor) != nil {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 manifest", Err: errors.New("publication manifest does not match root tree")}
	}
	restoreDescriptor, restoreDigest, err := adapter.loadRestore(ctx, repository, revision.RestoreID)
	if errors.Is(err, ErrNotFound) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 restore state", Err: errors.New("bound restore descriptor is missing")}
	}
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if restoreDigest != revision.RestoreSHA256 || restoreDescriptor.AfterTreeSHA256 != revision.TreeSHA256 ||
		restoreDescriptor.PlanID != revision.PlanID || restoreDescriptor.ChangeID != revision.ChangeID ||
		(restoreDescriptor.RootExisted != (revision.RestoreRootSHA256 != "")) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 restore state", Err: errors.New("restore state does not match canonical publication")}
	}
	if restoreDescriptor.RootExisted {
		retainedRoot, retainedInfo, err := adapter.client.Get(ctx, restoreRootKey(repository, revision.RestoreID), maximumMetadataSize)
		if errors.Is(err, ErrNotFound) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 restore state", Err: errors.New("bound retained root is missing")}
		}
		if err != nil {
			return host.PublishedRevision{}, infrastructure("read retained S3 root", err)
		}
		if digestBytes(retainedRoot) != revision.RestoreRootSHA256 || retainedInfo.SHA256 != revision.RestoreRootSHA256 || retainedInfo.Metadata["sha256"] != revision.RestoreRootSHA256 {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 restore state", Err: errors.New("bound retained root is corrupt")}
		}
	}
	if err := forEachObject(ctx, len(descriptor.Files), func(ctx context.Context, index int) error {
		file := descriptor.Files[index]
		info, err := adapter.client.Head(ctx, publishedFileKey(repository, revision.TreeSHA256, rootPath, file.Path))
		if errors.Is(err, ErrNotFound) {
			return &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 release", Err: fmt.Errorf("release object %q is missing or corrupt", file.Path)}
		}
		if err != nil {
			return infrastructure("inspect S3 release object", err)
		}
		if info.Size != file.Size || info.SHA256 != file.SHA256 || info.Metadata["sha256"] != file.SHA256 {
			return &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 release", Err: fmt.Errorf("release object %q is missing or corrupt", file.Path)}
		}
		return nil
	}); err != nil {
		return host.PublishedRevision{}, err
	}
	releaseRoot, _, err := adapter.client.Get(ctx, releaseKey(repository, revision.TreeSHA256, rootPath), maximumMetadataSize)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "read immutable S3 root", Err: errors.New("bound immutable root is missing")}
		}
		return host.PublishedRevision{}, infrastructure("read immutable S3 root", err)
	}
	expectedRoot, err := rewriteRoot(repository, releaseRoot, revision.TreeSHA256, bindingAnnotation(rootBindingFromRevision(revision)))
	if err != nil {
		return host.PublishedRevision{}, err
	}
	canonicalRoot, canonicalInfo, err := adapter.client.Get(ctx, objectKey(repository, rootPath), maximumMetadataSize)
	if err != nil || canonicalInfo.ETag != root.ETag || !reflect.DeepEqual(canonicalInfo.Metadata, root.Metadata) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 root", Err: errors.New("canonical root bytes do not match immutable release")}
	}
	if !bytes.Equal(canonicalRoot, expectedRoot) {
		legacyRoot, legacyErr := rewriteRoot(repository, releaseRoot, revision.TreeSHA256, legacyBindingAnnotation(revision.PlanID, revision.ChangeID))
		if legacyErr == nil && bytes.Equal(canonicalRoot, legacyRoot) {
			// Force a same-tree update so the next reviewed plan migrates the root
			// to body-bound publication metadata.
			return host.PublishedRevision{NativeRevision: root.ETag}, nil
		}
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "observe S3 root", Err: errors.New("canonical root bytes do not match immutable release")}
	}
	return revision, nil
}

func (adapter *Adapter) ReadAccess(ctx context.Context, repository host.Repository, revision host.PublishedRevision) (host.ClientAccess, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return host.ClientAccess{}, err
	}
	if err := adapter.validateRepository(repository); err != nil {
		return host.ClientAccess{}, err
	}
	if revision.TreeSHA256 == "" {
		return host.ClientAccess{}, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "issue S3 read access", Err: errors.New("published revision has no tree identity")}
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.ClientAccess{}, err
	}
	if observed != revision {
		return host.ClientAccess{}, &host.Error{Kind: host.ErrorStale, Operation: "issue S3 read access", Err: errors.New("requested revision is no longer canonical")}
	}
	descriptor, _, err := adapter.loadRelease(ctx, repository, revision.TreeSHA256)
	if err != nil {
		return host.ClientAccess{}, err
	}
	releaseRoot, _, err := adapter.client.Get(ctx, releaseKey(repository, revision.TreeSHA256, rootPath), maximumMetadataSize)
	if err != nil {
		return host.ClientAccess{}, infrastructure("read immutable S3 root", err)
	}
	canonicalRoot, err := rewriteRoot(repository, releaseRoot, revision.TreeSHA256, bindingAnnotation(rootBindingFromRevision(revision)))
	if err != nil {
		return host.ClientAccess{}, err
	}
	routes, err := canonicalClientRoutes(repository.CanonicalEndpoint, revision.TreeSHA256, rootPath,
		repository.RootRewriter != nil, descriptor.Files, canonicalRoot)
	if err != nil {
		return host.ClientAccess{}, err
	}
	return adapter.issueAccess(ctx, repository, host.ReadScope{
		WorkspaceID: repository.WorkspaceID, Repository: repository.Name, HostIdentity: repository.HostIdentity,
		Bucket: repository.Bucket, Endpoint: repository.CanonicalEndpoint, PlanID: revision.PlanID, ChangeID: revision.ChangeID, TreeSHA256: revision.TreeSHA256,
		Prefixes: readPrefixes(repository, revision.TreeSHA256, rootPath),
	}, routes)
}

func (adapter *Adapter) Stage(ctx context.Context, repository host.Repository, request host.StageRequest) (result host.StagedPublication, resultErr error) {
	if err := adapter.validateRepository(repository); err != nil {
		return host.StagedPublication{}, err
	}
	descriptor, _, err := descriptorFromRequest(repository, request)
	if err != nil {
		return host.StagedPublication{}, err
	}
	descriptorContent, err := json.Marshal(descriptor)
	if err != nil {
		return host.StagedPublication{}, err
	}
	descriptorDigest := digestBytes(descriptorContent)
	effectID := effectIdentifier(descriptor.PlanID, descriptor.ChangeID)
	if pointer, pointerErr := adapter.loadStagePointer(ctx, repository, effectID); pointerErr == nil {
		existing, loadErr := adapter.loadStage(ctx, repository, pointer.ID)
		if loadErr == nil && pointer.DescriptorSHA256 == descriptorDigest && reflect.DeepEqual(existing, descriptor) {
			return adapter.stageResult(ctx, repository, pointer.ID, existing)
		}
		if loadErr != nil {
			return host.StagedPublication{}, loadErr
		}
		return host.StagedPublication{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "reuse S3 stage", Err: errors.New("effect stage pointer conflicts")}
	} else if !errors.Is(pointerErr, ErrNotFound) {
		return host.StagedPublication{}, infrastructure("read S3 stage pointer", pointerErr)
	}
	identifier, err := randomIdentifier()
	if err != nil {
		return host.StagedPublication{}, infrastructure("create S3 stage identity", err)
	}
	var uploaded []string
	defer func() {
		if resultErr == nil {
			return
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancelCleanup()
		var cleanupErr error
		for _, key := range uploaded {
			if err := adapter.client.Delete(cleanupCtx, key, Conditions{}); err != nil && !errors.Is(err, ErrNotFound) && cleanupErr == nil {
				cleanupErr = err
			}
		}
		if cleanupErr != nil {
			resultErr = fmt.Errorf("%w; clean partial S3 stage: %v", resultErr, cleanupErr)
		}
	}()
	// Every key is recorded before any upload starts so the deferred cleanup
	// removes partial stages regardless of which uploads were in flight.
	for _, file := range descriptor.Files {
		uploaded = append(uploaded, stageKey(repository, identifier, file.Path))
	}
	if err := forEachObject(ctx, len(descriptor.Files), func(ctx context.Context, index int) error {
		file := descriptor.Files[index]
		name := filepath.Join(request.Directory, filepath.FromSlash(file.Path))
		actualSize, actualDigest, err := hashFile(name)
		if err != nil {
			return err
		}
		if actualSize != file.Size || actualDigest != file.SHA256 {
			return &host.Error{Kind: host.ErrorStale, Operation: "stage S3 repository", Err: fmt.Errorf("file %q changed after verification", file.Path)}
		}
		input, err := os.Open(name)
		if err != nil {
			return err
		}
		stored, putErr := adapter.client.Put(ctx, PutRequest{
			Key: stageKey(repository, identifier, file.Path), Body: input, Size: file.Size, SHA256: file.SHA256,
			ContentType: contentType(file.Path), Metadata: map[string]string{"sha256": file.SHA256},
		})
		closeErr := input.Close()
		if putErr != nil {
			return infrastructure("upload S3 stage object", putErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if stored.Size != file.Size || stored.SHA256 != file.SHA256 || stored.Metadata["sha256"] != file.SHA256 {
			return &host.Error{Kind: host.ErrorInfrastructure, Operation: "verify S3 stage object", Err: fmt.Errorf("object %q metadata does not match", file.Path)}
		}
		return nil
	}); err != nil {
		return host.StagedPublication{}, err
	}
	manifest, err := app.VerifyRepository(request.Directory)
	if err != nil || !manifestFormatIs(manifest.Format, repository.Format) || manifest.TreeSHA256 != request.TreeSHA256 {
		return host.StagedPublication{}, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository",
			Err: fmt.Errorf("staged repository is not a valid %s publication", repository.Format)}
	}
	descriptorKey := stageDescriptorKey(repository, identifier)
	uploaded = append(uploaded, descriptorKey)
	if _, err := adapter.client.Put(ctx, PutRequest{
		Key: descriptorKey, Body: bytes.NewReader(descriptorContent), Size: int64(len(descriptorContent)),
		SHA256: digestBytes(descriptorContent), ContentType: "application/json",
		Metadata: map[string]string{"sha256": digestBytes(descriptorContent)},
	}); err != nil {
		return host.StagedPublication{}, infrastructure("write S3 stage descriptor", err)
	}
	stagedResult, err := adapter.stageResult(ctx, repository, identifier, descriptor)
	if err != nil {
		return host.StagedPublication{}, err
	}
	candidateCredential := stagedResult.Access.Credential
	defer func() {
		if resultErr != nil && candidateCredential != nil {
			candidateCredential.Destroy()
		}
	}()
	pointerContent, err := json.Marshal(stagePointer{ID: identifier, DescriptorSHA256: descriptorDigest})
	if err != nil {
		return host.StagedPublication{}, err
	}
	pointerKey := stagePointerKey(repository, effectID)
	if _, err := adapter.client.Put(ctx, PutRequest{
		Key: pointerKey, Body: bytes.NewReader(pointerContent), Size: int64(len(pointerContent)),
		SHA256: digestBytes(pointerContent), ContentType: "application/json",
		Metadata: map[string]string{"sha256": digestBytes(pointerContent)}, Conditions: Conditions{IfNoneMatch: true},
	}); errors.Is(err, ErrPrecondition) {
		pointer, readErr := adapter.loadStagePointer(ctx, repository, effectID)
		if readErr != nil {
			return host.StagedPublication{}, infrastructure("read concurrent S3 stage pointer", readErr)
		}
		existing, loadErr := adapter.loadStage(ctx, repository, pointer.ID)
		if loadErr != nil || pointer.DescriptorSHA256 != descriptorDigest || !reflect.DeepEqual(existing, descriptor) {
			return host.StagedPublication{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "publish S3 stage pointer", Err: errors.New("concurrent effect stage conflicts")}
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		for _, key := range uploaded {
			_ = adapter.client.Delete(cleanupCtx, key, Conditions{})
		}
		cancelCleanup()
		uploaded = nil
		if candidateCredential != nil {
			candidateCredential.Destroy()
			candidateCredential = nil
		}
		return adapter.stageResult(ctx, repository, pointer.ID, existing)
	} else if err != nil {
		pointer, readErr := adapter.loadStagePointer(ctx, repository, effectID)
		if readErr == nil && pointer.ID == identifier && pointer.DescriptorSHA256 == descriptorDigest {
			return stagedResult, nil
		}
		if readErr != nil && !errors.Is(readErr, ErrNotFound) {
			uploaded = nil
			return host.StagedPublication{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "publish S3 stage pointer", EffectMayHaveOccurred: true, Err: readErr}
		}
		return host.StagedPublication{}, infrastructure("publish S3 stage pointer", err)
	}
	return stagedResult, nil
}

func (adapter *Adapter) Commit(ctx context.Context, repository host.Repository, staged host.StagedPublication, expected host.ExpectedRevision) (host.CommitResult, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	if err := adapter.validateRepository(repository); err != nil {
		return host.CommitResult{}, err
	}
	descriptor, err := adapter.loadStage(ctx, repository, staged.ID)
	if err != nil {
		return host.CommitResult{}, err
	}
	if staged.PlanID != descriptor.PlanID || staged.ChangeID != descriptor.ChangeID || staged.TreeSHA256 != descriptor.TreeSHA256 ||
		!reflect.DeepEqual(staged.Files, descriptor.Files) || !reflect.DeepEqual(staged.CommitPaths, descriptor.CommitPaths) {
		return host.CommitResult{}, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "commit S3 repository", Err: errors.New("stage handle does not match its immutable descriptor")}
	}
	expectedReleaseDigest, expectedManifestDigest, err := publicationDigestBindings(descriptor)
	if err != nil {
		return host.CommitResult{}, err
	}
	unlock, err := adapter.acquireCommitLock(ctx, repository, staged.ID)
	if err != nil {
		return host.CommitResult{}, err
	}
	defer unlock()
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.CommitResult{}, err
	}
	if observed.TreeSHA256 == descriptor.TreeSHA256 && observed.PlanID == descriptor.PlanID && observed.ChangeID == descriptor.ChangeID &&
		observed.ReleaseSHA256 == expectedReleaseDigest && observed.ManifestSHA256 == expectedManifestDigest {
		if observed.RestoreID == staged.ID {
			access, err := adapter.ReadAccess(ctx, repository, observed)
			if err != nil {
				return host.CommitResult{}, err
			}
			return commitResult(repository, observed, access), nil
		}
		return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "commit S3 repository", Err: errors.New("publication effect is already bound to different restore state")}
	}
	if !revisionMatchesExpected(observed, expected) {
		return host.CommitResult{}, stale("commit S3 repository", expected, observed)
	}
	releaseDigest, err := adapter.materializeRelease(ctx, repository, staged.ID, descriptor)
	if err != nil {
		return host.CommitResult{}, err
	}
	manifestDigest, err := adapter.materializePublicationManifest(ctx, repository, staged.ID, descriptor)
	if err != nil {
		return host.CommitResult{}, err
	}
	restoreDigest, restoreRootDigest, err := adapter.prepareRestore(ctx, repository, staged.ID, descriptor, observed)
	if err != nil {
		return host.CommitResult{}, err
	}
	rootContent, _, err := adapter.client.Get(ctx, stageKey(repository, staged.ID, rootPath), maximumMetadataSize)
	if err != nil {
		return host.CommitResult{}, infrastructure("read staged S3 root metadata", err)
	}
	binding := rootBinding{
		TreeSHA256: descriptor.TreeSHA256, PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID,
		ReleaseSHA256: releaseDigest, ManifestSHA256: manifestDigest, RestoreID: staged.ID,
		RestoreSHA256: restoreDigest, RestoreRootSHA256: restoreRootDigest,
	}
	rootContent, err = rewriteRoot(repository, rootContent, binding.TreeSHA256, bindingAnnotation(binding))
	if err != nil {
		return host.CommitResult{}, err
	}
	routes, err := canonicalClientRoutes(repository.CanonicalEndpoint, descriptor.TreeSHA256, rootPath,
		repository.RootRewriter != nil, descriptor.Files, rootContent)
	if err != nil {
		return host.CommitResult{}, err
	}
	access, err := adapter.issueAccess(ctx, repository, host.ReadScope{
		WorkspaceID: repository.WorkspaceID, Repository: repository.Name, HostIdentity: repository.HostIdentity,
		Bucket: repository.Bucket, Endpoint: repository.CanonicalEndpoint, PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID, TreeSHA256: descriptor.TreeSHA256,
		Prefixes: readPrefixes(repository, descriptor.TreeSHA256, rootPath),
	}, routes)
	if err != nil {
		return host.CommitResult{}, err
	}
	accessReturned := false
	defer func() {
		if !accessReturned && access.Credential != nil {
			access.Credential.Destroy()
		}
	}()
	conditions := Conditions{IfMatch: expected.NativeRevision, IfNoneMatch: expected.NativeRevision == ""}
	rootMetadata := map[string]string{
		"tree-sha256": descriptor.TreeSHA256, "plan-id": descriptor.PlanID,
		"change-id": descriptor.ChangeID, "release-id": descriptor.TreeSHA256,
		"release-sha256": releaseDigest, "restore-id": staged.ID,
		"manifest-sha256": manifestDigest, "restore-sha256": restoreDigest,
	}
	if restoreRootDigest != "" {
		rootMetadata["restore-root-sha256"] = restoreRootDigest
	}
	root, err := adapter.client.Put(ctx, PutRequest{
		Key: objectKey(repository, rootPath), Body: bytes.NewReader(rootContent), Size: int64(len(rootContent)),
		SHA256: digestBytes(rootContent), ContentType: contentType(rootPath), Conditions: conditions,
		Metadata: rootMetadata,
	})
	if err != nil {
		postcondition, observeErr := adapter.Observe(ctx, repository)
		if observeErr == nil && revisionMatchesBinding(postcondition, binding) {
			accessReturned = true
			return commitResult(repository, postcondition, access), nil
		}
		if observeErr != nil {
			return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "commit S3 root metadata", EffectMayHaveOccurred: true, Err: observeErr}
		}
		if errors.Is(err, ErrPrecondition) {
			return host.CommitResult{}, &host.Error{Kind: host.ErrorStale, Operation: "commit S3 root metadata", Err: err}
		}
		return host.CommitResult{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "commit S3 root metadata", EffectMayHaveOccurred: true, Err: err}
	}
	revision := host.PublishedRevision{
		NativeRevision: root.ETag, TreeSHA256: descriptor.TreeSHA256,
		PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID, RestoreID: staged.ID,
		ReleaseSHA256: releaseDigest, ManifestSHA256: manifestDigest,
		RestoreSHA256: restoreDigest, RestoreRootSHA256: restoreRootDigest,
	}
	accessReturned = true
	return commitResult(repository, revision, access), nil
}

// Restore puts back the root object the failed publication replaced, or deletes it
// if there was none.
//
// It touches nothing else, and that is sufficient for both publication shapes. A
// staged tree's files live in a release directory the restored root does not point
// at. A canonically published tree's files sit at paths whose bytes are fixed by
// the path, so the failed revision never overwrote anything the previous one
// serves — restoring its root makes it whole again, with every file it names still
// present.
//
// What the failed revision leaves behind is unreferenced either way. For a
// canonical publication that debris is in the repository's own namespace rather
// than under .snailmail/releases, which is something lifecycle cleanup has to know;
// it is not a correctness problem, because nothing reaches it without a root that
// names it.
func (adapter *Adapter) Restore(ctx context.Context, repository host.Repository, restore host.RestoreRef, expected host.ExpectedRevision) (host.PublishedRevision, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if err := adapter.validateRepository(repository); err != nil {
		return host.PublishedRevision{}, err
	}
	if !validIdentifier(restore.ID) || restore.PlanID == "" || restore.ChangeID == "" || !hexdigest.ValidSHA256(restore.FailedTree) ||
		!hexdigest.ValidSHA256(restore.DescriptorSHA256) || (restore.RootSHA256 != "" && !hexdigest.ValidSHA256(restore.RootSHA256)) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "restore S3 repository", Err: errors.New("invalid restore reference")}
	}
	unlock, err := adapter.acquireCommitLock(ctx, repository, "restore-"+restore.ID)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	defer unlock()
	descriptor, descriptorDigest, err := adapter.loadRestore(ctx, repository, restore.ID)
	if errors.Is(err, ErrNotFound) {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 repository", Err: errors.New("bound restore descriptor is missing")}
	}
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if descriptorDigest != restore.DescriptorSHA256 || descriptor.AfterTreeSHA256 != restore.FailedTree || descriptor.PlanID != restore.PlanID || descriptor.ChangeID != restore.ChangeID {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 repository", Err: errors.New("restore reference is not bound to current publication")}
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.PublishedRevision{}, err
	}
	if restored, revision, postconditionErr := adapter.restorePostcondition(ctx, repository, descriptor, restore); postconditionErr != nil {
		return host.PublishedRevision{}, postconditionErr
	} else if restored {
		return revision, nil
	}
	if !revisionMatchesExpected(observed, expected) || observed.PlanID != restore.PlanID || observed.ChangeID != restore.ChangeID || observed.TreeSHA256 != restore.FailedTree ||
		observed.RestoreID != restore.ID || observed.RestoreSHA256 != restore.DescriptorSHA256 || observed.RestoreRootSHA256 != restore.RootSHA256 {
		return host.PublishedRevision{}, stale("restore S3 repository", expected, observed)
	}
	rootKey := objectKey(repository, rootPath)
	if !descriptor.RootExisted {
		if err := adapter.client.Delete(ctx, rootKey, Conditions{IfMatch: expected.NativeRevision}); err != nil {
			if restored, revision, postconditionErr := adapter.restorePostcondition(ctx, repository, descriptor, restore); postconditionErr == nil && restored {
				return revision, nil
			} else if postconditionErr != nil {
				return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 root", EffectMayHaveOccurred: true, Err: postconditionErr}
			}
			if errors.Is(err, ErrPrecondition) {
				return host.PublishedRevision{}, &host.Error{Kind: host.ErrorStale, Operation: "restore S3 root", Err: err}
			}
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 root", EffectMayHaveOccurred: true, Err: err}
		}
		return host.PublishedRevision{}, nil
	}
	content, _, err := adapter.client.Get(ctx, restoreRootKey(repository, restore.ID), maximumMetadataSize)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "read retained S3 root", Err: errors.New("bound retained root is missing")}
		}
		return host.PublishedRevision{}, infrastructure("read retained S3 root", err)
	}
	if digestBytes(content) != restore.RootSHA256 {
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "read retained S3 root", Err: errors.New("retained root digest does not match restore reference")}
	}
	if err := adapter.validateRestoreTarget(ctx, repository, descriptor, content); err != nil {
		return host.PublishedRevision{}, err
	}
	root, err := adapter.client.Put(ctx, PutRequest{
		Key: rootKey, Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: digestBytes(content),
		ContentType: contentType(rootPath), Metadata: descriptor.BeforeMetadata,
		Conditions: Conditions{IfMatch: expected.NativeRevision},
	})
	if err != nil {
		if restored, revision, postconditionErr := adapter.restorePostcondition(ctx, repository, descriptor, restore); postconditionErr == nil && restored {
			return revision, nil
		} else if postconditionErr != nil {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 root", EffectMayHaveOccurred: true, Err: postconditionErr}
		}
		if errors.Is(err, ErrPrecondition) {
			return host.PublishedRevision{}, &host.Error{Kind: host.ErrorStale, Operation: "restore S3 root", Err: err}
		}
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "restore S3 root", EffectMayHaveOccurred: true, Err: err}
	}
	observed, observeErr := adapter.Observe(ctx, repository)
	expectedRestored := revisionFromRestore(root.ETag, descriptor)
	if observeErr != nil || observed != expectedRestored {
		if observeErr == nil {
			observeErr = errors.New("restored publication does not match retained state")
		}
		return host.PublishedRevision{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "verify restored S3 root", EffectMayHaveOccurred: true, Err: observeErr}
	}
	return observed, nil
}

func (adapter *Adapter) Abort(ctx context.Context, repository host.Repository, staged host.StagedPublication) error {
	if err := adapter.validateRepository(repository); err != nil {
		return err
	}
	if !validIdentifier(staged.ID) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "abort S3 stage", Err: errors.New("invalid stage identifier")}
	}
	if staged.Access.Credential != nil {
		staged.Access.Credential.Destroy()
	}
	descriptor, err := adapter.loadStage(ctx, repository, staged.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	pointerKey := stagePointerKey(repository, effectIdentifier(descriptor.PlanID, descriptor.ChangeID))
	if content, info, pointerErr := adapter.client.Get(ctx, pointerKey, maximumMetadataSize); pointerErr == nil {
		var pointer stagePointer
		if json.Unmarshal(content, &pointer) == nil && pointer.ID == staged.ID {
			if err := adapter.client.Delete(ctx, pointerKey, Conditions{IfMatch: info.ETag}); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrPrecondition) {
				return infrastructure("abort S3 stage pointer", err)
			}
		}
	} else if !errors.Is(pointerErr, ErrNotFound) {
		return infrastructure("read S3 stage pointer", pointerErr)
	}
	// Completed stages can be shared by exact concurrent retries. Removing the
	// effect pointer marks this stage for lifecycle cleanup without invalidating
	// another caller that already holds the stage handle.
	return nil
}

type publicationDescriptor struct {
	PlanID      string      `json:"plan_id"`
	ChangeID    string      `json:"change_id"`
	TreeSHA256  string      `json:"tree_sha256"`
	Files       []host.File `json:"files"`
	CommitPaths []string    `json:"commit_paths"`
}

type releaseDescriptor struct {
	TreeSHA256  string      `json:"tree_sha256"`
	Files       []host.File `json:"files"`
	CommitPaths []string    `json:"commit_paths"`
}

type stagePointer struct {
	ID               string `json:"id"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
}

type rootBinding struct {
	TreeSHA256        string
	PlanID            string
	ChangeID          string
	ReleaseSHA256     string
	ManifestSHA256    string
	RestoreID         string
	RestoreSHA256     string
	RestoreRootSHA256 string
}

type restoreDescriptor struct {
	PlanID           string            `json:"plan_id"`
	ChangeID         string            `json:"change_id"`
	AfterTreeSHA256  string            `json:"after_tree_sha256"`
	RootExisted      bool              `json:"root_existed"`
	BeforeTreeSHA256 string            `json:"before_tree_sha256,omitempty"`
	BeforePlanID     string            `json:"before_plan_id,omitempty"`
	BeforeChangeID   string            `json:"before_change_id,omitempty"`
	BeforeMetadata   map[string]string `json:"before_metadata,omitempty"`
}

// singleRootPath is the one object whose switch makes a revision live here.
//
// An object store has no ordered multi-object commit; what it offers is one
// atomic PUT. So a format can be published to one exactly when its liveness
// hangs on a single path — PyPI's simple/index.html, a yum repodata/repomd.xml,
// a Helm index.yaml. Everything else is written first, at paths either
// content-addressed or not yet referenced, and the last PUT publishes them all.
//
// Debian needs a suite's Release and its detached signature to become live
// together, Alpine one index per architecture, raw its listing and SHA256SUMS.
// Those are what this refuses, and the reason is the store rather than the
// format — which is why the paths are given rather than inferred.
func singleRootPath(repository host.Repository) (string, error) {
	if len(repository.CommitPaths) != 1 {
		return "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "resolve S3 commit path",
			Err: fmt.Errorf("format %q makes a revision live by switching %d paths, and an object store commits one",
				repository.Format, len(repository.CommitPaths))}
	}
	return repository.CommitPaths[0], nil
}

func descriptorFromRequest(repository host.Repository, request host.StageRequest) (publicationDescriptor, string, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return publicationDescriptor{}, "", err
	}
	if !hexdigest.ValidSHA256(request.TreeSHA256) || !hexdigest.ValidSHA256(request.PlanID) || !changeIDPattern.MatchString(request.ChangeID) {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage identity or tree digest is invalid")}
	}
	if len(request.CommitPaths) != 1 || request.CommitPaths[0] != rootPath {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository",
			Err: fmt.Errorf("format %q must commit %q and nothing else", repository.Format, rootPath)}
	}
	files := append([]host.File(nil), request.Files...)
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if len(files) == 0 || len(files) > maximumFiles {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage file count is outside limits")}
	}
	var total int64
	rootFound := false
	for index, file := range files {
		if err := validateFile(file); err != nil {
			return publicationDescriptor{}, "", err
		}
		if index != 0 && files[index-1].Path == file.Path {
			return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: fmt.Errorf("duplicate file path %q", file.Path)}
		}
		if file.Size > maximumTreeBytes-total {
			return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage exceeds tree size limit")}
		}
		total += file.Size
		rootFound = rootFound || file.Path == rootPath
	}
	if !rootFound {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage has no PyPI root index")}
	}
	var treeFiles []buildgraph.ManifestFile
	for _, file := range files {
		if file.Path != buildgraph.ManifestFilename {
			treeFiles = append(treeFiles, buildgraph.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256})
		}
	}
	if buildgraph.TreeDigest(treeFiles) != request.TreeSHA256 {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage tree digest does not match file descriptors")}
	}
	descriptor := publicationDescriptor{
		PlanID: request.PlanID, ChangeID: request.ChangeID, TreeSHA256: request.TreeSHA256,
		Files: files, CommitPaths: append([]string(nil), request.CommitPaths...),
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil || len(encoded) > maximumMetadataSize {
		return publicationDescriptor{}, "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: errors.New("stage descriptor exceeds metadata size limit")}
	}
	return descriptor, "", nil
}

func (adapter *Adapter) materializeRelease(ctx context.Context, repository host.Repository, stageID string, publication publicationDescriptor) (string, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return "", err
	}
	descriptor := releaseDescriptorFromPublication(publication)
	if err := forEachObject(ctx, len(descriptor.Files), func(ctx context.Context, index int) error {
		file := descriptor.Files[index]
		destination := publishedFileKey(repository, descriptor.TreeSHA256, rootPath, file.Path)
		stored, err := adapter.client.CopyCreate(ctx, stageKey(repository, stageID, file.Path), destination, file.Size, file.SHA256)
		if errors.Is(err, ErrPrecondition) {
			stored, err = adapter.client.Head(ctx, destination)
			if err != nil {
				return infrastructure("reconcile S3 release object", err)
			}
			if stored.Size != file.Size || stored.SHA256 != file.SHA256 || stored.Metadata["sha256"] != file.SHA256 {
				return &host.Error{Kind: host.ErrorIndeterminate, Operation: "materialize S3 release", Err: fmt.Errorf("immutable release object %q conflicts", file.Path)}
			}
			return nil
		}
		if err != nil {
			return infrastructure("materialize S3 release object", err)
		}
		if stored.Size != file.Size || stored.SHA256 != file.SHA256 || stored.Metadata["sha256"] != file.SHA256 {
			return &host.Error{Kind: host.ErrorInfrastructure, Operation: "verify S3 release object", Err: fmt.Errorf("object %q metadata does not match", file.Path)}
		}
		return nil
	}); err != nil {
		return "", err
	}
	content, marshalErr := json.Marshal(descriptor)
	if marshalErr != nil {
		return "", marshalErr
	}
	descriptorDigest := digestBytes(content)
	key := releaseDescriptorKey(repository, descriptor.TreeSHA256)
	_, err = adapter.client.Put(ctx, PutRequest{
		Key: key, Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: descriptorDigest,
		ContentType: "application/json", Metadata: map[string]string{"sha256": descriptorDigest},
		Conditions: Conditions{IfNoneMatch: true},
	})
	if errors.Is(err, ErrPrecondition) {
		existing, _, readErr := adapter.client.Get(ctx, key, maximumMetadataSize)
		if readErr != nil {
			return "", infrastructure("read S3 release descriptor", readErr)
		}
		if !bytes.Equal(existing, content) {
			return "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "materialize S3 release", Err: errors.New("immutable release descriptor conflicts")}
		}
		return descriptorDigest, nil
	}
	if err != nil {
		return "", infrastructure("write S3 release descriptor", err)
	}
	return descriptorDigest, nil
}

func (adapter *Adapter) materializePublicationManifest(ctx context.Context, repository host.Repository, stageID string, descriptor publicationDescriptor) (string, error) {
	var manifest host.File
	for _, file := range descriptor.Files {
		if file.Path == buildgraph.ManifestFilename {
			manifest = file
			break
		}
	}
	if manifest.Path == "" {
		return "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "materialize S3 manifest", Err: errors.New("stage has no management manifest")}
	}
	content, info, err := adapter.client.Get(ctx, stageKey(repository, stageID, manifest.Path), maximumMetadataSize)
	if err != nil {
		return "", infrastructure("read staged S3 publication manifest", err)
	}
	var decoded buildgraph.RepositoryManifest
	if info.Size != manifest.Size || info.SHA256 != manifest.SHA256 || digestBytes(content) != manifest.SHA256 || json.Unmarshal(content, &decoded) != nil ||
		validatePublishedManifest(repository, content, decoded, releaseDescriptorFromPublication(descriptor)) != nil {
		return "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "materialize S3 manifest", Err: errors.New("staged publication manifest is invalid")}
	}
	destination := publicationManifestKey(repository, manifest.SHA256)
	stored, err := adapter.client.CopyCreate(ctx, stageKey(repository, stageID, manifest.Path), destination, manifest.Size, manifest.SHA256)
	if errors.Is(err, ErrPrecondition) {
		stored, err = adapter.client.Head(ctx, destination)
		if err != nil {
			return "", infrastructure("reconcile S3 publication manifest", err)
		}
		if stored.Size != manifest.Size || stored.SHA256 != manifest.SHA256 || stored.Metadata["sha256"] != manifest.SHA256 {
			return "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "materialize S3 manifest", Err: errors.New("immutable publication manifest conflicts")}
		}
		return manifest.SHA256, nil
	}
	if err != nil {
		return "", infrastructure("materialize S3 publication manifest", err)
	}
	if stored.Size != manifest.Size || stored.SHA256 != manifest.SHA256 || stored.Metadata["sha256"] != manifest.SHA256 {
		return "", &host.Error{Kind: host.ErrorInfrastructure, Operation: "verify S3 publication manifest", Err: errors.New("publication manifest metadata does not match")}
	}
	return manifest.SHA256, nil
}

func (adapter *Adapter) prepareRestore(ctx context.Context, repository host.Repository, restoreID string, after publicationDescriptor, before host.PublishedRevision) (string, string, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return "", "", err
	}
	descriptor := restoreDescriptor{
		PlanID: after.PlanID, ChangeID: after.ChangeID, AfterTreeSHA256: after.TreeSHA256,
		RootExisted: before.NativeRevision != "", BeforeTreeSHA256: before.TreeSHA256,
		BeforePlanID: before.PlanID, BeforeChangeID: before.ChangeID,
	}
	rootDigest := ""
	if descriptor.RootExisted {
		content, info, err := adapter.client.Get(ctx, objectKey(repository, rootPath), maximumMetadataSize)
		if err != nil {
			return "", "", infrastructure("retain prior S3 root", err)
		}
		if info.ETag != before.NativeRevision || (before.TreeSHA256 != "" && !metadataMatchesRevision(info.Metadata, before)) {
			return "", "", &host.Error{Kind: host.ErrorStale, Operation: "retain prior S3 root", Err: errors.New("canonical root changed while preparing restore state")}
		}
		rootDigest = digestBytes(content)
		descriptor.BeforeMetadata = info.Metadata
		_, err = adapter.client.Put(ctx, PutRequest{
			Key: restoreRootKey(repository, restoreID), Body: bytes.NewReader(content), Size: int64(len(content)),
			SHA256: rootDigest, ContentType: contentType(rootPath),
			Metadata: map[string]string{"sha256": rootDigest}, Conditions: Conditions{IfNoneMatch: true},
		})
		if errors.Is(err, ErrPrecondition) {
			existing, _, readErr := adapter.client.Get(ctx, restoreRootKey(repository, restoreID), maximumMetadataSize)
			if readErr != nil || !bytes.Equal(existing, content) {
				return "", "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "retain prior S3 root", Err: errors.New("retained root conflicts")}
			}
		} else if err != nil {
			return "", "", infrastructure("retain prior S3 root", err)
		}
	}
	content, err := json.Marshal(descriptor)
	if err != nil {
		return "", "", err
	}
	descriptorDigest := digestBytes(content)
	key := restoreDescriptorKey(repository, restoreID)
	_, err = adapter.client.Put(ctx, PutRequest{
		Key: key, Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: descriptorDigest,
		ContentType: "application/json", Metadata: map[string]string{"sha256": descriptorDigest},
		Conditions: Conditions{IfNoneMatch: true},
	})
	if errors.Is(err, ErrPrecondition) {
		existing, _, readErr := adapter.client.Get(ctx, key, maximumMetadataSize)
		if readErr != nil {
			return "", "", infrastructure("read S3 restore descriptor", readErr)
		}
		if !bytes.Equal(existing, content) {
			return "", "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "prepare S3 restore", Err: errors.New("restore descriptor conflicts")}
		}
		return descriptorDigest, rootDigest, nil
	}
	if err != nil {
		return "", "", infrastructure("write S3 restore descriptor", err)
	}
	return descriptorDigest, rootDigest, nil
}

func (adapter *Adapter) loadStage(ctx context.Context, repository host.Repository, identifier string) (publicationDescriptor, error) {
	if !validIdentifier(identifier) {
		return publicationDescriptor{}, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "load S3 stage", Err: errors.New("invalid stage identifier")}
	}
	content, _, err := adapter.client.Get(ctx, stageDescriptorKey(repository, identifier), maximumMetadataSize)
	if err != nil {
		return publicationDescriptor{}, infrastructure("read S3 stage descriptor", err)
	}
	return decodePublicationDescriptor(repository, content, "decode S3 stage descriptor")
}

func (adapter *Adapter) loadStagePointer(ctx context.Context, repository host.Repository, effectID string) (stagePointer, error) {
	content, _, err := adapter.client.Get(ctx, stagePointerKey(repository, effectID), maximumMetadataSize)
	if err != nil {
		return stagePointer{}, err
	}
	var pointer stagePointer
	if err := json.Unmarshal(content, &pointer); err != nil || !validIdentifier(pointer.ID) || !hexdigest.ValidSHA256(pointer.DescriptorSHA256) {
		return stagePointer{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 stage pointer", Err: errors.New("stage pointer is invalid")}
	}
	return pointer, nil
}

func (adapter *Adapter) loadRelease(ctx context.Context, repository host.Repository, treeSHA256 string) (releaseDescriptor, string, error) {
	content, _, err := adapter.client.Get(ctx, releaseDescriptorKey(repository, treeSHA256), maximumMetadataSize)
	if err != nil {
		return releaseDescriptor{}, "", infrastructure("read S3 release descriptor", err)
	}
	var descriptor releaseDescriptor
	if err := json.Unmarshal(content, &descriptor); err != nil {
		return releaseDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 release descriptor", Err: err}
	}
	validated, _, validationErr := descriptorFromRequest(repository, host.StageRequest{
		PlanID: strings.Repeat("0", sha256.Size*2), ChangeID: "release:000000000000", TreeSHA256: descriptor.TreeSHA256,
		Files: descriptor.Files, CommitPaths: descriptor.CommitPaths,
	})
	if validationErr != nil || !reflect.DeepEqual(validated.Files, descriptor.Files) || !reflect.DeepEqual(validated.CommitPaths, descriptor.CommitPaths) {
		return releaseDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 release descriptor", Err: errors.New("release descriptor is not canonical")}
	}
	var treeFiles []buildgraph.ManifestFile
	for _, file := range descriptor.Files {
		if file.Path != buildgraph.ManifestFilename {
			treeFiles = append(treeFiles, buildgraph.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256})
		}
	}
	if buildgraph.TreeDigest(treeFiles) != descriptor.TreeSHA256 {
		return releaseDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 release descriptor", Err: errors.New("release descriptor tree digest does not match files")}
	}
	return descriptor, digestBytes(content), nil
}

func decodePublicationDescriptor(repository host.Repository, content []byte, operation string) (publicationDescriptor, error) {
	var descriptor publicationDescriptor
	if err := json.Unmarshal(content, &descriptor); err != nil {
		return publicationDescriptor{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: operation, Err: err}
	}
	request := host.StageRequest{
		PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID, TreeSHA256: descriptor.TreeSHA256,
		Files: descriptor.Files, CommitPaths: descriptor.CommitPaths,
	}
	validated, _, err := descriptorFromRequest(repository, request)
	if err != nil || !reflect.DeepEqual(validated, descriptor) {
		return publicationDescriptor{}, &host.Error{Kind: host.ErrorIndeterminate, Operation: operation, Err: errors.New("descriptor is not canonical")}
	}
	return descriptor, nil
}

func (adapter *Adapter) loadRestore(ctx context.Context, repository host.Repository, identifier string) (restoreDescriptor, string, error) {
	content, _, err := adapter.client.Get(ctx, restoreDescriptorKey(repository, identifier), maximumMetadataSize)
	if err != nil {
		return restoreDescriptor{}, "", infrastructure("read S3 restore descriptor", err)
	}
	var descriptor restoreDescriptor
	if err := json.Unmarshal(content, &descriptor); err != nil {
		return restoreDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 restore descriptor", Err: err}
	}
	managedBeforeInvalid := descriptor.BeforeTreeSHA256 != "" && (!hexdigest.ValidSHA256(descriptor.BeforeTreeSHA256) || !hexdigest.ValidSHA256(descriptor.BeforePlanID) || !changeIDPattern.MatchString(descriptor.BeforeChangeID))
	unmanagedBeforeInvalid := descriptor.BeforeTreeSHA256 == "" && (descriptor.BeforePlanID != "" || descriptor.BeforeChangeID != "")
	legacyBeforeInvalid := descriptor.RootExisted && descriptor.BeforeTreeSHA256 == "" && hasReservedMetadata(descriptor.BeforeMetadata) && !validManagedMetadata(descriptor.BeforeMetadata)
	missingRootInvalid := !descriptor.RootExisted && (descriptor.BeforeTreeSHA256 != "" || descriptor.BeforePlanID != "" || descriptor.BeforeChangeID != "" || len(descriptor.BeforeMetadata) != 0)
	if !hexdigest.ValidSHA256(descriptor.PlanID) || !changeIDPattern.MatchString(descriptor.ChangeID) || !hexdigest.ValidSHA256(descriptor.AfterTreeSHA256) || managedBeforeInvalid || unmanagedBeforeInvalid || legacyBeforeInvalid || missingRootInvalid {
		return restoreDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 restore descriptor", Err: errors.New("restore descriptor is invalid")}
	}
	if descriptor.BeforeTreeSHA256 != "" && !metadataMatchesRevision(descriptor.BeforeMetadata, revisionFromRestore("", descriptor)) {
		return restoreDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 restore descriptor", Err: errors.New("restore descriptor metadata is inconsistent")}
	}
	canonical, marshalErr := json.Marshal(descriptor)
	if marshalErr != nil || !bytes.Equal(content, canonical) {
		return restoreDescriptor{}, "", &host.Error{Kind: host.ErrorIndeterminate, Operation: "decode S3 restore descriptor", Err: errors.New("restore descriptor is not canonical")}
	}
	return descriptor, digestBytes(content), nil
}

func (adapter *Adapter) acquireCommitLock(ctx context.Context, repository host.Repository, owner string) (func(), error) {
	content := []byte(owner)
	key := objectKey(repository, path.Join(".snailmail", "commit.lock"))
	metadata := map[string]string{"expires": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)}
	request := PutRequest{
		Key: key, Body: bytes.NewReader(content), Size: int64(len(content)), SHA256: digestBytes(content),
		ContentType: "text/plain", Metadata: metadata, Conditions: Conditions{IfNoneMatch: true},
	}
	info, err := adapter.client.Put(ctx, request)
	if errors.Is(err, ErrPrecondition) {
		existing, headErr := adapter.client.Head(ctx, key)
		if headErr != nil {
			return nil, infrastructure("inspect S3 publication lease", headErr)
		}
		expires, parseErr := time.Parse(time.RFC3339, existing.Metadata["expires"])
		if parseErr != nil || !time.Now().UTC().After(expires) {
			return nil, &host.Error{Kind: host.ErrorInfrastructure, Operation: "acquire S3 publication lease", Err: errors.New("another publication is running")}
		}
		request.Body = bytes.NewReader(content)
		request.Conditions = Conditions{IfMatch: existing.ETag}
		info, err = adapter.client.Put(ctx, request)
	}
	if err != nil {
		return nil, infrastructure("acquire S3 publication lease", err)
	}
	return func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancelCleanup()
		_ = adapter.client.Delete(cleanupCtx, key, Conditions{IfMatch: info.ETag})
	}, nil
}

func validateRepository(repository host.Repository) error {
	// Configuration validation rejects an unsupported pair earlier; this is the
	// adapter refusing to act on one that reached it anyway.
	if repository.Type != "s3" || !host.Supports(repository.Type, repository.Format).Publish {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: fmt.Errorf("S3 does not serve format %q", repository.Format)}
	}
	if repository.Visibility != "public" && repository.Visibility != "private" {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("S3 visibility must be public or private")}
	}
	if repository.Visibility == "private" && (repository.ReadAuth != "basic" || repository.CredentialBroker == "") {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("private S3 reads require a Basic credential broker")}
	}
	if repository.Visibility == "private" && (!hexdigest.ValidSHA256(repository.WorkspaceID) || !hexdigest.ValidSHA256(repository.HostIdentity)) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("private S3 reads require workspace and host identities")}
	}
	if repository.Path != "" || repository.Bucket == "" || repository.CanonicalEndpoint == "" {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("bucket and canonical endpoint are required")}
	}
	if hasControl(repository.Bucket) || hasControl(repository.Region) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("bucket and region must not contain control characters")}
	}
	prefix := strings.Trim(repository.Prefix, "/")
	if prefix != repository.Prefix || strings.ContainsRune(prefix, '\\') || hasControl(prefix) || (prefix != "" && (path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../"))) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("S3 prefix is invalid")}
	}
	if err := validateHTTPURL(repository.CanonicalEndpoint); err != nil {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: fmt.Errorf("canonical endpoint: %w", err)}
	}
	parsed, _ := url.Parse(repository.CanonicalEndpoint)
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("client endpoint must use HTTPS")}
	}
	if repository.Endpoint != "" {
		if err := validateHTTPURL(repository.Endpoint); err != nil {
			return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: fmt.Errorf("S3 endpoint: %w", err)}
		}
		parsed, _ := url.Parse(repository.Endpoint)
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
			return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("S3 API endpoint must use HTTPS")}
		}
	}
	return nil
}

func (adapter *Adapter) validateRepository(repository host.Repository) error {
	if err := validateRepository(repository); err != nil {
		return err
	}
	if repository.Visibility == "private" && adapter.broker == nil {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "configure S3 host", Err: errors.New("private S3 credential broker is unavailable")}
	}
	return nil
}

func validateHTTPURL(value string) error {
	if hasControl(value) {
		return errors.New("must not contain control characters")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be an HTTP(S) URL without credentials, query, or fragment")
	}
	return nil
}

func isLoopbackHost(value string) bool {
	return value == "localhost" || value == "127.0.0.1" || value == "::1"
}

func validateFile(file host.File) error {
	if file.Path == "" || file.Path == "." || len(file.Path) > 1024 || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path ||
		strings.HasPrefix(file.Path, "../") || strings.ContainsRune(file.Path, '\\') || file.Size < 0 || !hexdigest.ValidSHA256(file.SHA256) {
		return &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "stage S3 repository", Err: fmt.Errorf("invalid file descriptor %q", file.Path)}
	}
	return nil
}

// rewriteRoot rebinds a release's root document so its references resolve inside
// the immutable release directory, and records the binding in it. One PUT of the
// result makes the revision live.
//
// The rewrite belongs to the format and arrives on the repository, so this knows
// only that a root has one. A format without one publishes through more than one
// path and never reaches here — singleRootPath refuses it first — but a nil
// rewriter is still reported rather than dereferenced, because a repository
// assembled by something other than the engine would otherwise panic during a
// publication.
func rewriteRoot(repository host.Repository, content []byte, treeSHA256, annotation string) ([]byte, error) {
	if repository.RootRewriter == nil {
		// Published as built. Everything this root names is already at a path
		// whose bytes are fixed, so there is nothing to rebind — and for a yum
		// repository rebinding would invalidate the signature over these exact
		// bytes. The binding is carried in the object's metadata instead, which is
		// where Observe reads it from for every format.
		return append([]byte(nil), content...), nil
	}
	rewritten, err := repository.RootRewriter.RewriteRoot(content, releaseDirectory(treeSHA256), annotation)
	if err != nil {
		return nil, &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "rewrite S3 root", Err: err}
	}
	return rewritten, nil
}

// releaseDirectory is where a release's whole tree is written, relative to the
// repository root. Everything a root names lives under it, at a path that never
// changes once written.
func releaseDirectory(treeSHA256 string) string {
	return ".snailmail/releases/" + treeSHA256 + "/"
}

// bindingAnnotation is what the host records in the published root so it can
// read its own publication binding back out of the bytes it wrote.
func bindingAnnotation(binding rootBinding) string {
	return "snailmail tree=" + binding.TreeSHA256 + " plan=" + binding.PlanID + " change=" + binding.ChangeID +
		" release=" + binding.ReleaseSHA256 + " manifest=" + binding.ManifestSHA256 + " restore=" + binding.RestoreID +
		" restore-descriptor=" + binding.RestoreSHA256 + " restore-root=" + binding.RestoreRootSHA256
}

// legacyBindingAnnotation is the shorter binding written before the root carried
// its release, manifest and restore identities. Roots published then are still
// live, and Observe recognises one so the next reviewed plan can migrate it.
func legacyBindingAnnotation(planID, changeID string) string {
	return "snailmail plan=" + planID + " change=" + changeID
}

func rootBindingFromRevision(revision host.PublishedRevision) rootBinding {
	return rootBinding{
		TreeSHA256: revision.TreeSHA256, PlanID: revision.PlanID, ChangeID: revision.ChangeID,
		ReleaseSHA256: revision.ReleaseSHA256, ManifestSHA256: revision.ManifestSHA256,
		RestoreID: revision.RestoreID, RestoreSHA256: revision.RestoreSHA256,
		RestoreRootSHA256: revision.RestoreRootSHA256,
	}
}

func releaseDescriptorFromPublication(publication publicationDescriptor) releaseDescriptor {
	descriptor := releaseDescriptor{TreeSHA256: publication.TreeSHA256, CommitPaths: append([]string(nil), publication.CommitPaths...)}
	for _, file := range publication.Files {
		if file.Path != buildgraph.ManifestFilename {
			descriptor.Files = append(descriptor.Files, file)
		}
	}
	return descriptor
}

func publicationDigestBindings(publication publicationDescriptor) (string, string, error) {
	releaseContent, err := json.Marshal(releaseDescriptorFromPublication(publication))
	if err != nil {
		return "", "", err
	}
	for _, file := range publication.Files {
		if file.Path == buildgraph.ManifestFilename {
			return digestBytes(releaseContent), file.SHA256, nil
		}
	}
	return "", "", &host.Error{Kind: host.ErrorInvalidConfiguration, Operation: "bind S3 publication", Err: errors.New("stage has no management manifest")}
}

// validatePublishedManifest checks that the published manifest describes the
// release it is bound to.
//
// The manifest's digest is already recorded in the root object's metadata and
// verified against its bytes, and its file set is compared against the descriptor
// below, so this is defence in depth rather than the only tie between them. What
// is checked for every format is structural: the schema, the identity, a canonical
// generation time, the file set, and canonical encoding.
//
// PyPI additionally has its install specification and its per-project verification
// cases asserted, which is how it has always been validated and is not weakened
// here. Another format gets the structural checks and a generic reading of its
// verification cases, because what a case names differs — a project for PyPI, a
// package elsewhere — and asserting PyPI's shape would refuse a correct
// publication. Lifting the format-specific part into a capability, the way the
// root rewrite was, is the follow-up.
// manifestFormatIs reports whether a manifest's format identity belongs to the
// repository's format.
//
// A manifest records a versioned identity — "pypi/v1" — while a repository is
// configured with the bare name. Comparing them directly looked right and refused
// every publication: the two are related by prefix, not equal. The version is not
// checked here because SupportedManifestSchema already decides which manifests this
// adapter understands.
func manifestFormatIs(manifestFormat, repositoryFormat string) bool {
	return repositoryFormat != "" && strings.HasPrefix(manifestFormat, repositoryFormat+"/")
}

// validateGenericVerificationCases reads verification cases without assuming what
// they name.
//
// A case has to identify something and a version, carry no control characters, and
// come in canonical order — the manifest is content-addressed, so a set that could
// be written two ways would produce two digests for one publication. What it must
// not do is require a project the way PyPI does: a yum or Helm case names a
// package, and demanding otherwise would refuse a correct publication.
func validateGenericVerificationCases(content []byte, manifest buildgraph.RepositoryManifest) error {
	if len(manifest.VerificationCases) == 0 {
		return errors.New("manifest verifies nothing")
	}
	for index, verification := range manifest.VerificationCases {
		named := verification.Package
		if named == "" {
			named = verification.Project
		}
		if named == "" || verification.Version == "" || hasControl(named) || hasControl(verification.Version) ||
			hasControl(verification.Architecture) {
			return errors.New("manifest verification case is invalid")
		}
		if index == 0 {
			continue
		}
		previous := manifest.VerificationCases[index-1]
		previousName := previous.Package
		if previousName == "" {
			previousName = previous.Project
		}
		if previousName > named || (previousName == named && previous.Version >= verification.Version) {
			return errors.New("manifest verification cases are not canonical")
		}
	}
	return requireCanonicalManifest(content, manifest)
}

func validatePublishedManifest(repository host.Repository, content []byte, manifest buildgraph.RepositoryManifest, descriptor releaseDescriptor) error {
	if !buildgraph.SupportedManifestSchema(manifest.SchemaVersion) || !manifestFormatIs(manifest.Format, repository.Format) ||
		manifest.TreeSHA256 != descriptor.TreeSHA256 {
		return errors.New("manifest identity does not match release")
	}
	generatedAt, err := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if err != nil || generatedAt.UTC().Format(time.RFC3339) != manifest.GeneratedAt {
		return errors.New("manifest generation time is invalid")
	}
	if manifest.Install.Kind != repository.Format || manifest.Install.IndexPath == "" {
		return errors.New("manifest install specification is invalid")
	}
	if repository.Format == pypi.FormatID &&
		(manifest.Install.IndexPath != "simple/" || manifest.Install.Suite != "" ||
			manifest.Install.Component != "" || len(manifest.Install.Architectures) != 0) {
		return errors.New("manifest install specification is invalid")
	}
	if len(manifest.Files) != len(descriptor.Files) {
		return errors.New("manifest file set does not match release")
	}
	for index, file := range manifest.Files {
		described := descriptor.Files[index]
		if file.Path != described.Path || file.Size != described.Size || file.SHA256 != described.SHA256 {
			return errors.New("manifest file set does not match release")
		}
	}
	if repository.Format != pypi.FormatID {
		return validateGenericVerificationCases(content, manifest)
	}
	paths := make(map[string]bool, len(descriptor.Files))
	projects := make(map[string]bool)
	for _, file := range descriptor.Files {
		paths[file.Path] = true
		parts := strings.Split(file.Path, "/")
		if len(parts) == 3 && parts[0] == "simple" && parts[2] == "index.html" {
			projects[parts[1]] = true
		}
	}
	verifiedProjects := make(map[string]bool)
	for index, verification := range manifest.VerificationCases {
		if verification.Project == "" || verification.Project != pypi.NormalizeName(verification.Project) || verification.Package != "" || verification.Version == "" || hasControl(verification.Version) || verification.Architecture != "" ||
			!paths[path.Join("simple", verification.Project, "index.html")] {
			return errors.New("manifest verification case is invalid")
		}
		verifiedProjects[verification.Project] = true
		if index != 0 {
			previous := manifest.VerificationCases[index-1]
			if previous.Project > verification.Project || (previous.Project == verification.Project && previous.Version >= verification.Version) {
				return errors.New("manifest verification cases are not canonical")
			}
		}
	}
	if len(projects) == 0 || !reflect.DeepEqual(projects, verifiedProjects) {
		return errors.New("manifest verification cases do not cover every project")
	}
	return requireCanonicalManifest(content, manifest)
}

// requireCanonicalManifest checks the published bytes are the one encoding of this
// manifest. It is content-addressed, so a manifest that could be written two ways
// would give one publication two identities.
func requireCanonicalManifest(content []byte, manifest buildgraph.RepositoryManifest) error {
	canonical, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(content, canonical) {
		return errors.New("manifest is not canonically encoded")
	}
	return nil
}

func metadataMatchesRevision(metadata map[string]string, revision host.PublishedRevision) bool {
	return metadata["tree-sha256"] == revision.TreeSHA256 && metadata["plan-id"] == revision.PlanID &&
		metadata["change-id"] == revision.ChangeID && metadata["release-id"] == revision.TreeSHA256 &&
		metadata["release-sha256"] == revision.ReleaseSHA256 && metadata["manifest-sha256"] == revision.ManifestSHA256 &&
		metadata["restore-id"] == revision.RestoreID && metadata["restore-sha256"] == revision.RestoreSHA256 &&
		metadata["restore-root-sha256"] == revision.RestoreRootSHA256
}

func validManagedMetadata(metadata map[string]string) bool {
	revision := host.PublishedRevision{
		TreeSHA256: metadata["tree-sha256"], PlanID: metadata["plan-id"], ChangeID: metadata["change-id"],
		ReleaseSHA256: metadata["release-sha256"], ManifestSHA256: metadata["manifest-sha256"], RestoreID: metadata["restore-id"],
		RestoreSHA256: metadata["restore-sha256"], RestoreRootSHA256: metadata["restore-root-sha256"],
	}
	return hexdigest.ValidSHA256(revision.TreeSHA256) && hexdigest.ValidSHA256(revision.PlanID) && changeIDPattern.MatchString(revision.ChangeID) &&
		hexdigest.ValidSHA256(revision.ReleaseSHA256) && hexdigest.ValidSHA256(revision.ManifestSHA256) && validIdentifier(revision.RestoreID) &&
		hexdigest.ValidSHA256(revision.RestoreSHA256) && (revision.RestoreRootSHA256 == "" || hexdigest.ValidSHA256(revision.RestoreRootSHA256)) &&
		metadataMatchesRevision(metadata, revision)
}

func hasReservedMetadata(metadata map[string]string) bool {
	for _, key := range []string{
		"tree-sha256", "plan-id", "change-id", "release-id", "release-sha256", "manifest-sha256",
		"restore-id", "restore-sha256", "restore-root-sha256",
	} {
		if _, exists := metadata[key]; exists {
			return true
		}
	}
	return false
}

func revisionMatchesBinding(revision host.PublishedRevision, binding rootBinding) bool {
	return revision.TreeSHA256 == binding.TreeSHA256 && revision.PlanID == binding.PlanID && revision.ChangeID == binding.ChangeID &&
		revision.ReleaseSHA256 == binding.ReleaseSHA256 && revision.ManifestSHA256 == binding.ManifestSHA256 && revision.RestoreID == binding.RestoreID &&
		revision.RestoreSHA256 == binding.RestoreSHA256 && revision.RestoreRootSHA256 == binding.RestoreRootSHA256
}

func revisionMatchesExpected(revision host.PublishedRevision, expected host.ExpectedRevision) bool {
	return revision.NativeRevision == expected.NativeRevision && revision.TreeSHA256 == expected.TreeSHA256 && revision.PlanID == expected.PlanID &&
		revision.ChangeID == expected.ChangeID && revision.ReleaseSHA256 == expected.ReleaseSHA256 && revision.ManifestSHA256 == expected.ManifestSHA256 &&
		revision.RestoreID == expected.RestoreID && revision.RestoreSHA256 == expected.RestoreSHA256 && revision.RestoreRootSHA256 == expected.RestoreRootSHA256
}

func commitResult(repository host.Repository, revision host.PublishedRevision, access host.ClientAccess) host.CommitResult {
	return host.CommitResult{
		Revision: revision, CanonicalEndpoint: repository.CanonicalEndpoint, Access: access,
		RestoreRef: &host.RestoreRef{
			ID: revision.RestoreID, PlanID: revision.PlanID, ChangeID: revision.ChangeID, FailedTree: revision.TreeSHA256,
			DescriptorSHA256: revision.RestoreSHA256, RootSHA256: revision.RestoreRootSHA256,
		},
	}
}

func revisionFromRestore(nativeRevision string, descriptor restoreDescriptor) host.PublishedRevision {
	if descriptor.BeforeTreeSHA256 == "" {
		return host.PublishedRevision{NativeRevision: nativeRevision}
	}
	return host.PublishedRevision{
		NativeRevision: nativeRevision, TreeSHA256: descriptor.BeforeTreeSHA256,
		PlanID: descriptor.BeforePlanID, ChangeID: descriptor.BeforeChangeID,
		RestoreID:         descriptor.BeforeMetadata["restore-id"],
		ReleaseSHA256:     descriptor.BeforeMetadata["release-sha256"],
		ManifestSHA256:    descriptor.BeforeMetadata["manifest-sha256"],
		RestoreSHA256:     descriptor.BeforeMetadata["restore-sha256"],
		RestoreRootSHA256: descriptor.BeforeMetadata["restore-root-sha256"],
	}
}

func (adapter *Adapter) validateRestoreTarget(ctx context.Context, repository host.Repository, descriptor restoreDescriptor, rootContent []byte) error {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return err
	}
	if descriptor.BeforeTreeSHA256 == "" {
		return nil
	}
	revision := revisionFromRestore("", descriptor)
	release, releaseDigest, err := adapter.loadRelease(ctx, repository, revision.TreeSHA256)
	if err != nil {
		return err
	}
	if releaseDigest != revision.ReleaseSHA256 {
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: errors.New("retained release descriptor is corrupt")}
	}
	manifestContent, manifestInfo, err := adapter.client.Get(ctx, publicationManifestKey(repository, revision.ManifestSHA256), maximumMetadataSize)
	if errors.Is(err, ErrNotFound) {
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: errors.New("retained publication manifest is missing")}
	}
	if err != nil {
		return infrastructure("read retained S3 publication manifest", err)
	}
	var manifest buildgraph.RepositoryManifest
	if manifestInfo.SHA256 != revision.ManifestSHA256 || digestBytes(manifestContent) != revision.ManifestSHA256 ||
		json.Unmarshal(manifestContent, &manifest) != nil || validatePublishedManifest(repository, manifestContent, manifest, release) != nil {
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: errors.New("retained publication manifest is corrupt")}
	}
	for _, file := range release.Files {
		info, err := adapter.client.Head(ctx, publishedFileKey(repository, revision.TreeSHA256, rootPath, file.Path))
		if errors.Is(err, ErrNotFound) || (err == nil && (info.Size != file.Size || info.SHA256 != file.SHA256 || info.Metadata["sha256"] != file.SHA256)) {
			return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: fmt.Errorf("retained release object %q is missing or corrupt", file.Path)}
		}
		if err != nil {
			return infrastructure("inspect retained S3 release object", err)
		}
	}
	immutableRoot, _, err := adapter.client.Get(ctx, releaseKey(repository, revision.TreeSHA256, rootPath), maximumMetadataSize)
	if errors.Is(err, ErrNotFound) {
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: errors.New("retained immutable root is missing")}
	}
	if err != nil {
		return infrastructure("read retained immutable S3 root", err)
	}
	expectedRoot, err := rewriteRoot(repository, immutableRoot, revision.TreeSHA256, bindingAnnotation(rootBindingFromRevision(revision)))
	if err != nil {
		return err
	}
	if !bytes.Equal(rootContent, expectedRoot) {
		return &host.Error{Kind: host.ErrorIndeterminate, Operation: "validate S3 restore target", Err: errors.New("retained canonical root does not match its immutable release")}
	}
	return nil
}

func (adapter *Adapter) restorePostcondition(ctx context.Context, repository host.Repository, descriptor restoreDescriptor, restore host.RestoreRef) (bool, host.PublishedRevision, error) {
	rootPath, err := singleRootPath(repository)
	if err != nil {
		return false, host.PublishedRevision{}, err
	}
	if !descriptor.RootExisted {
		_, err := adapter.client.Head(ctx, objectKey(repository, rootPath))
		if errors.Is(err, ErrNotFound) {
			return true, host.PublishedRevision{}, nil
		}
		if err != nil {
			return false, host.PublishedRevision{}, infrastructure("inspect restored S3 root", err)
		}
		return false, host.PublishedRevision{}, nil
	}
	content, info, err := adapter.client.Get(ctx, objectKey(repository, rootPath), maximumMetadataSize)
	if errors.Is(err, ErrNotFound) {
		return false, host.PublishedRevision{}, nil
	}
	if err != nil {
		return false, host.PublishedRevision{}, infrastructure("inspect restored S3 root", err)
	}
	if digestBytes(content) != restore.RootSHA256 || !reflect.DeepEqual(info.Metadata, descriptor.BeforeMetadata) {
		return false, host.PublishedRevision{}, nil
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return false, host.PublishedRevision{}, err
	}
	return true, observed, nil
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func randomIdentifier() (string, error) {
	var value [sha256.Size]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func effectIdentifier(planID, changeID string) string {
	digest := sha256.Sum256([]byte(planID + "\x00" + changeID))
	return hex.EncodeToString(digest[:])
}

func (adapter *Adapter) stageResult(ctx context.Context, repository host.Repository, identifier string, descriptor publicationDescriptor) (host.StagedPublication, error) {
	routes, err := clientRoutes(strings.TrimSuffix(repository.CanonicalEndpoint, "/")+"/.snailmail/stages/"+identifier, "", descriptor.Files, nil)
	if err != nil {
		return host.StagedPublication{}, err
	}
	access, err := adapter.issueAccess(ctx, repository, host.ReadScope{
		WorkspaceID: repository.WorkspaceID, Repository: repository.Name, HostIdentity: repository.HostIdentity,
		Bucket: repository.Bucket, Endpoint: repository.CanonicalEndpoint, PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID,
		StageID: identifier, TreeSHA256: descriptor.TreeSHA256, Prefixes: []string{stageKey(repository, identifier, "")},
	}, routes)
	if err != nil {
		return host.StagedPublication{}, err
	}
	return host.StagedPublication{
		ID: identifier, PlanID: descriptor.PlanID, ChangeID: descriptor.ChangeID,
		PreviewEndpoint: strings.TrimSuffix(repository.CanonicalEndpoint, "/") + "/.snailmail/stages/" + identifier,
		TreeSHA256:      descriptor.TreeSHA256, Files: append([]host.File(nil), descriptor.Files...),
		CommitPaths: append([]string(nil), descriptor.CommitPaths...), Access: access,
	}, nil
}

func (adapter *Adapter) issueAccess(ctx context.Context, repository host.Repository, scope host.ReadScope, routes []host.ClientRoute) (host.ClientAccess, error) {
	access := host.ClientAccess{Endpoint: repository.CanonicalEndpoint, Routes: routes}
	if scope.StageID != "" {
		access.Endpoint = strings.TrimSuffix(repository.CanonicalEndpoint, "/") + "/.snailmail/stages/" + scope.StageID
	}
	if repository.Visibility == "public" {
		return access, nil
	}
	credential, err := adapter.broker.Issue(ctx, scope)
	if err != nil {
		return host.ClientAccess{}, &host.Error{Kind: host.ErrorInfrastructure, Operation: "issue private S3 read credential", Retryable: true, Err: err}
	}
	access.Credential = credential
	return access, nil
}

// canonicalClientRoutes says where a client reads each published file from. The
// root is served from the canonical endpoint, because that is the object a
// commit switched; every other file is read from its immutable release, which
// nothing rewrites.
// canonicalClientRoutes are the URLs a client fetches a live revision from.
//
// Where the tree is staged, everything but the root is reached inside the release
// directory, which is what the rebound root points at. Where it is published at
// canonical paths, every file is at the endpoint itself — so the routes a client
// is given match where the objects were actually written, and a verification run
// exercises the same URLs a user would.
func canonicalClientRoutes(endpoint, treeSHA256, rootPath string, staged bool, files []host.File, rootContent []byte) ([]host.ClientRoute, error) {
	releaseEndpoint := strings.TrimSuffix(endpoint, "/") + "/.snailmail/releases/" + treeSHA256
	if !staged {
		routes := make([]host.ClientRoute, 0, len(files))
		for _, file := range files {
			base := endpoint
			content := []byte(nil)
			if snailmailOwned(file.Path) {
				base = releaseEndpoint
			}
			if file.Path == rootPath {
				content = rootContent
			}
			route, err := clientRoute(base, file, content)
			if err != nil {
				return nil, err
			}
			routes = append(routes, route)
		}
		return routes, nil
	}
	routes := make([]host.ClientRoute, 0, len(files))
	for _, file := range files {
		base := releaseEndpoint
		content := []byte(nil)
		if file.Path == rootPath {
			base = endpoint
			content = rootContent
		}
		route, err := clientRoute(base, file, content)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func clientRoutes(endpoint, rootPath string, files []host.File, rootContent []byte) ([]host.ClientRoute, error) {
	routes := make([]host.ClientRoute, 0, len(files))
	for _, file := range files {
		content := []byte(nil)
		if rootPath != "" && file.Path == rootPath {
			content = rootContent
		}
		route, err := clientRoute(endpoint, file, content)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func clientRoute(endpoint string, file host.File, content []byte) (host.ClientRoute, error) {
	routePath := file.Path
	if strings.HasSuffix(routePath, "/index.html") {
		routePath = strings.TrimSuffix(routePath, "index.html")
	}
	address, err := url.JoinPath(strings.TrimSuffix(endpoint, "/")+"/", routePath)
	if err != nil {
		return host.ClientRoute{}, err
	}
	if strings.HasSuffix(routePath, "/") && !strings.HasSuffix(address, "/") {
		address += "/"
	}
	route := host.ClientRoute{URL: address, Size: file.Size, SHA256: file.SHA256}
	if content != nil {
		route.Size = int64(len(content))
		route.SHA256 = digestBytes(content)
	}
	return route, nil
}

func objectKey(repository host.Repository, name string) string {
	if repository.Prefix == "" {
		return path.Clean(name)
	}
	return path.Join(strings.Trim(repository.Prefix, "/"), name)
}

func stageKey(repository host.Repository, identifier, name string) string {
	return objectKey(repository, path.Join(".snailmail", "stages", identifier, name))
}

func stageDescriptorKey(repository host.Repository, identifier string) string {
	return objectKey(repository, path.Join(".snailmail", "stages", identifier, "stage.json"))
}

func stagePointerKey(repository host.Repository, effectID string) string {
	return objectKey(repository, path.Join(".snailmail", "stages", "effects", effectID+".json"))
}

// readPrefixes are the key prefixes a client needs to fetch a revision.
//
// For a format staged in a release directory this is narrow: the root object and
// that one directory. For a format published at canonical paths it is the
// repository, because that is where its packages and metadata are — a wider grant,
// and a stated consequence of publishing without the indirection rather than an
// oversight. It is still scoped to this repository's prefix, and still issued per
// publication with a lifetime of minutes.
func readPrefixes(repository host.Repository, treeSHA256, rootPath string) []string {
	if repository.RootRewriter != nil {
		return []string{objectKey(repository, rootPath), releaseKey(repository, treeSHA256, "")}
	}
	return []string{objectKey(repository, ""), releaseKey(repository, treeSHA256, "")}
}

// publishedFileKey is where one file of a revision is written.
//
// Two shapes, decided by whether the format needs its root rebound:
//
// A format that does — PyPI, whose per-project indexes are rewritten between
// revisions — has its whole tree staged under the release directory, and only its
// rebound root appears at a canonical path. Writing such a tree canonically would
// change what the live revision serves before the new one was committed.
//
// A format that does not — Helm, unsigned yum — has its non-root files written at
// canonical paths, because each of those paths holds bytes fixed by the path and
// so cannot collide with what the live revision serves. Its root is still copied
// into the release directory, as the immutable record Observe compares the live
// root against. Only the root is duplicated: copying the packages too would double
// the storage for no further guarantee, since the descriptor already pins their
// digests.
func publishedFileKey(repository host.Repository, treeSHA256, rootPath, name string) string {
	if repository.RootRewriter != nil || name == rootPath || snailmailOwned(name) {
		return releaseKey(repository, treeSHA256, name)
	}
	return objectKey(repository, name)
}

// snailmailOwned reports whether a published file is snailmail's own rather than
// the format's: the browsable listing and the build-graph manifest.
//
// They are kept in the release directory whichever shape a repository uses,
// because unlike the format's files they are rewritten with every revision — a
// listing gains a row, a manifest gains a verification case. Writing them at
// canonical paths would leave the previous revision unverifiable after a rollback,
// since Observe checks the whole file set and would find the newer bytes.
//
// Nothing is lost by it. Neither is read by a package client, and neither has ever
// been reachable at a canonical path on this host: PyPI stages its whole tree, so
// on S3 these two have always lived in the release directory. A browsable page
// served from an object store is a separate thing to build, not something this
// takes away.
func snailmailOwned(name string) bool {
	return name == listing.Filename || name == buildgraph.ManifestFilename
}

func releaseKey(repository host.Repository, treeSHA256, name string) string {
	return objectKey(repository, path.Join(".snailmail", "releases", treeSHA256, name))
}

func releaseDescriptorKey(repository host.Repository, treeSHA256 string) string {
	return objectKey(repository, path.Join(".snailmail", "releases", treeSHA256, "release.json"))
}

func publicationManifestKey(repository host.Repository, manifestSHA256 string) string {
	return objectKey(repository, path.Join(".snailmail", "manifests", manifestSHA256+".json"))
}

func restoreDescriptorKey(repository host.Repository, identifier string) string {
	return objectKey(repository, path.Join(".snailmail", "restores", identifier, "restore.json"))
}

func restoreRootKey(repository host.Repository, identifier string) string {
	return objectKey(repository, path.Join(".snailmail", "restores", identifier, "root.html"))
}

func validIdentifier(value string) bool {
	return len(value) == sha256.Size*2 && hexdigest.ValidSHA256(value)
}

func contentType(name string) string {
	if extension := filepath.Ext(name); extension != "" {
		if value := mime.TypeByExtension(extension); value != "" {
			return value
		}
	}
	return "application/octet-stream"
}

func hashFile(name string) (int64, string, error) {
	file, err := os.Open(name)
	if err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	size, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil {
		return 0, "", readErr
	}
	if closeErr != nil {
		return 0, "", closeErr
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func infrastructure(operation string, err error) error {
	return &host.Error{Kind: host.ErrorInfrastructure, Operation: operation, Retryable: true, Err: err}
}

func stale(operation string, expected host.ExpectedRevision, actual host.PublishedRevision) error {
	return &host.Error{
		Kind: host.ErrorStale, Operation: operation,
		Err: fmt.Errorf("expected revision %q tree %q, found revision %q tree %q", expected.NativeRevision, expected.TreeSHA256, actual.NativeRevision, actual.TreeSHA256),
	}
}
