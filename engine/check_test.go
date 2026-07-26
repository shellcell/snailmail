package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shellcell/snailmail/blob"
	"github.com/shellcell/snailmail/internal/state"
)

func TestCheckWorkspaceAuditsPlacedAndUnplacedArtifacts(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "check-test"}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"pypi", "deb", "helm"} {
		setup := SetupRepositoryRequest{Root: root, Name: format, Format: format, HostType: "local", Output: "public/" + format, Visibility: "public"}
		if format == "deb" {
			setup.AllowUnsigned = true
		}
		if err := SetupRepository(setup); err != nil {
			t.Fatal(err)
		}
		artifact := workspaceArtifact(t, root, format, "1.2.3")
		if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: format, Artifacts: []string{artifact}}); err != nil {
			t.Fatal(err)
		}
	}
	checked, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if checked.Repositories != 3 || checked.PackageVersions != 3 || checked.Artifacts != 3 || len(checked.Findings) != 0 {
		t.Fatalf("initial check %#v", checked)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CheckWorkspace(canceled, CheckWorkspaceRequest{Root: root}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled check error = %v", err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	pyLock, err := state.LoadLock(root, manifest.Repositories["pypi"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Yank(PlacementMutationRequest{Root: root, Repository: "pypi", Package: pyLock.PackageVersion[0].Package, Version: pyLock.PackageVersion[0].Version, All: true}); err != nil {
		t.Fatal(err)
	}
	_, missingName, err := state.LoadBlob(root, "pypi", pyLock.PackageVersion[0].Blobs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(missingName); err != nil {
		t.Fatal(err)
	}
	helmLock, err := state.LoadLock(root, manifest.Repositories["helm"])
	if err != nil {
		t.Fatal(err)
	}
	_, changedName, err := state.LoadBlob(root, "helm", helmLock.PackageVersion[0].Blobs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(changedName, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changedName, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	checked, err = CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.Findings) != 2 || checked.Findings[0].State != "changed" || checked.Findings[1].State != "missing" {
		t.Fatalf("corrupt check findings %#v", checked.Findings)
	}
}

func TestCheckWorkspaceReadsRemoteAuthorityWithoutFillingCAS(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "-b", "main")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := InitWorkspace(InitWorkspaceRequest{Root: root, Name: "remote-check"}); err != nil {
		t.Fatal(err)
	}
	if err := SetupRepository(SetupRepositoryRequest{Root: root, Name: "python", Format: "pypi", HostType: "local", Output: "public/python", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	artifact := workspaceArtifact(t, root, "pypi", "1.2.3")
	if _, err := AddArtifacts(AddArtifactsRequest{Root: root, Repository: "python", Artifacts: []string{artifact}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := state.LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.LoadLock(root, manifest.Repositories["python"])
	if err != nil {
		t.Fatal(err)
	}
	locked := lock.PackageVersion[0].Blobs[0]
	_, localName, err := state.LoadBlob(root, "pypi", locked)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(localName)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryBlobStore{objects: map[string][]byte{locked.SHA256: content}}
	manifest.BlobStore = state.BlobStoreConfig{Type: "s3", Bucket: "check-bucket", Region: "us-east-1"}
	if err := state.WriteManifest(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(localName); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{}}); err == nil {
		t.Fatal("remote resolver returned a nil store")
	}
	checked, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{store: store}})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.Findings) != 0 {
		t.Fatalf("remote check findings %#v", checked.Findings)
	}
	if _, err := os.Stat(localName); !os.IsNotExist(err) {
		t.Fatalf("read-only check filled local CAS: %v", err)
	}
	delete(store.objects, locked.SHA256)
	missing, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{store: store}})
	if err != nil || len(missing.Findings) != 1 || missing.Findings[0].State != "missing" {
		t.Fatalf("remote missing check=%#v err=%v", missing, err)
	}
	store.objects[locked.SHA256] = []byte("provider failure")
	unknown, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{store: store}})
	if err != nil || len(unknown.Findings) != 1 || unknown.Findings[0].State != "unknown" {
		t.Fatalf("remote unknown check=%#v err=%v", unknown, err)
	}
	failed := &checkBlobStore{err: fmt.Errorf("%w: remote bytes differ", blob.ErrCorrupt)}
	changed, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{store: failed}})
	if err != nil || len(changed.Findings) != 1 || changed.Findings[0].State != "changed" {
		t.Fatalf("remote changed check=%#v err=%v", changed, err)
	}
	lock.PackageVersion[0].Blobs[0].Size = 1 << 40
	if err := state.WriteLock(root, manifest.Repositories["python"], lock); err != nil {
		t.Fatal(err)
	}
	oversized := &checkBlobStore{}
	changed, err = CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: root, Blobs: staticBlobResolver{store: oversized}})
	if err != nil || len(changed.Findings) != 1 || changed.Findings[0].State != "changed" || oversized.fetches != 0 {
		t.Fatalf("oversized remote check=%#v fetches=%d err=%v", changed, oversized.fetches, err)
	}
}

func TestCheckWorkspaceRejectsShallowHistory(t *testing.T) {
	source := t.TempDir()
	initializeRepository(t, source, "pypi")
	commitWorkspace(t, source, "initialize workspace")
	clone := filepath.Join(t.TempDir(), "clone")
	if output, err := exec.Command("git", "clone", "--depth=1", "file://"+source, clone).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v: %s", err, output)
	}
	if _, err := CheckWorkspace(context.Background(), CheckWorkspaceRequest{Root: clone}); err == nil {
		t.Fatal("check accepted incomplete Git history")
	}
}

type checkBlobStore struct {
	err     error
	fetches int
}

func (*checkBlobStore) Put(context.Context, blob.Ref, io.Reader) error {
	return errors.New("unexpected put")
}

func (store *checkBlobStore) Fetch(context.Context, blob.Ref, io.Writer) error {
	store.fetches++
	return store.err
}
