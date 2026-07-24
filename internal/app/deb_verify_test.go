package app

import (
	"testing"

	"github.com/shellcell/snailmail/internal/domain"
)

func TestDigestPinnedImage(t *testing.T) {
	valid := "registry.example/debian@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !digestPinnedImage(valid) {
		t.Fatal("digest-pinned image was rejected")
	}
	for _, invalid := range []string{"", "debian:latest", "debian@sha256:short", "debian@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if digestPinnedImage(invalid) {
			t.Fatalf("mutable or invalid image %q was accepted", invalid)
		}
	}
}

func TestDebWorkspaceSizeIncludesStoredAndInstalledBytes(t *testing.T) {
	blobs := []domain.Blob{{Size: 100 << 20, Facts: domain.PackageFacts{InstalledSize: 500 << 20}}}
	workspace, err := debWorkspaceSize(blobs, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if workspace < 856<<20 {
		t.Fatalf("workspace %d did not include base, stored, and installed bytes", workspace)
	}
	if _, err := debWorkspaceSize(blobs, 512<<20); err == nil {
		t.Fatal("expected insufficient workspace limit to fail")
	}
}
