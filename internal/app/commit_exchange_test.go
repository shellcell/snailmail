//go:build linux || darwin

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExchangeReleaseLinkPreservesConcurrentReplacement(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "repository")
	temporary := filepath.Join(directory, "new-link")
	if err := os.WriteFile(output, []byte("unrelated data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("new-release", temporary); err != nil {
		t.Fatal(err)
	}
	committed, err := exchangeReleaseLink(temporary, output, "old-release")
	if err == nil || !committed {
		t.Fatal("expected concurrent replacement to fail")
	}
	content, err := os.ReadFile(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unrelated data" {
		t.Fatalf("concurrent entry was not preserved: %q", content)
	}
}

func TestExchangeReleaseLinkExchangesExpectedSymlink(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "repository")
	temporary := filepath.Join(directory, "new-link")
	if err := os.Symlink("old-release", output); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("new-release", temporary); err != nil {
		t.Fatal(err)
	}
	committed, err := exchangeReleaseLink(temporary, output, "old-release")
	if err != nil {
		t.Fatal(err)
	}
	if !committed {
		t.Fatal("release was not committed")
	}
	link, err := os.Readlink(output)
	if err != nil {
		t.Fatal(err)
	}
	if link != "new-release" {
		t.Fatalf("release link = %q, want new-release", link)
	}
	oldLink, err := os.Readlink(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if oldLink != "old-release" {
		t.Fatalf("displaced release link = %q, want old-release", oldLink)
	}
}
