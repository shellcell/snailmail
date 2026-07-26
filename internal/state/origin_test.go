package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLockMigratesSchemaOneWithoutOrigins(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "schema_version = 1\nrepository = \"python\"\npackage_version = []\nplacement = []\n"
	if err := os.WriteFile(filepath.Join(root, "repos", "python.lock.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := LoadLock(root, Repository{Lock: "repos/python.lock.toml"})
	if err != nil {
		t.Fatal(err)
	}
	if lock.SchemaVersion != LockSchema {
		t.Fatalf("migrated lock schema = %d", lock.SchemaVersion)
	}
}

func TestValidateLockRejectsUnsafeArtifactOrigin(t *testing.T) {
	lock := RepositoryLock{
		SchemaVersion: LockSchema, Repository: "python",
		PackageVersion: []PackageVersion{{
			Package: "demo", Version: "1.2.3", State: "draft",
			Blobs: []LockedBlob{{
				Filename: "demo-1.2.3-py3-none-any.whl", Size: 1, SHA256: strings.Repeat("a", 64),
				Origin: &ArtifactOrigin{Kind: "https", URL: "https://user:secret@example.test/demo.whl"},
			}},
		}},
		Placement: []Placement{{Package: "demo", Version: "1.2.3", Track: "stable"}},
	}
	if err := ValidateLock(lock, "python", "pypi"); err == nil {
		t.Fatal("lock accepted an unsafe artifact origin")
	}
	lock.PackageVersion[0].Blobs[0].Origin.URL = "https://127.0.0.1/demo.whl"
	if err := ValidateLock(lock, "python", "pypi"); err == nil {
		t.Fatal("lock accepted a private artifact origin")
	}
	lock.PackageVersion[0].Blobs[0].Origin.URL = "https://downloads.example/demo.whl"
	if err := ValidateLock(lock, "python", "pypi"); err != nil {
		t.Fatalf("safe artifact origin rejected: %v", err)
	}
}

func TestOriginRoundTripAndSchemaBoundary(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	repository := Repository{Lock: "repos/python.lock.toml"}
	lock := RepositoryLock{
		Repository: "python",
		PackageVersion: []PackageVersion{{Package: "demo", Version: "1.2.3", State: "draft", Blobs: []LockedBlob{{
			Filename: "demo.whl", Size: 1, SHA256: strings.Repeat("a", 64), Origin: &ArtifactOrigin{Kind: "https", URL: "https://downloads.example/demo.whl"},
		}}}},
		Placement: []Placement{{Package: "demo", Version: "1.2.3", Track: "stable"}},
	}
	if err := WriteLock(root, repository, lock); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadLock(root, repository)
	if err != nil || loaded.PackageVersion[0].Blobs[0].Origin == nil || loaded.PackageVersion[0].Blobs[0].Origin.URL != "https://downloads.example/demo.whl" {
		t.Fatalf("origin round trip=%#v err=%v", loaded, err)
	}
	name := filepath.Join(root, "repos", "python.lock.toml")
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), "schema_version = 2", "schema_version = 1", 1))
	if err := os.WriteFile(name, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLock(root, repository); err == nil {
		t.Fatal("schema-one lock accepted schema-two origin fields")
	}
}
