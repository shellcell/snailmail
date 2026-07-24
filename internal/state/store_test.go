package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifestMigratesSchemaOneLocalOutput(t *testing.T) {
	root := t.TempDir()
	content := []byte(`schema_version = 1

[workspace]
name = "legacy-workspace"

[repo.python]
format = "pypi"
lock = "repos/python.lock.toml"
output = "public/python"
gate = "auto"
`)
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	repository := manifest.Repositories["python"]
	if manifest.SchemaVersion != ManifestSchema || repository.Host.Type != "local" || repository.Host.Path != "public/python" || repository.Visibility != "public" {
		t.Fatalf("unexpected migrated manifest %#v", manifest)
	}
}

func TestValidateInstallDocumentRejectsEndpointDrift(t *testing.T) {
	root := t.TempDir()
	repository := Repository{
		Format: "pypi", Visibility: "public",
		Host: HostConfig{Type: "s3", Bucket: "packages", CanonicalEndpoint: "https://packages.example/python"},
	}
	if err := writeInstallDocument(root, "python", repository); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstallDocument(root, "python", repository); err != nil {
		t.Fatal(err)
	}
	repository.Host.CanonicalEndpoint = "https://other.example/python"
	if err := ValidateInstallDocument(root, "python", repository); err == nil {
		t.Fatal("expected changed endpoint to invalidate generated install document")
	}
}
