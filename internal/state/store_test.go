package state

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadManifestMigratesSchemaTwoToLocalBlobStore(t *testing.T) {
	root := t.TempDir()
	content := []byte(`schema_version = 2

[workspace]
name = "legacy-workspace"
`)
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != ManifestSchema || manifest.BlobStore.Type != "local" || !validSHA256(manifest.Workspace.ID) {
		t.Fatalf("unexpected schema-two migration %#v", manifest)
	}
}

func TestLoadManifestMigratesSchemaFourWithoutSigningKeys(t *testing.T) {
	root := t.TempDir()
	content := []byte(`schema_version = 4

[workspace]
name = "phase-two"
id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[blob_store]
type = "local"
`)
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != ManifestSchema || manifest.Keys == nil || len(manifest.Keys) != 0 {
		t.Fatalf("unexpected schema-four migration %#v", manifest)
	}
}

func TestValidateBlobStoreRejectsSecretsAndUnsafeConfiguration(t *testing.T) {
	for _, configuration := range []BlobStoreConfig{
		{Type: "local", Bucket: "unexpected"},
		{Type: "s3"},
		{Type: "s3", Bucket: "artifacts", Prefix: "../escape"},
		{Type: "s3", Bucket: "artifacts", Endpoint: "https://user:secret@example.test"},
		{Type: "s3", Bucket: "artifacts", Endpoint: "https://example.test?token=secret"},
	} {
		if err := ValidateBlobStore(configuration); err == nil {
			t.Fatalf("accepted invalid blob store %#v", configuration)
		}
	}
	valid := BlobStoreConfig{Type: "s3", Bucket: "artifacts", Prefix: "snailmail/blobs", Endpoint: "https://objects.example.test"}
	if err := ValidateBlobStore(valid); err != nil {
		t.Fatal(err)
	}
	encoded := strings.Join([]string{valid.Bucket, valid.Prefix, valid.Endpoint}, "\n")
	if strings.Contains(encoded, "secret") {
		t.Fatal("test configuration unexpectedly contains credential material")
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

func TestPrivateS3HostRequiresNonSecretBasicBrokerReference(t *testing.T) {
	repository := Repository{
		Format: "pypi", Visibility: "private",
		Host: HostConfig{
			Type: "s3", Bucket: "packages", CanonicalEndpoint: "https://packages.example/python",
			ReadAuth: "basic", CredentialBroker: "default",
		},
	}
	if err := validateRepositoryHost("python", repository); err != nil {
		t.Fatal(err)
	}
	repository.Host.CredentialBroker = ""
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("private S3 host accepted no credential broker")
	}
	repository.Visibility = "public"
	repository.Host.CredentialBroker = "default"
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("public S3 host accepted private credential configuration")
	}
}

func TestS3APIEndpointRequiresHTTPSOutsideLoopback(t *testing.T) {
	repository := Repository{
		Format: "pypi", Visibility: "public",
		Host: HostConfig{Type: "s3", Bucket: "packages", CanonicalEndpoint: "https://packages.example/python", Endpoint: "http://objects.example"},
	}
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("plaintext remote S3 API endpoint was accepted")
	}
	repository.Host.Endpoint = "http://127.0.0.1:9000"
	if err := validateRepositoryHost("python", repository); err != nil {
		t.Fatalf("loopback development endpoint rejected: %v", err)
	}
}

func TestS3ClientAndBlobEndpointsRequireHTTPSOutsideLoopback(t *testing.T) {
	repository := Repository{
		Format: "pypi", Visibility: "public",
		Host: HostConfig{Type: "s3", Bucket: "packages", CanonicalEndpoint: "http://packages.example/python"},
	}
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("plaintext public package endpoint was accepted")
	}
	if err := ValidateBlobStore(BlobStoreConfig{Type: "s3", Bucket: "packages", Endpoint: "http://objects.example"}); err == nil {
		t.Fatal("plaintext remote blob endpoint was accepted")
	}
	if err := ValidateBlobStore(BlobStoreConfig{Type: "s3", Bucket: "packages", Endpoint: "http://localhost:9000"}); err != nil {
		t.Fatalf("loopback blob endpoint rejected: %v", err)
	}
}

func TestGitHubPagesRequiresDistinctPublicPreviewSite(t *testing.T) {
	repository := Repository{
		Format: "pypi", Visibility: "public",
		Host: HostConfig{
			Type: "github-pages", Repository: "ShellCell/Python_Packages", Branch: "releases/pages",
			PreviewRepository: "ShellCell/Python_Packages.preview", PreviewBranch: "preview/pages",
			CanonicalEndpoint: "https://packages.example", PreviewEndpoint: "https://preview.example",
		},
	}
	if err := validateRepositoryHost("python", repository); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := writeInstallDocument(root, "python", repository); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstallDocument(root, "python", repository); err != nil {
		t.Fatal(err)
	}
	repository.Host.PreviewRepository = repository.Host.Repository
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("production Pages site was accepted as its own preview")
	}
	repository.Host.PreviewRepository = "shellcell/python_packages"
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("case-variant production Pages repository was accepted as preview")
	}
	repository.Host.PreviewRepository = "ShellCell/Python_Packages.preview"
	repository.Visibility = "private"
	if err := validateRepositoryHost("python", repository); err == nil {
		t.Fatal("private GitHub Pages repository was accepted")
	}
}

func TestRepositoryGateValidation(t *testing.T) {
	for _, policy := range []string{"auto", "pr", "approval"} {
		if !validGate(policy) {
			t.Fatalf("valid gate %q rejected", policy)
		}
	}
	for _, policy := range []string{"", "manual", "PR"} {
		if validGate(policy) {
			t.Fatalf("invalid gate %q accepted", policy)
		}
	}
}
