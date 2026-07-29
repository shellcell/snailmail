package formats

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

// PublishedPaths says where artifacts will be served from without rendering
// anything, so a plan can be checked against the signing shape its repository
// will produce. Build says where they are actually served from.
//
// If the two ever disagree, a plan validates against one shape and applies
// against another, and a publication is refused for a difference nobody made.
// They agree by construction today; this is what keeps it that way.
func TestPublishedPathsMatchTheRender(t *testing.T) {
	for _, name := range Names() {
		signing, err := SignerFor(name)
		if err != nil {
			continue
		}
		blobs := signableBlobs(t, name)
		if len(blobs) == 0 {
			continue
		}
		artifacts := make([]PublishedArtifact, 0, len(blobs))
		for _, blob := range blobs {
			artifacts = append(artifacts, PublishedArtifact{Filename: blob.Filename, SHA256: blob.SHA256})
		}
		predicted := signing.PublishedPaths(artifacts)
		if len(predicted) == 0 {
			// A format whose signing shape does not depend on which artifacts
			// there are has nothing to predict, and nothing to disagree about.
			continue
		}

		selected, err := For(name)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := selected.Build(blobs, BuildOptions{GeneratedAt: time.Unix(1, 0).UTC()})
		if err != nil {
			t.Fatalf("format %q: %v", name, err)
		}
		rendered := make([]string, 0, len(artifact.Files))
		for _, file := range artifact.Files {
			if file.BlobSHA256 != "" {
				rendered = append(rendered, file.Path)
			}
		}
		sort.Strings(rendered)
		if !reflect.DeepEqual(predicted, rendered) {
			t.Errorf("format %q predicts %v but renders %v", name, predicted, rendered)
		}
	}
}

// signableBlobs is a minimal set of artifacts for a format whose signing shape
// depends on them. Only Helm has one today; the loop above skips the rest.
func signableBlobs(t *testing.T, name string) []domain.Blob {
	t.Helper()
	if name != "helm" {
		return nil
	}
	return []domain.Blob{
		{
			Filename: "demo-1.2.3.tgz", Size: 10,
			SHA256: "1abd1906c4179e52517dfdd671dea2ec1ea7c3d6ee7e16f68fbe27e20975c469",
			Facts: domain.PackageFacts{
				Name: "demo", Version: "1.2.3",
				Fields: map[string]string{"apiVersion": "v2"},
			},
		},
		{
			Filename: "demo-2.0.0.tgz", Size: 12,
			SHA256: "2abd1906c4179e52517dfdd671dea2ec1ea7c3d6ee7e16f68fbe27e20975c469",
			Facts: domain.PackageFacts{
				Name: "demo", Version: "2.0.0",
				Fields: map[string]string{"apiVersion": "v2"},
			},
		},
	}
}
