package engine

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/formats/helm"
	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/state"
)

// helmChartPaths lists the chart archives a rendered repository publishes.
//
// A chart file is one that carries blob content; index.yaml and the browsable
// listing are generated, and there is nothing about them for a provenance file
// to attest to.
func helmChartPaths(artifact domain.RepositoryArtifact) []string {
	paths := make([]string, 0, len(artifact.Files))
	for _, file := range artifact.Files {
		if file.BlobSHA256 != "" && strings.HasSuffix(file.Path, ".tgz") {
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

// helmChartPathsFromLock lists the same archives from desired state, for the
// one caller that has the lock but not the rendered tree.
//
// It must agree with helmChartPaths: a plan is checked against the shape this
// produces and then applied against the shape the rendered tree produces, and a
// disagreement would refuse a publication for a difference nobody made. They
// agree because both are the visible package versions of one lock, laid out by
// the same rule the renderer uses.
func helmChartPathsFromLock(repository state.Repository, lock state.RepositoryLock) []string {
	seen := make(map[string]bool)
	paths := make([]string, 0, len(lock.PackageVersion))
	for _, packageVersion := range visiblePackageVersions(lock, repository) {
		for _, locked := range packageVersion.Blobs {
			chart := path.Join("charts", locked.SHA256, locked.Filename)
			if !seen[chart] {
				seen[chart] = true
				paths = append(paths, chart)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// helmProvenancePayload builds the document one chart's provenance signs.
//
// The bytes come from the workspace's own store rather than from the staged
// tree: the tree is what is about to be published, and a signature made over it
// would attest to whatever was written there. Reading the content-addressed
// blob means the provenance covers the bytes the lock pinned.
func helmProvenancePayload(artifact domain.RepositoryArtifact, chart string, sources map[string]string) ([]byte, error) {
	digest := ""
	for _, file := range artifact.Files {
		if file.Path == chart {
			digest = file.BlobSHA256
			break
		}
	}
	if digest == "" {
		return nil, fmt.Errorf("repository has no chart at %q to sign", chart)
	}
	source, exists := sources[digest]
	if !exists {
		return nil, fmt.Errorf("chart %q has no stored content to build provenance from", chart)
	}
	file, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	// The published basename is what `helm verify` looks itself up by, and it is
	// the archive's own name rather than the path it is served at.
	return helm.ProvenancePayload(path.Base(chart), file, info.Size())
}
