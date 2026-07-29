package engine

import (
	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/state"
)

// lockedArtifactPaths says where a repository's visible artifacts will be
// served from, without rendering anything.
//
// A plan is checked against the shape its repository will produce, and that
// happens before the tree is rebuilt. Formats that sign an index do not care;
// one that signs each artifact has to name them, and only the format knows
// where it puts them.
func lockedArtifactPaths(repository state.Repository, lock state.RepositoryLock) []string {
	signing, err := formats.SignerFor(repository.Format)
	if err != nil {
		return nil
	}
	artifacts := make([]formats.PublishedArtifact, 0, len(lock.PackageVersion))
	for _, packageVersion := range visiblePackageVersions(lock, repository) {
		for _, locked := range packageVersion.Blobs {
			artifacts = append(artifacts, formats.PublishedArtifact{
				Filename: locked.Filename, SHA256: locked.SHA256,
			})
		}
	}
	return signing.PublishedPaths(artifacts)
}
