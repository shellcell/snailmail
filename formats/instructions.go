package formats

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/listing"
)

// InstallSteps are the commands a person runs to consume a repository, written
// against the URL it is actually served from.
//
// They live here rather than in each format because they are the one thing on a
// listing that is about the reader rather than about the artifacts, and because
// a signed repository and an unsigned one need genuinely different instructions:
// the signed form installs a key first, and the unsigned form has to tell the
// client not to check — which is worth seeing written out before it is pasted.
func InstallSteps(format string, repository Repository) []string {
	endpoint := strings.TrimRight(repository.Endpoint, "/")
	if endpoint == "" {
		// A repository published to a directory has no URL to install from, and
		// a guessed one would be worse than none.
		return nil
	}
	switch format {
	case "deb":
		suite := defaulted(repository.Suite, "stable")
		component := defaulted(repository.Component, "main")
		if repository.Signing == nil {
			return []string{
				"# This repository is unsigned; apt will not verify what it installs.",
				"echo 'deb [trusted=yes] " + endpoint + " " + suite + " " + component + "' \\",
				"  | sudo tee /etc/apt/sources.list.d/" + listName(repository) + ".list",
				"sudo apt-get update && sudo apt-get install <package>",
			}
		}
		keyring := "/usr/share/keyrings/" + listName(repository) + ".gpg"
		return []string{
			"curl -fsSL " + endpoint + "/" + repository.Signing.KeyPath + " \\",
			"  | sudo tee " + keyring + " > /dev/null",
			"echo 'deb [signed-by=" + keyring + "] " + endpoint + " " + suite + " " + component + "' \\",
			"  | sudo tee /etc/apt/sources.list.d/" + listName(repository) + ".list",
			"sudo apt-get update && sudo apt-get install <package>",
		}
	case "rpm":
		lines := []string{
			"sudo tee /etc/yum.repos.d/" + listName(repository) + ".repo > /dev/null <<'REPO'",
			"[" + listName(repository) + "]",
			"name=" + listName(repository),
			"baseurl=" + endpoint,
			"enabled=1",
			// gpgcheck covers signatures inside each package, which are made by
			// whoever built it rather than by this repository.
			"gpgcheck=0",
		}
		if repository.Signing == nil {
			lines = append(lines, "repo_gpgcheck=0", "REPO", "sudo dnf install <package>")
			return append([]string{"# This repository is unsigned; nothing verifies its metadata."}, lines...)
		}
		lines = append(lines,
			"repo_gpgcheck=1",
			"gpgkey="+endpoint+"/"+repository.Signing.KeyPath,
			"REPO",
			"sudo dnf install <package>")
		return lines
	case "apk":
		if repository.Signing == nil {
			return []string{
				"# This repository is unsigned; --allow-untrusted disables the check.",
				"echo " + endpoint + " | sudo tee -a /etc/apk/repositories",
				"sudo apk add --allow-untrusted <package>",
			}
		}
		// apk finds the key by filename alone, so it must land under exactly the
		// name the index names.
		return []string{
			"sudo curl -fsSL -o /etc/apk/keys/" + path.Base(repository.Signing.KeyPath) + " \\",
			"  " + endpoint + "/" + repository.Signing.KeyPath,
			"echo " + endpoint + " | sudo tee -a /etc/apk/repositories",
			"sudo apk add <package>",
		}
	case "helm":
		name := listName(repository)
		if repository.Signing == nil {
			return []string{
				"# This repository is unsigned; nothing verifies the charts you install.",
				"helm repo add " + name + " " + endpoint,
				"helm repo update",
				"helm install <release> " + name + "/<chart>",
			}
		}
		// helm reads a binary OpenPGP keyring from a file it is pointed at,
		// rather than a system trust store, so the key is downloaded and named
		// on the command that uses it.
		keyring := "~/.snailmail/" + name + ".gpg"
		return []string{
			"mkdir -p ~/.snailmail",
			"curl -fsSL " + endpoint + "/" + repository.Signing.KeyPath + " -o " + keyring,
			"helm repo add " + name + " " + endpoint,
			"helm repo update",
			"helm install <release> " + name + "/<chart> --verify --keyring " + keyring,
		}
	case "pypi":
		return []string{"pip install --index-url " + endpoint + "/simple <package>"}
	case "raw":
		return []string{
			"curl -LO " + endpoint + "/<name>/<version>/<file>",
			"curl -LO " + endpoint + "/SHA256SUMS",
			"sha256sum -c --ignore-missing SHA256SUMS",
		}
	default:
		return nil
	}
}

// listName is the repository's own name where it has one, and a neutral default
// where a format is rendered outside a workspace.
func listName(repository Repository) string {
	if repository.Name == "" {
		return "snailmail"
	}
	return repository.Name
}

func defaulted(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// AppendListing appends the browsable index to a rendered repository.
//
// It is exported because three formats are built by the engine directly rather
// than through the format interface, and a listing that only some repositories
// carried would be worse than none: a visitor would read its absence as the
// repository being empty.
//
// It wraps each format's own render rather than living inside them: the page is
// the same for every ecosystem, and a format subpackage cannot reach this one
// without the import cycle the interface exists to avoid.
//
// The artifacts it lists are the files carrying blob content — the packages —
// found by matching each blob's digest to where the render placed it. Index
// files are generated and are not what a visitor came for.
func AppendListing(artifact domain.RepositoryArtifact, format string, options BuildOptions, blobs []domain.Blob) (domain.RepositoryArtifact, error) {
	placed := make(map[string]string, len(artifact.Files))
	for _, file := range artifact.Files {
		if file.BlobSHA256 != "" {
			placed[file.BlobSHA256] = file.Path
		}
		if file.Path == listing.Filename {
			return domain.RepositoryArtifact{}, fmt.Errorf("format %q already renders %s", format, listing.Filename)
		}
	}
	artifacts := make([]listing.Artifact, 0, len(blobs))
	seen := make(map[string]bool, len(blobs))
	for _, blob := range blobs {
		path, published := placed[blob.SHA256]
		if !published || seen[path] {
			continue
		}
		seen[path] = true
		artifacts = append(artifacts, listing.Artifact{
			Name: blob.Facts.Name, Version: blob.Facts.Version, Architecture: blob.Facts.Architecture,
			Path: path, Size: blob.Size, SHA256: blob.SHA256, Published: blob.Added,
		})
	}
	page := listing.Page{
		Repository: listName(options.Repository), Format: format,
		Endpoint: options.Repository.Endpoint, Install: InstallSteps(format, options.Repository),
		Artifacts: artifacts,
	}
	if signing := options.Repository.Signing; signing != nil {
		page.Signing = &listing.Signing{
			Fingerprint: signing.Fingerprint, Algorithm: signing.Algorithm, KeyPath: signing.KeyPath,
		}
	}
	files := append([]domain.File(nil), artifact.Files...)
	files = append(files, domain.File{Path: listing.Filename, Content: listing.Render(page)})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	artifact.Files = files
	return artifact, nil
}
