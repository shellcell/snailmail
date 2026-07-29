package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/listing"
	"github.com/shellcell/snailmail/internal/state"
)

// SiteIndexRequest asks for the workspace overview page.
type SiteIndexRequest struct {
	Root string
	// Title and Description head the page. Both default to something derived
	// from the workspace, because a site with no name is harder to recognise
	// than one named after the workspace that produces it.
	Title       string
	Description string
	// Output is where the page is written. Empty means the directory every
	// local repository is published under, which is the only place the page's
	// relative links resolve from.
	Output string
}

type SiteIndexResult struct {
	// Path is where the page was written.
	Path string
	// Repositories and Packages are what it describes, reported so a caller can
	// tell an overview of an empty workspace from one that failed to see it.
	Repositories int
	Packages     int
}

// SiteIndex writes the page that sits above the repositories.
//
// It is read-only with respect to published state: it reports what the locks
// already say, publishes nothing, and records nothing. That is deliberate — the
// overview is a view of the workspace, and a view that could change what it is
// describing would be a second source of truth for what has been published.
func SiteIndex(ctx context.Context, request SiteIndexRequest) (SiteIndexResult, error) {
	root, err := workspaceRoot(request.Root)
	if err != nil {
		return SiteIndexResult{}, err
	}
	unlock, err := state.AcquireWorkspaceLock(root)
	if err != nil {
		return SiteIndexResult{}, err
	}
	defer unlock()
	manifest, err := state.LoadManifest(root)
	if err != nil {
		return SiteIndexResult{}, err
	}
	page := listing.SitePage{
		Title:       defaultedString(request.Title, manifest.Workspace.Name),
		Description: request.Description,
	}
	// latest[package][repository] is the newest version that repository carries,
	// compared by that format's own ordering rather than as text: 1.10 is newer
	// than 1.9 everywhere except in a string sort.
	latest := map[string]map[string]string{}

	for _, name := range state.RepositoryNames(manifest) {
		if err := ctx.Err(); err != nil {
			return SiteIndexResult{}, err
		}
		repository := manifest.Repositories[name]
		selected, err := formats.For(repository.Format)
		if err != nil {
			return SiteIndexResult{}, err
		}
		lock, err := state.LoadLock(root, repository)
		if err != nil {
			return SiteIndexResult{}, err
		}
		if err := state.ValidateLock(lock, name, repository.Format); err != nil {
			return SiteIndexResult{}, err
		}
		page.Repositories = append(page.Repositories, listing.SiteRepository{
			Name: name, Format: repository.Format, Signed: len(repository.SigningKeys) != 0,
		})
		for _, packageVersion := range visiblePackageVersions(lock, repository) {
			newer, err := isNewerVersion(selected, latest[packageVersion.Package][name], packageVersion.Version)
			if err != nil {
				return SiteIndexResult{}, fmt.Errorf("repository %q package %q: %w", name, packageVersion.Package, err)
			}
			if !newer {
				continue
			}
			if latest[packageVersion.Package] == nil {
				latest[packageVersion.Package] = map[string]string{}
			}
			latest[packageVersion.Package][name] = packageVersion.Version
		}
	}

	names := make([]string, 0, len(latest))
	for name := range latest {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		page.Tools = append(page.Tools, listing.SiteTool{Name: name, Latest: latest[name]})
	}

	destination, err := siteIndexPath(root, request.Output, manifest)
	if err != nil {
		return SiteIndexResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return SiteIndexResult{}, err
	}
	if err := os.WriteFile(destination, listing.RenderSite(page), 0o644); err != nil {
		return SiteIndexResult{}, err
	}
	return SiteIndexResult{Path: destination, Repositories: len(page.Repositories), Packages: len(page.Tools)}, nil
}

// isNewerVersion reports whether candidate should replace current, treating an
// unset current as always replaceable.
func isNewerVersion(format formats.Format, current, candidate string) (bool, error) {
	if current == "" {
		return true, nil
	}
	order, err := format.CompareVersions(candidate, current)
	if err != nil {
		return false, err
	}
	return order > 0, nil
}

// siteIndexPath decides where the overview goes.
//
// Its links are relative — each cell points at <repository>/ — so it only works
// from the directory the repositories are published under. Where every local
// repository shares one, that is not a guess and the caller need not supply it;
// where they do not, there is no such directory and refusing is better than
// writing a page whose every link is broken.
func siteIndexPath(root, output string, manifest state.Manifest) (string, error) {
	if output != "" {
		if filepath.IsAbs(output) {
			return output, nil
		}
		return filepath.Join(root, output), nil
	}
	parent := ""
	for _, name := range state.RepositoryNames(manifest) {
		repository := manifest.Repositories[name]
		if repository.Host.Type != "local" {
			continue
		}
		candidate := filepath.Dir(filepath.Clean(repository.Host.Path))
		if parent == "" {
			parent = candidate
			continue
		}
		if candidate != parent {
			return "", errors.New("local repositories are published under different directories; pass --output to say where the index belongs")
		}
	}
	if parent == "" || parent == "." || parent == string(filepath.Separator) {
		return "", errors.New("no shared publication directory to write the index into; pass --output")
	}
	return filepath.Join(root, parent, listing.Filename), nil
}

func defaultedString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
