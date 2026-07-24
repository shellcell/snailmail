package pypi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/internal/domain"
)

const FormatID = "pypi/v1"

var normalizePattern = regexp.MustCompile(`[-_.]+`)

type project struct {
	distributions []domain.Blob
}

// NormalizeName implements the PEP 503 project-name normalization rule.
func NormalizeName(name string) string {
	return strings.ToLower(normalizePattern.ReplaceAllString(name, "-"))
}

// Build renders a PEP 503 repository description without performing I/O.
func Build(blobs []domain.Blob) (domain.RepositoryArtifact, error) {
	if len(blobs) == 0 {
		return domain.RepositoryArtifact{}, fmt.Errorf("at least one PyPI distribution is required")
	}
	projects := make(map[string]*project)
	for _, blob := range blobs {
		if err := validateBlob(blob); err != nil {
			return domain.RepositoryArtifact{}, err
		}
		if blob.Filename == "" || path.Base(blob.Filename) != blob.Filename {
			return domain.RepositoryArtifact{}, fmt.Errorf("invalid distribution filename %q", blob.Filename)
		}
		name := NormalizeName(blob.Facts.Name)
		if name == "" {
			return domain.RepositoryArtifact{}, fmt.Errorf("distribution %q has no project name", blob.Filename)
		}
		entry := projects[name]
		if entry == nil {
			entry = &project{}
			projects[name] = entry
		}
		entry.distributions = append(entry.distributions, blob)
	}

	projectNames := make([]string, 0, len(projects))
	for name := range projects {
		projectNames = append(projectNames, name)
	}
	sort.Strings(projectNames)

	var files []domain.File
	rootLinks := make([]string, 0, len(projectNames))
	verification := make([]domain.VerificationCase, 0)
	seenCases := make(map[string]bool)
	for _, name := range projectNames {
		entry := projects[name]
		sort.Slice(entry.distributions, func(i, j int) bool {
			left, right := entry.distributions[i], entry.distributions[j]
			if left.Filename != right.Filename {
				return left.Filename < right.Filename
			}
			return left.SHA256 < right.SHA256
		})
		rootLinks = append(rootLinks, fmt.Sprintf(`<a href="%s/">%s</a>`, url.PathEscape(name), html.EscapeString(name)))

		links := make([]string, 0, len(entry.distributions))
		seenFiles := make(map[string]bool)
		for _, blob := range entry.distributions {
			destination := path.Join("packages", blob.SHA256, blob.Filename)
			if seenFiles[destination] {
				continue
			}
			files = append(files, domain.File{
				Path:       destination,
				Size:       blob.Size,
				SHA256:     blob.SHA256,
				BlobSHA256: blob.SHA256,
			})
			seenFiles[destination] = true
			href := "../../packages/" + blob.SHA256 + "/" + url.PathEscape(blob.Filename) + "#sha256=" + blob.SHA256
			attribute := ""
			if blob.Facts.RequiresPython != "" {
				attribute = ` data-requires-python="` + html.EscapeString(blob.Facts.RequiresPython) + `"`
			}
			links = append(links, fmt.Sprintf(`<a href="%s"%s>%s</a>`, href, attribute, html.EscapeString(blob.Filename)))

			caseKey := name + "\x00" + blob.Facts.Version
			if !seenCases[caseKey] {
				verification = append(verification, domain.VerificationCase{Project: name, Version: blob.Facts.Version})
				seenCases[caseKey] = true
			}
		}
		files = append(files, generatedFile(path.Join("simple", name, "index.html"), htmlPage(name, links)))
	}
	files = append(files, generatedFile(path.Join("simple", "index.html"), htmlPage("Simple index", rootLinks)))
	sort.Slice(verification, func(i, j int) bool {
		if verification[i].Project != verification[j].Project {
			return verification[i].Project < verification[j].Project
		}
		return verification[i].Version < verification[j].Version
	})

	return domain.RepositoryArtifact{
		Format:            FormatID,
		Files:             files,
		Install:           domain.InstallSpec{Kind: "pypi", IndexPath: "simple/"},
		VerificationCases: verification,
	}, nil
}

func validateBlob(blob domain.Blob) error {
	if !IsDistributionFilename(blob.Filename) || !packageNamePattern.MatchString(blob.Facts.Name) || !versionPattern.MatchString(blob.Facts.Version) {
		return fmt.Errorf("distribution %q has invalid package facts", blob.Filename)
	}
	if blob.Size < 0 {
		return fmt.Errorf("distribution %q has a negative size", blob.Filename)
	}
	decoded, err := hex.DecodeString(blob.SHA256)
	if err != nil || len(decoded) != sha256.Size || blob.SHA256 != strings.ToLower(blob.SHA256) {
		return fmt.Errorf("distribution %q has an invalid SHA-256", blob.Filename)
	}
	if blob.Facts.Version == "" {
		return fmt.Errorf("distribution %q has no version", blob.Filename)
	}
	return nil
}

func generatedFile(name string, content []byte) domain.File {
	return domain.File{Path: name, Content: content}
}

func htmlPage(title string, links []string) []byte {
	var page strings.Builder
	page.WriteString("<!DOCTYPE html>\n<html>\n  <head>\n")
	page.WriteString(`    <meta name="pypi:repository-version" content="1.0">`)
	page.WriteString("\n    <title>")
	page.WriteString(html.EscapeString(title))
	page.WriteString("</title>\n  </head>\n  <body>\n")
	for _, link := range links {
		page.WriteString("    ")
		page.WriteString(link)
		page.WriteString("<br>\n")
	}
	page.WriteString("  </body>\n</html>\n")
	return []byte(page.String())
}
