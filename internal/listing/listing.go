// Package listing renders the human-readable index a repository serves
// alongside its machine-readable one.
//
// It exists because a package repository is otherwise opaque: a client knows
// how to read dists/ or repodata/, and a person visiting the URL sees a 404.
// The page answers what a person actually arrives wanting — what is in here,
// how do I install it, and is it signed — from the same facts the machine index
// is built from, so the two cannot disagree about what was published.
package listing

import (
	"bytes"
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Filename is where the page is published. It is the directory index, so a
// browser reaching the repository root finds it without being told.
const Filename = "index.html"

// Artifact is one published file as the page shows it.
type Artifact struct {
	Name         string
	Version      string
	Architecture string
	// Path is relative to the repository root, and is what a link points at.
	Path   string
	Size   int64
	SHA256 string
}

// Signing describes how a client verifies the repository, or reports that
// nothing does.
type Signing struct {
	// Fingerprint of the active signing key.
	Fingerprint string
	// KeyPath is the file a client installs, relative to the repository root.
	KeyPath string
	// Algorithm names the scheme, so a reader can tell an OpenPGP repository
	// from one apk verifies with a bare RSA key.
	Algorithm string
}

// Page is everything the listing shows.
type Page struct {
	// Repository is the configured name, used as the page title.
	Repository string
	// Format is the ecosystem, shown so a visitor knows what they are looking at.
	Format string
	// Endpoint is the public URL, which install instructions are written
	// against. Empty for a repository published to a directory, where no URL is
	// known and instructions are omitted rather than guessed.
	Endpoint string
	// Install is the commands a user runs, in order.
	Install []string
	// Signing is nil when the repository is unsigned, which the page states
	// plainly rather than leaving to be inferred from an absence.
	Signing     *Signing
	Artifacts   []Artifact
	GeneratedAt time.Time
}

// Render produces the page. The same inputs always produce the same bytes:
// a repository is content-addressed, and a listing that varied would change the
// tree without anything having been published.
func Render(page Page) []byte {
	artifacts := append([]Artifact(nil), page.Artifacts...)
	// Newest version first within a package, which is the order someone
	// scanning for "what is the current release" reads in.
	sort.SliceStable(artifacts, func(left, right int) bool {
		if artifacts[left].Name != artifacts[right].Name {
			return artifacts[left].Name < artifacts[right].Name
		}
		if artifacts[left].Version != artifacts[right].Version {
			return artifacts[left].Version > artifacts[right].Version
		}
		return artifacts[left].Path < artifacts[right].Path
	})

	var document bytes.Buffer
	document.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	document.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&document, "<title>%s</title>\n", escape(page.Repository))
	document.WriteString("<style>\n" + pageStyle + "</style>\n</head>\n<body>\n")

	fmt.Fprintf(&document, "<h1>%s</h1>\n", escape(page.Repository))
	fmt.Fprintf(&document, "<p class=\"lede\">%s repository", escape(strings.ToUpper(page.Format)))
	if page.Endpoint != "" {
		fmt.Fprintf(&document, " at <code>%s</code>", escape(page.Endpoint))
	}
	document.WriteString("</p>\n")

	writeSigning(&document, page.Signing)
	writeInstall(&document, page.Install)
	writeArtifacts(&document, artifacts)

	fmt.Fprintf(&document, "<footer>%d %s, generated %s. Every artifact is pinned by SHA-256 in a reviewed lock before publication.</footer>\n",
		len(artifacts), plural(len(artifacts), "artifact", "artifacts"),
		escape(page.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")))
	document.WriteString("<script>\n" + pageScript + "</script>\n</body>\n</html>\n")
	return document.Bytes()
}

func writeSigning(document *bytes.Buffer, signing *Signing) {
	if signing == nil {
		document.WriteString("<div class=\"note unsigned\"><strong>This repository is not signed.</strong> " +
			"Nothing verifies what you install from it, so a client will either refuse it or has been told not to check.</div>\n")
		return
	}
	document.WriteString("<div class=\"note signed\"><strong>Signed.</strong> ")
	fmt.Fprintf(document, "Verified with the %s key <code>%s</code>",
		escape(signing.Algorithm), escape(signing.Fingerprint))
	if signing.KeyPath != "" {
		fmt.Fprintf(document, ", published at <a href=\"%s\">%s</a>", escape(signing.KeyPath), escape(signing.KeyPath))
	}
	document.WriteString(".</div>\n")
}

func writeInstall(document *bytes.Buffer, steps []string) {
	if len(steps) == 0 {
		return
	}
	document.WriteString("<h2>Install</h2>\n")
	// The button copies the plain text; only what is shown is marked up, so a
	// paste never carries the colouring.
	command := strings.Join(steps, "\n")
	document.WriteString("<div class=\"snippet\">")
	fmt.Fprintf(document, "<button class=\"copy\" data-copy=\"%s\">Copy</button>", escape(command))
	document.WriteString("<pre><code class=\"shell\">")
	for index, step := range steps {
		if index > 0 {
			document.WriteString("\n")
		}
		document.WriteString(highlightShell(step))
	}
	document.WriteString("</code></pre></div>\n")
}

func writeArtifacts(document *bytes.Buffer, artifacts []Artifact) {
	document.WriteString("<h2>Packages</h2>\n")
	if len(artifacts) == 0 {
		document.WriteString("<p class=\"empty\">Nothing has been published yet.</p>\n")
		return
	}
	document.WriteString("<table id=\"artifacts\">\n<thead><tr>")
	for index, column := range []string{"Package", "Version", "Arch", "Size", "SHA-256"} {
		// Every column sorts; the numeric one has to sort by its value rather
		// than by the text a reader sees.
		kind := "text"
		if column == "Size" {
			kind = "number"
		}
		fmt.Fprintf(document, "<th data-column=\"%d\" data-sort=\"%s\">%s</th>", index, kind, column)
	}
	document.WriteString("</tr></thead>\n<tbody>\n")
	for _, artifact := range artifacts {
		document.WriteString("<tr>")
		fmt.Fprintf(document, "<td><a href=\"%s\">%s</a></td>", escape(artifact.Path), escape(artifact.Name))
		fmt.Fprintf(document, "<td>%s</td>", escape(artifact.Version))
		fmt.Fprintf(document, "<td>%s</td>", escape(defaulted(artifact.Architecture, "any")))
		fmt.Fprintf(document, "<td class=\"size\" data-value=\"%d\">%s</td>", artifact.Size, escape(humanSize(artifact.Size)))
		fmt.Fprintf(document, "<td class=\"digest\"><button class=\"copy\" data-copy=\"%s\" title=\"%s\">%s…</button></td>",
			escape(artifact.SHA256), escape(artifact.SHA256), escape(shorten(artifact.SHA256)))
		document.WriteString("</tr>\n")
	}
	document.WriteString("</tbody>\n</table>\n")
}

// humanSize renders bytes the way a person reads them, in binary units because
// that is what every package manager reports.
func humanSize(size int64) string {
	if size < 1024 {
		return strconv.FormatInt(size, 10) + " B"
	}
	value := float64(size)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= 1024
		if value < 1024 {
			if value < 10 {
				return strconv.FormatFloat(value, 'f', 1, 64) + " " + unit
			}
			return strconv.FormatFloat(value, 'f', 0, 64) + " " + unit
		}
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + " PiB"
}

func shorten(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

func defaulted(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func plural(count int, singular, many string) string {
	if count == 1 {
		return singular
	}
	return many
}

func escape(value string) string { return html.EscapeString(value) }
