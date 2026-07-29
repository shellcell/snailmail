package listing

import (
	"bytes"
	"fmt"
	"sort"
)

// SiteRepository is one repository as the overview shows it.
type SiteRepository struct {
	// Name is both the configured name and the directory the page links to.
	Name   string
	Format string
	// Signed reports whether a client can verify this repository, which is the
	// one property worth seeing before choosing which one to install from.
	Signed bool
}

// SiteTool is one package across every repository that carries it.
type SiteTool struct {
	Name string
	// Latest maps a repository name to the newest version published there.
	// A repository absent from the map does not carry this package, which the
	// matrix shows as a gap rather than as a zero.
	Latest map[string]string
}

// SitePage is the workspace overview: which tools are published, and where.
type SitePage struct {
	Title string
	// Description is the one line under the title, left to the operator because
	// what a site is for is not something a lock records.
	Description  string
	Repositories []SiteRepository
	Tools        []SiteTool
}

// RenderSite produces the overview page.
//
// It answers the question a repository listing cannot: someone arriving at the
// site knows which tool they want, not which ecosystem directory it lives in.
// A matrix of tools against repositories puts both on one screen, and shows the
// gaps — a release that reached apt but not alpine is visible as an empty cell
// rather than as a page that never mentions it.
func RenderSite(page SitePage) []byte {
	repositories := append([]SiteRepository(nil), page.Repositories...)
	sort.Slice(repositories, func(left, right int) bool { return repositories[left].Name < repositories[right].Name })
	tools := append([]SiteTool(nil), page.Tools...)
	sort.Slice(tools, func(left, right int) bool { return tools[left].Name < tools[right].Name })

	var document bytes.Buffer
	document.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	document.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&document, "<title>%s</title>\n", escape(page.Title))
	document.WriteString("<style>\n" + pageStyle + "</style>\n</head>\n<body>\n")

	fmt.Fprintf(&document, "<h1>%s</h1>\n", escape(page.Title))
	if page.Description != "" {
		fmt.Fprintf(&document, "<p class=\"lede\">%s</p>\n", escape(page.Description))
	}

	writeMatrix(&document, repositories, tools)
	writeRepositories(&document, repositories)

	// No generation time, for the same reason a repository listing carries
	// none: rewriting the page when nothing was published is churn, not news.
	fmt.Fprintf(&document, "<footer>%d %s across %d %s.</footer>\n",
		len(tools), plural(len(tools), "package", "packages"),
		len(repositories), plural(len(repositories), "repository", "repositories"))
	document.WriteString("<script>\n" + pageScript + "</script>\n</body>\n</html>\n")
	return document.Bytes()
}

func writeMatrix(document *bytes.Buffer, repositories []SiteRepository, tools []SiteTool) {
	document.WriteString("<h2>Published</h2>\n")
	if len(tools) == 0 || len(repositories) == 0 {
		document.WriteString("<p class=\"empty\">Nothing has been published yet.</p>\n")
		return
	}
	document.WriteString("<div class=\"table-scroll\">\n<table id=\"matrix\">\n<thead><tr>")
	document.WriteString("<th data-column=\"0\" data-sort=\"text\">Package</th>")
	for index, repository := range repositories {
		// The column header is the repository, and it links there: the cell
		// below it says which version, and the header says where to get it.
		fmt.Fprintf(document, "<th data-column=\"%d\" data-sort=\"text\"><a href=\"%s/\">%s</a> <span class=\"muted\">%s</span></th>",
			index+1, escape(repository.Name), escape(repository.Name), escape(repository.Format))
	}
	document.WriteString("</tr></thead>\n<tbody>\n")
	for _, tool := range tools {
		document.WriteString("<tr>")
		fmt.Fprintf(document, "<td class=\"tool\">%s</td>", escape(tool.Name))
		for _, repository := range repositories {
			version, carried := tool.Latest[repository.Name]
			if !carried {
				document.WriteString("<td class=\"absent\">&mdash;</td>")
				continue
			}
			fmt.Fprintf(document, "<td class=\"version\"><a href=\"%s/\">%s</a></td>",
				escape(repository.Name), escape(version))
		}
		document.WriteString("</tr>\n")
	}
	document.WriteString("</tbody>\n</table>\n</div>\n")
}

func writeRepositories(document *bytes.Buffer, repositories []SiteRepository) {
	if len(repositories) == 0 {
		return
	}
	document.WriteString("<h2>Repositories</h2>\n<ul class=\"repositories\">\n")
	for _, repository := range repositories {
		fmt.Fprintf(document, "<li><a href=\"%s/\">%s</a> <span class=\"muted\">%s</span> ",
			escape(repository.Name), escape(repository.Name), escape(repository.Format))
		if repository.Signed {
			document.WriteString("<span class=\"badge signed\">signed</span>")
		} else {
			document.WriteString("<span class=\"badge unsigned\">unsigned</span>")
		}
		document.WriteString("</li>\n")
	}
	document.WriteString("</ul>\n")
}
