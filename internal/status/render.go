package status

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/internal/state"
)

const SchemaVersion = 1

type InputRepository struct {
	Name       string
	Config     state.Repository
	Lock       state.RepositoryLock
	Records    []state.PublicationRecord
	Deployment state.DeploymentRecord
	Pending    bool
}

type Document struct {
	SchemaVersion int          `json:"schema_version"`
	Workspace     string       `json:"workspace"`
	GitRevision   string       `json:"git_revision"`
	Repositories  []Repository `json:"repositories"`
}

type Repository struct {
	Name       string    `json:"name"`
	Format     string    `json:"format"`
	Visibility string    `json:"visibility"`
	Gate       string    `json:"gate"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Packages   []Package `json:"packages"`
}

type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	State       string `json:"state"`
	PlanID      string `json:"plan_id,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
}

type Output struct {
	JSON []byte
	HTML []byte
}

func Render(workspace, gitRevision string, repositories []InputRepository) (Output, error) {
	sort.Slice(repositories, func(left, right int) bool { return repositories[left].Name < repositories[right].Name })
	document := Document{SchemaVersion: SchemaVersion, Workspace: workspace, GitRevision: gitRevision}
	for _, input := range repositories {
		repository := Repository{
			Name: input.Name, Format: input.Config.Format, Visibility: input.Config.Visibility,
			Gate: input.Config.Gate, Endpoint: publicEndpoint(input.Config),
		}
		active := make(map[string]bool)
		for _, placement := range input.Lock.Placement {
			if placement.Track != input.Config.Track || (input.Config.Format == "deb" && placement.Distro != input.Config.Suite) || (input.Config.Format != "deb" && placement.Distro != "") {
				continue
			}
			active[placement.Package+"\x00"+placement.Version] = true
		}
		published := make(map[string]state.PublicationRecord)
		for _, record := range input.Records {
			key := record.Package + "\x00" + record.Version
			published[key] = record
		}
		for _, version := range input.Lock.PackageVersion {
			key := version.Package + "\x00" + version.Version
			if !active[key] {
				continue
			}
			entry := Package{Name: version.Package, Version: version.Version, State: "missing"}
			if record, exists := published[key]; exists && equalDigests(record.BlobSHA256, version.Blobs) {
				entry.State = "unknown"
				entry.PlanID = record.PlanID
				entry.PublishedAt = record.RecordedAt
				if input.Deployment.TreeSHA256 == record.TreeSHA256 && input.Deployment.PlanID == record.PlanID {
					entry.State = "current"
				}
			} else if input.Pending {
				entry.State = "pending"
			} else if input.Deployment.TreeSHA256 != "" {
				entry.State = "lagging"
			}
			repository.Packages = append(repository.Packages, entry)
		}
		sort.Slice(repository.Packages, func(left, right int) bool {
			if repository.Packages[left].Name != repository.Packages[right].Name {
				return repository.Packages[left].Name < repository.Packages[right].Name
			}
			return repository.Packages[left].Version < repository.Packages[right].Version
		})
		document.Repositories = append(document.Repositories, repository)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return Output{}, err
	}
	encoded = append(encoded, '\n')
	var html bytes.Buffer
	if err := pageTemplate.Execute(&html, document); err != nil {
		return Output{}, err
	}
	return Output{JSON: encoded, HTML: html.Bytes()}, nil
}

func publicEndpoint(repository state.Repository) string {
	if repository.Host.Type == "local" {
		return ""
	}
	return repository.Host.CanonicalEndpoint
}

func equalDigests(recorded []string, blobs []state.LockedBlob) bool {
	expected := append([]string(nil), recorded...)
	actual := make([]string, 0, len(blobs))
	for _, blob := range blobs {
		actual = append(actual, blob.SHA256)
	}
	sort.Strings(expected)
	sort.Strings(actual)
	return strings.Join(expected, "\x00") == strings.Join(actual, "\x00")
}

func stateLabel(value string) string {
	switch value {
	case "current":
		return "Published"
	case "pending":
		return "Gate pending"
	case "missing":
		return "Not published"
	case "lagging":
		return "Behind desired state"
	case "unknown":
		return "Deployment unknown"
	default:
		return value
	}
}

var pageTemplate = template.Must(template.New("status").Funcs(template.FuncMap{"stateLabel": stateLabel}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Workspace}} package status</title>
  <style>
    :root{color-scheme:light;--paper:#f4f0e8;--ink:#17201d;--muted:#65716b;--line:#c8c2b6;--current:#176b4d;--pending:#a55f09;--missing:#8a3b32}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1120px;margin:auto;padding:56px 24px 80px}header{display:flex;align-items:end;justify-content:space-between;gap:24px;border-bottom:3px solid var(--ink);padding-bottom:18px;margin-bottom:36px}h1{font:700 clamp(34px,6vw,68px)/.95 Georgia,serif;letter-spacing:-.04em;margin:0}.revision{color:var(--muted);font-size:12px;word-break:break-all;text-align:right}.repository{margin:0 0 42px}.repository-head{display:flex;justify-content:space-between;align-items:baseline;gap:18px;border-bottom:1px solid var(--line);padding-bottom:8px}.repository h2{font:700 24px/1.2 Georgia,serif;margin:0}.meta{color:var(--muted);font-size:12px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}.state{font-weight:700}.state-current{color:var(--current)}.state-pending,.state-lagging{color:var(--pending)}.state-missing,.state-unknown{color:var(--missing)}a{color:inherit;text-underline-offset:3px}.empty{color:var(--muted);padding:20px 8px;border-bottom:1px solid var(--line)}@media(max-width:640px){main{padding:32px 16px}header{display:block}.revision{text-align:left;margin-top:14px}.published{display:none}}
  </style>
</head>
<body><main>
  <header><h1>{{.Workspace}}<br>package status</h1><div class="revision">Git {{.GitRevision}}</div></header>
  {{range .Repositories}}<section class="repository">
    <div class="repository-head"><h2>{{if .Endpoint}}<a href="{{.Endpoint}}">{{.Name}}</a>{{else}}{{.Name}}{{end}}</h2><div class="meta">{{.Format}} / {{.Visibility}} / {{.Gate}}</div></div>
    {{if .Packages}}<table><thead><tr><th>Package</th><th>Version</th><th>Status</th><th class="published">Published</th></tr></thead><tbody>
    {{range .Packages}}<tr><td>{{.Name}}</td><td>{{.Version}}</td><td class="state state-{{.State}}">{{stateLabel .State}}</td><td class="published">{{if .PublishedAt}}{{.PublishedAt}}{{else}}-{{end}}</td></tr>{{end}}
    </tbody></table>{{else}}<div class="empty">No active placements.</div>{{end}}
  </section>{{end}}
  <p class="meta">Machine-readable status: <a href="status.json">status.json</a></p>
</main></body></html>
`))

func ValidateState(value string) error {
	for _, allowed := range []string{"current", "lagging", "missing", "pending", "failed", "unknown"} {
		if value == allowed {
			return nil
		}
	}
	return fmt.Errorf("invalid status state %q", value)
}
