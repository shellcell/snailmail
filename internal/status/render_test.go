package status

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

func TestRenderIsDeterministicAndDistinguishesGateState(t *testing.T) {
	locked := state.LockedBlob{SHA256: strings.Repeat("a", 64)}
	inputs := []InputRepository{
		{
			Name: "python", Config: state.Repository{Format: "pypi", Visibility: "public", Gate: "approval", Host: state.HostConfig{Type: "s3", CanonicalEndpoint: "https://packages.example"}},
			Pending: true, Deployment: state.DeploymentRecord{TreeSHA256: "older", PlanID: strings.Repeat("d", 64)},
			Lock: state.RepositoryLock{
				PackageVersion: []state.PackageVersion{{Package: "demo", Version: "2.0.0", Blobs: []state.LockedBlob{locked}}},
				Placement:      []state.Placement{{Package: "demo", Version: "2.0.0"}},
			},
		},
		{
			Name: "archive", Config: state.Repository{Format: "pypi", Visibility: "public", Gate: "auto"},
			Lock: state.RepositoryLock{
				PackageVersion: []state.PackageVersion{{Package: "old", Version: "1.0.0", Blobs: []state.LockedBlob{locked}}},
				Placement:      []state.Placement{{Package: "old", Version: "1.0.0"}},
			},
			Records:    []state.PublicationRecord{{Package: "old", Version: "1.0.0", BlobSHA256: []string{locked.SHA256}, PlanID: strings.Repeat("b", 64), TreeSHA256: "tree", RecordedAt: "2026-07-25T00:00:00Z"}},
			Deployment: state.DeploymentRecord{TreeSHA256: "tree", PlanID: strings.Repeat("b", 64)},
		},
		{
			Name: "interrupted", Config: state.Repository{Format: "pypi", Visibility: "public", Gate: "auto"},
			Lock: state.RepositoryLock{
				PackageVersion: []state.PackageVersion{{Package: "uncertain", Version: "3.0.0", Blobs: []state.LockedBlob{locked}}},
				Placement:      []state.Placement{{Package: "uncertain", Version: "3.0.0"}},
			},
			Records: []state.PublicationRecord{{Package: "uncertain", Version: "3.0.0", BlobSHA256: []string{locked.SHA256}, PlanID: strings.Repeat("e", 64), TreeSHA256: "uncertain-tree"}},
		},
	}
	first, err := Render("demo <workspace>", strings.Repeat("c", 40), inputs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render("demo <workspace>", strings.Repeat("c", 40), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.JSON, second.JSON) || !bytes.Equal(first.HTML, second.HTML) {
		t.Fatal("status rendering was not deterministic")
	}
	if !bytes.Contains(first.JSON, []byte(`"state": "current"`)) || !bytes.Contains(first.JSON, []byte(`"state": "pending"`)) {
		t.Fatalf("status JSON omitted expected states: %s", first.JSON)
	}
	if !bytes.Contains(first.JSON, []byte(`"state": "unknown"`)) {
		t.Fatalf("interrupted publication did not remain unknown: %s", first.JSON)
	}
	if bytes.Contains(first.HTML, []byte("demo <workspace>")) || !bytes.Contains(first.HTML, []byte("demo &lt;workspace&gt;")) {
		t.Fatal("status HTML did not escape workspace name")
	}
}
