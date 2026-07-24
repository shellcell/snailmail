package helm

import (
	"bytes"
	"testing"

	"github.com/shellcell/snailmail/internal/testutil"
)

func TestInspectChart(t *testing.T) {
	content, filename, err := testutil.HelmChart("snail-demo", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := Inspect(filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Name != "snail-demo" || facts.Version != "1.2.3" {
		t.Fatalf("unexpected chart facts: %#v", facts)
	}
	if facts.Fields["apiVersion"] != "v2" || facts.Fields["appVersion"] != "2.4.6" {
		t.Fatalf("unexpected Chart.yaml fields: %#v", facts.Fields)
	}
	if facts.InstalledSize == 0 {
		t.Fatal("expanded chart size was not derived")
	}
}

func TestInspectRejectsFilenameIdentityMismatch(t *testing.T) {
	content, _, err := testutil.HelmChart("snail-demo", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect("other-1.2.3.tgz", bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected mismatched chart filename to fail")
	}
}

func TestInspectRejectsInvalidArchive(t *testing.T) {
	content := []byte("not a chart")
	if _, err := Inspect("broken-1.0.0.tgz", bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected invalid chart to fail")
	}
}

func TestInspectRejectsNumericRequiredMetadata(t *testing.T) {
	chartYAML := "apiVersion: v2\nname: snail-demo\nversion: 1.2\ndescription: invalid numeric version\n"
	content, filename, err := testutil.HelmChartWithMetadata("snail-demo", "1.2", chartYAML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(filename, bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected numeric version scalar to fail")
	}
}

func FuzzInspect(f *testing.F) {
	content, filename, err := testutil.HelmChart("snail-demo", "1.2.3")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(filename, content)
	f.Add("broken-1.0.0.tgz", []byte("not a chart"))
	f.Fuzz(func(t *testing.T, name string, raw []byte) {
		if int64(len(raw)) > MaxArtifactSize {
			t.Skip()
		}
		_, _ = Inspect(name, bytes.NewReader(raw), int64(len(raw)))
	})
}
