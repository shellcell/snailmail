package pypi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/shellcell/snailmail/internal/testutil"
)

func TestInspectWheel(t *testing.T) {
	content, filename, err := testutil.WheelWithDependencies("Demo-Pkg", "1.2.3", ">=3.8", []string{"Support-Pkg == 2.0"})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := Inspect(filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Name != "Demo-Pkg" || facts.Version != "1.2.3" || facts.RequiresPython != ">=3.8" {
		t.Fatalf("unexpected facts: %#v", facts)
	}
	if len(facts.Requirements) != 1 || facts.Requirements[0] != "Support-Pkg == 2.0" {
		t.Fatalf("unexpected requirements: %#v", facts.Requirements)
	}
}

func TestInspectRejectsWheelWithoutMetadata(t *testing.T) {
	content := []byte("not a zip archive")
	if _, err := Inspect("broken-1.0-py3-none-any.whl", bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected invalid wheel to fail")
	}
}

func TestInspectRejectsFilenameMetadataMismatch(t *testing.T) {
	content, _, err := testutil.Wheel("Demo-Pkg", "1.2.3", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect("other_pkg-1.2.3-py3-none-any.whl", bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected mismatched wheel identity to fail")
	}
}

func TestInspectRejectsOversizedArtifact(t *testing.T) {
	if _, err := Inspect("demo_pkg-1.0-py3-none-any.whl", bytes.NewReader(nil), MaxArtifactSize+1); err == nil {
		t.Fatal("expected oversized artifact to fail")
	}
}

func TestInspectRejectsCentralDirectoryGap(t *testing.T) {
	content, filename, err := testutil.Wheel("Demo-Pkg", "1.2.3", "")
	if err != nil {
		t.Fatal(err)
	}
	endRecord := bytes.LastIndex(content, []byte{'P', 'K', 0x05, 0x06})
	if endRecord < 0 {
		t.Fatal("wheel has no zip end record")
	}
	directorySize := binary.LittleEndian.Uint32(content[endRecord+12 : endRecord+16])
	binary.LittleEndian.PutUint32(content[endRecord+12:endRecord+16], directorySize-1)
	if _, err := Inspect(filename, bytes.NewReader(content), int64(len(content))); err == nil {
		t.Fatal("expected inconsistent central directory to fail")
	}
}

func TestNormalizeName(t *testing.T) {
	tests := map[string]string{
		"Friendly-Bard":     "friendly-bard",
		"Friendly_Bard":     "friendly-bard",
		"friendly.bard":     "friendly-bard",
		"FrIeNdLy-._.-bArD": "friendly-bard",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := NormalizeName(input); got != want {
				t.Fatalf("NormalizeName(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func FuzzInspectWheel(f *testing.F) {
	content, filename, err := testutil.Wheel("Demo-Pkg", "1.2.3", ">=3.8")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(filename, content)
	f.Add("broken-1.0-py3-none-any.whl", []byte("not a wheel"))
	f.Fuzz(func(t *testing.T, name string, raw []byte) {
		if int64(len(raw)) > MaxArtifactSize {
			t.Skip()
		}
		_, _ = Inspect(name, bytes.NewReader(raw), int64(len(raw)))
	})
}
