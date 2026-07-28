package raw

import (
	"bytes"
	"strings"
	"testing"
)

func inspectName(t *testing.T, filename string, supplied Identity) (string, string, string, error) {
	t.Helper()
	content := []byte("artifact bytes")
	facts, err := Inspect(filename, bytes.NewReader(content), int64(len(content)), supplied)
	return facts.Name, facts.Version, facts.Architecture, err
}

func TestInspectReadsTheReleaseNamingConvention(t *testing.T) {
	for filename, want := range map[string][3]string{
		"snailmail_0.1.2_linux_amd64.tar.gz":    {"snailmail", "0.1.2", "amd64"},
		"ttysvg_1.4.0-rc1_darwin_arm64.zip":     {"ttysvg", "1.4.0-rc1", "arm64"},
		"tool_2.0.0_windows_386.exe":            {"tool", "2.0.0", "386"},
		"cnvrt_0.0.3.tar.gz":                    {"cnvrt", "0.0.3", ""},
		"exex_1.2.3_linux.tar.gz":               {"exex", "1.2.3", ""},
		"thing_20240115_linux_x86_64.tar.zst":   {"thing", "20240115", "x86_64"},
		"pkg_1.2.3.4_linux_aarch64.tar.bz2":     {"pkg", "1.2.3.4", "aarch64"},
		"snail-demo_0.1.0_linux_riscv64.tar.xz": {"snail-demo", "0.1.0", "riscv64"},
	} {
		t.Run(filename, func(t *testing.T) {
			name, version, architecture, err := inspectName(t, filename, Identity{})
			if want[0] == "" {
				if err == nil {
					t.Fatalf("%q parsed as %s@%s, want a request for --name/--version", filename, name, version)
				}
				if !strings.Contains(err.Error(), "--name") {
					t.Fatalf("error %v does not tell the operator what to supply", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != want[0] || version != want[1] || architecture != want[2] {
				t.Fatalf("got %s@%s/%s, want %s@%s/%s", name, version, architecture, want[0], want[1], want[2])
			}
		})
	}
}

// A name containing an underscore cannot be told apart from an extra field, so
// the parser must decline rather than guess a wrong split.
func TestInspectDeclinesAmbiguousFilenames(t *testing.T) {
	for _, filename := range []string{
		"my_tool_2.0.0_linux_amd64.tar.gz",
		"build.tar.gz",
		"snailmail.tar.gz",
		"_0.1.2_linux_amd64.tar.gz",
	} {
		if _, _, _, err := inspectName(t, filename, Identity{}); err == nil {
			t.Errorf("%q was parsed rather than declined", filename)
		}
	}
}

func TestSuppliedIdentityFillsAndOverrides(t *testing.T) {
	name, version, _, err := inspectName(t, "build-final.tar.gz", Identity{Name: "ttysvg", Version: "0.1.2"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "ttysvg" || version != "0.1.2" {
		t.Fatalf("got %s@%s", name, version)
	}
	// A partial override keeps whatever the filename supplied.
	name, version, _, err = inspectName(t, "my-tool_1.0.0_linux_amd64.tar.gz", Identity{Version: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "my-tool" || version != "2.0.0" {
		t.Fatalf("got %s@%s, want my-tool@2.0.0", name, version)
	}
}

// Identity becomes a path segment, so anything that would escape the tree or
// collide with generated files has to be refused.
func TestInspectRejectsUnusableIdentity(t *testing.T) {
	for name, supplied := range map[string]Identity{
		"traversing name":    {Name: "../escape", Version: "1.0.0"},
		"separator in name":  {Name: "a/b", Version: "1.0.0"},
		"traversing version": {Name: "tool", Version: "../1.0.0"},
		"non-numeric start":  {Name: "tool", Version: "v1.0.0"},
		"empty version":      {Name: "tool", Version: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := inspectName(t, "build-final.tar.gz", supplied); err == nil {
				t.Fatalf("%+v was accepted", supplied)
			}
		})
	}
}

func TestArtifactFilenameRejectsUnsafeAndReservedNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "SHA256SUMS", "index.html", strings.Repeat("x", 256)} {
		if IsArtifactFilename(name) {
			t.Errorf("%q was accepted", name)
		}
	}
	for _, name := range []string{"snailmail_0.1.2_linux_amd64.tar.gz", "notes.txt", "binary"} {
		if !IsArtifactFilename(name) {
			t.Errorf("%q was rejected", name)
		}
	}
}

// Inspect reads the artifact so a declared size that does not match the bytes
// is caught; raw performs no structural parse, so this is the only such check.
func TestInspectRejectsAShortReader(t *testing.T) {
	content := []byte("short")
	if _, err := Inspect("tool_1.0.0_linux_amd64.bin", bytes.NewReader(content), int64(len(content))+64, Identity{}); err == nil {
		t.Fatal("a size longer than the bytes was accepted")
	}
}
