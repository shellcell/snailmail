package apk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// realPackage was produced by abuild in an Alpine container and is committed
// rather than generated: a parser checked only against fixtures it also writes
// will agree with itself about a format it has misread.
const realPackage = "snail-demo-1.2.3-r4.apk"

func loadRealPackage(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", realPackage))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// Every value here is what `apk index` wrote for the same file, and the
// checksum is the one that proves the stream boundary was found correctly:
// it covers the compressed control stream, not the file and not the data.
func TestInspectAgreesWithApkIndex(t *testing.T) {
	content := loadRealPackage(t)
	pkg, err := InspectPackage(realPackage, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("parsing a real abuild package failed: %v", err)
	}
	for name, got := range map[string][2]string{
		"name":        {pkg.Name, "snail-demo"},
		"version":     {pkg.Version, "1.2.3-r4"},
		"arch":        {pkg.Architecture, "noarch"},
		"license":     {pkg.License, "MIT"},
		"origin":      {pkg.Origin, "snail-demo"},
		"description": {pkg.Description, "Deterministic test package"},
		"url":         {pkg.URL, "https://example.invalid/snail-demo"},
		// C: from the APKINDEX apk itself generated.
		"checksum": {pkg.Checksum, "Q1EdGFduziftFxVmEaf+YyUEOyr4o="},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, apk reports %q", name, got[0], got[1])
		}
	}
	// S: and I: from the same index.
	if pkg.Size != 1411 {
		t.Errorf("size = %d, apk reports 1411", pkg.Size)
	}
	if pkg.InstalledSize != 6 {
		t.Errorf("installed size = %d, apk reports 6", pkg.InstalledSize)
	}
	if pkg.BuildTime != 1785301961 {
		t.Errorf("build time = %d, apk reports 1785301961", pkg.BuildTime)
	}
}

func TestInspectRejectsWhatItCannotServe(t *testing.T) {
	content := loadRealPackage(t)
	for name, testCase := range map[string]struct {
		filename string
		content  []byte
	}{
		"not an apk":      {"demo.apk", []byte("not a gzip stream at all")},
		"wrong extension": {"demo.tar.gz", content},
		"truncated":       {"demo.apk", content[:32]},
		"empty":           {"demo.apk", nil},
		"path separator":  {"a/demo.apk", content},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectPackage(testCase.filename, bytes.NewReader(testCase.content), int64(len(testCase.content))); err == nil {
				t.Fatal("an unusable package was accepted")
			}
		})
	}
}
