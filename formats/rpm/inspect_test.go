package rpm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// realPackage is committed rather than generated: a parser checked only against
// fixtures it also writes will agree with itself about a format it has misread.
// The spec that produced it, built with rpmbuild:
//
//	Name: snail-demo   Version: 1.2.3   Release: 4
//	Summary: Deterministic test package   License: MIT
//	BuildArch: noarch  Requires: bash
const realPackage = "snail-demo-1.2.3-4.noarch.rpm"

func loadRealPackage(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", realPackage))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// Every value here is what `rpm -qp` reports for the same file.
func TestInspectReadsWhatRPMReports(t *testing.T) {
	content := loadRealPackage(t)
	pkg, err := InspectPackage(realPackage, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("parsing a real rpmbuild package failed: %v", err)
	}
	for name, got := range map[string][2]string{
		"name":    {pkg.Name, "snail-demo"},
		"version": {pkg.Version, "1.2.3"},
		"release": {pkg.Release, "4"},
		"arch":    {pkg.Architecture, "noarch"},
		"evr":     {pkg.EVR(), "1.2.3-4"},
		"license": {pkg.License, "MIT"},
		"summary": {pkg.Summary, "Deterministic test package"},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, rpm reports %q", name, got[0], got[1])
		}
	}
	if pkg.Epoch != 0 {
		t.Errorf("epoch = %d, rpm reports none", pkg.Epoch)
	}
	// The header range lets a client read metadata without the payload, so it
	// has to land inside the file and be non-empty.
	if pkg.HeaderStart <= 0 || pkg.HeaderEnd <= pkg.HeaderStart || pkg.HeaderEnd > int64(len(content)) {
		t.Errorf("header range [%d,%d) is not inside a %d byte package", pkg.HeaderStart, pkg.HeaderEnd, len(content))
	}
	// rpmbuild always adds rpmlib() requirements alongside the declared one.
	var declared bool
	for _, dependency := range pkg.Requires {
		if dependency.Name == "bash" {
			declared = true
		}
	}
	if !declared {
		t.Errorf("the declared Requires: bash is missing from %+v", pkg.Requires)
	}
}

func TestInspectPopulatesTheFieldsAnIndexNeeds(t *testing.T) {
	content := loadRealPackage(t)
	facts, err := Inspect(realPackage, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Name != "snail-demo" || facts.Version != "1.2.3-4" || facts.Architecture != "noarch" {
		t.Fatalf("facts are %+v", facts)
	}
	// A lock carries Fields and nothing else, so anything the index needs that
	// is missing here cannot be recovered when the repository is rebuilt.
	for _, key := range []string{"license", "summary", "header_start", "header_end"} {
		if facts.Fields[key] == "" {
			t.Errorf("field %q is absent, so a rebuilt index would lose it", key)
		}
	}
}

func TestInspectRejectsWhatItCannotServe(t *testing.T) {
	content := loadRealPackage(t)
	for name, testCase := range map[string]struct {
		filename string
		content  []byte
	}{
		"not an rpm":      {"demo.rpm", []byte("this is not a package at all, but it is long enough to read a lead from")},
		"source package":  {"demo.src.rpm", content},
		"wrong extension": {"demo.deb", content},
		"truncated":       {"demo.rpm", content[:64]},
		"empty":           {"demo.rpm", nil},
		"path separator":  {"a/demo.rpm", content},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectPackage(testCase.filename, bytes.NewReader(testCase.content), int64(len(testCase.content))); err == nil {
				t.Fatal("an unusable package was accepted")
			}
		})
	}
}

// A header claiming more entries or a larger store than the file holds must be
// refused before any of it is read, not trusted into an allocation.
func TestInspectRefusesAHeaderThatOverrunsTheFile(t *testing.T) {
	content := loadRealPackage(t)
	corrupt := append([]byte(nil), content...)
	// The signature header's index count sits just past the lead and its magic.
	corrupt[leadSize+8] = 0xff
	corrupt[leadSize+9] = 0xff
	if _, err := InspectPackage(realPackage, bytes.NewReader(corrupt), int64(len(corrupt))); err == nil {
		t.Fatal("a header claiming more entries than the file holds was accepted")
	}
}
