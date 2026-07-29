package helm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are a chart packaged and signed by Helm itself, not by this
// package. That is the point: a provenance builder tested only against its own
// output agrees with itself about a format it may have misread, and every
// format defect this project has found came from checking against the tool that
// actually consumes the bytes.
const fixtureChart = "demo-1.2.3.tgz"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// helmSignedBlock is the document inside a provenance file: what lies between
// the clear-signed header and the signature.
func helmSignedBlock(t *testing.T, provenance []byte) string {
	t.Helper()
	_, body, found := strings.Cut(string(provenance), "\n\n")
	if !found {
		t.Fatal("fixture provenance has no clear-signed body")
	}
	signed, _, found := strings.Cut(body, "-----BEGIN PGP SIGNATURE-----")
	if !found {
		t.Fatal("fixture provenance has no signature")
	}
	// Clear-signing adds a newline before the signature block that is not part
	// of the document being signed.
	return strings.TrimSuffix(signed, "\n")
}

func TestProvenancePayloadMatchesHelm(t *testing.T) {
	archive := loadFixture(t, fixtureChart)
	want := helmSignedBlock(t, loadFixture(t, fixtureChart+ProvenanceSuffix))

	got, err := ProvenancePayload(fixtureChart, bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("provenance document differs from the one Helm produced\n got: %q\nwant: %q", got, want)
	}
}

// The digest in the document is what `helm verify` actually checks, so it must
// be the digest of the archive as published rather than of anything derived
// from it.
func TestProvenancePayloadPinsTheArchive(t *testing.T) {
	archive := loadFixture(t, fixtureChart)
	got, err := ProvenancePayload(fixtureChart, bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "\nfiles:\n  "+fixtureChart+": sha256:") {
		t.Fatalf("the archive is not named with its digest:\n%s", got)
	}
	// A changed archive must produce a changed document, or the signature would
	// cover something other than what was published.
	altered := append([]byte(nil), archive...)
	altered[len(altered)-1] ^= 0x01
	other, err := ProvenancePayload(fixtureChart, bytes.NewReader(altered), int64(len(altered)))
	if err == nil && bytes.Equal(got, other) {
		t.Fatal("altering the archive did not change the signed document")
	}
}

// Every field a chart declares is carried, including ones a fixed struct would
// have no place for: the signed document describes the chart that was
// published, not the subset this package happens to model.
func TestProvenanceCarriesUnmodelledFields(t *testing.T) {
	document, err := sortedMetadata([]byte(
		"name: demo\nversion: 1.2.3\napiVersion: v2\n" +
			"keywords:\n  - one\n  - two\n" +
			"annotations:\n  example.com/team: platform\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"keywords:\n  - one\n  - two\n", "annotations:\n  example.com/team: platform\n"} {
		if !strings.Contains(string(document), want) {
			t.Errorf("a declared field was dropped from the signed document: %q\n%s", want, document)
		}
	}
	// Sorted, because that is the order Helm's own signer emits.
	if got := string(document); strings.Index(got, "apiVersion") > strings.Index(got, "name") {
		t.Errorf("fields are not sorted:\n%s", got)
	}
}

// Provenance is only made for an archive this package already accepts as the
// chart it claims to be; signing anything else would put a signature on bytes
// nothing else in the system will serve.
func TestProvenanceRefusesWhatInspectRefuses(t *testing.T) {
	archive := loadFixture(t, fixtureChart)
	if _, err := ProvenancePayload("wrong-name-9.9.9.tgz", bytes.NewReader(archive), int64(len(archive))); err == nil {
		t.Fatal("built provenance for an archive whose filename disagrees with its chart")
	}
	if _, err := ProvenancePayload(fixtureChart, bytes.NewReader(archive), int64(len(archive))-1); err == nil {
		t.Fatal("built provenance for a truncated archive")
	}
}

// A chart archive is one gzip stream, and the tar inside it ends before that
// stream does. Reading only as far as the tar's end-of-archive marker leaves
// gzip's CRC and length unchecked, which accepted an archive missing its last
// eight bytes — bytes no client would accept and a signature would have
// covered.
func TestInspectChecksTheWholeCompressedStream(t *testing.T) {
	archive := loadFixture(t, fixtureChart)
	for _, drop := range []int{1, 2, 4, 8} {
		short := archive[:len(archive)-drop]
		if _, err := Inspect(fixtureChart, bytes.NewReader(short), int64(len(short))); err == nil {
			t.Errorf("an archive missing its last %d bytes was accepted", drop)
		}
	}
	if _, err := Inspect(fixtureChart, bytes.NewReader(archive), int64(len(archive))); err != nil {
		t.Fatalf("the intact archive was refused: %v", err)
	}
}
