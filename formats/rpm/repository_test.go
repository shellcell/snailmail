package rpm

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

const aDigest = "855e8ab0d2b1ab053d679996cd8f4afa9f6dc7e5a0572e2952056071c554d88e"

func repomdNaming(entries string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>` + entries + `
</repomd>`)
}

func primaryEntry(name, epoch, ver, rel, arch, location, digest string) string {
	return fmt.Sprintf(`
  <package type="rpm">
    <name>%s</name>
    <arch>%s</arch>
    <version epoch="%s" ver="%s" rel="%s"/>
    <checksum type="sha256" pkgid="YES">%s</checksum>
    <location href="%s"/>
    <size package="1024"/>
  </package>`, name, arch, epoch, ver, rel, digest, location)
}

func primaryNaming(entries string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">` + entries + `
</metadata>`)
}

func TestRepomdNamesItsIndexes(t *testing.T) {
	metadata, err := ParseRepomd(repomdNaming(`
  <data type="primary">
    <checksum type="sha256">` + aDigest + `</checksum>
    <location href="repodata/abc-primary.xml.gz"/>
    <size>4096</size>
  </data>`))
	if err != nil {
		t.Fatal(err)
	}
	primary, found := FindMetadata(metadata, "primary")
	if !found {
		t.Fatal("primary was not found")
	}
	if primary.SHA256 != aDigest || primary.Location != "repodata/abc-primary.xml.gz" || primary.Size != 4096 {
		t.Errorf("read %+v", primary)
	}
}

// repomd may state sha1 or md5 instead. Reading one into the SHA256 field would
// make a caller check the chain against a digest of a different algorithm and
// conclude the index was tampered with; leaving it empty lets the caller say the
// chain cannot be established, which is the true statement.
func TestRepomdIgnoresADigestThatIsNotSHA256(t *testing.T) {
	metadata, err := ParseRepomd(repomdNaming(`
  <data type="primary">
    <checksum type="sha1">da39a3ee5e6b4b0d3255bfef95601890afd80709</checksum>
    <location href="repodata/abc-primary.xml.gz"/>
  </data>`))
	if err != nil {
		t.Fatal(err)
	}
	if metadata[0].SHA256 != "" {
		t.Errorf("a sha1 was read as a SHA-256: %q", metadata[0].SHA256)
	}
}

// An index is a list of places to fetch from, so a location that escapes the
// repository or names another host is the one thing it must not be able to say.
func TestRepomdRefusesALocationThatLeavesTheRepository(t *testing.T) {
	for _, href := range []string{
		"/etc/passwd",
		"../../../etc/passwd",
		"https://elsewhere.example/primary.xml.gz",
		"repodata/../../out",
	} {
		_, err := ParseRepomd(repomdNaming(`
  <data type="primary">
    <checksum type="sha256">` + aDigest + `</checksum>
    <location href="` + href + `"/>
  </data>`))
		if err == nil {
			t.Errorf("%q was accepted as a location", href)
		}
	}
}

func TestPrimaryNamesEveryPackage(t *testing.T) {
	packages, err := ParsePrimary(primaryNaming(
		primaryEntry("demo", "0", "1.0", "1.el9", "x86_64", "Packages/d/demo-1.0-1.el9.x86_64.rpm", aDigest) +
			primaryEntry("other", "2", "3.4", "5.el9", "noarch", "Packages/o/other-3.4-5.el9.noarch.rpm", aDigest)))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("read %d packages, want 2", len(packages))
	}
	// An epoch of 0 is not part of the version anyone writes, but a non-zero one is
	// and dropping it would make two different packages look like one.
	if packages[0].EVR() != "1.0-1.el9" {
		t.Errorf("EVR = %q, want the epoch omitted when it is zero", packages[0].EVR())
	}
	if packages[1].EVR() != "2:3.4-5.el9" {
		t.Errorf("EVR = %q, want the epoch kept", packages[1].EVR())
	}
}

// Multilib: one name and EVR built for two architectures is two real artifacts,
// not a duplicate. Collapsing them would silently drop one from a repository that
// legitimately serves both, which is what Rocky and Fedora do throughout.
func TestPrimaryKeepsTwoArchitecturesOfOneVersion(t *testing.T) {
	packages, err := ParsePrimary(primaryNaming(
		primaryEntry("demo", "0", "1.0", "1.el9", "i686", "Packages/d/demo-1.0-1.el9.i686.rpm", aDigest) +
			primaryEntry("demo", "0", "1.0", "1.el9", "x86_64", "Packages/d/demo-1.0-1.el9.x86_64.rpm",
				"4a5a4e68281b9fd6d5291766633fba25e52ccfa47214cf152ac9fafd0ca621bc")))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("read %d, want both architectures", len(packages))
	}
	for _, entry := range packages {
		if entry.Ambiguous {
			t.Errorf("%s.%s was marked ambiguous", entry.Name, entry.Architecture)
		}
	}
}

// The same package listed twice with disagreeing digests means the index cannot say
// which artifact it is. As in helm, that spoils the entry rather than the document:
// one bad package should not make a repository of thousands unreadable.
func TestPrimaryMarksAContradictionWithoutSpoilingTheRest(t *testing.T) {
	packages, err := ParsePrimary(primaryNaming(
		primaryEntry("demo", "0", "1.0", "1.el9", "x86_64", "Packages/d/demo.rpm", aDigest) +
			primaryEntry("demo", "0", "1.0", "1.el9", "x86_64", "Packages/d/demo.rpm",
				"4a5a4e68281b9fd6d5291766633fba25e52ccfa47214cf152ac9fafd0ca621bc") +
			primaryEntry("sound", "0", "2.0", "1.el9", "x86_64", "Packages/s/sound.rpm", aDigest)))
	if err != nil {
		t.Fatalf("one contradictory package made the whole index unreadable: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("read %+v", packages)
	}
	if !packages[0].Ambiguous {
		t.Error("the contradictory package was not marked")
	}
	if packages[1].Ambiguous {
		t.Error("the sound package was marked because another one was bad")
	}
}

func TestPrimaryRefusesALocationThatLeavesTheRepository(t *testing.T) {
	_, err := ParsePrimary(primaryNaming(
		primaryEntry("demo", "0", "1.0", "1.el9", "x86_64", "../../../etc/passwd", aDigest)))
	if err == nil {
		t.Error("a package pointing outside the repository was accepted")
	}
}

// A compressed index that expands past the limit has to be caught rather than
// truncated into a shorter document that still parses — which would import a
// silently partial repository and report success.
func TestPrimaryDecompressionIsBounded(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	// Highly compressible, so a small body expands past the limit.
	if _, err := writer.Write(bytes.Repeat([]byte("a"), MaximumPrimaryBytes+1024)); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	_, err := DecompressPrimary("repodata/x-primary.xml.gz", compressed.Bytes())
	if err == nil {
		t.Fatal("an index that expands past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %v, want the limit named", err)
	}
}

// zstd appears in newer repositories. Naming the encoding beats failing to parse
// compressed bytes as XML, which is what an operator would otherwise have to
// diagnose from a syntax error.
func TestAnUnreadableEncodingIsNamed(t *testing.T) {
	_, err := DecompressPrimary("repodata/x-primary.xml.zst", []byte("\x28\xb5\x2f\xfd"))
	if err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Errorf("error = %v, want the encoding named", err)
	}
}
