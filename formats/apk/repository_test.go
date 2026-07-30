package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"strings"
	"testing"
)

// packIndexArchive packs entries into APKINDEX.tar.gz the way Alpine publishes it,
// optionally preceded by a signature member in its own gzip stream — which is what
// the real archive does and what a single-stream reader would stop at.
func packIndexArchive(t *testing.T, entries string, signed bool) []byte {
	t.Helper()
	var archive bytes.Buffer
	writeMember := func(name string, content []byte) {
		compressor := gzip.NewWriter(&archive)
		writer := tar.NewWriter(compressor)
		if err := writer.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		compressor.Close()
	}
	if signed {
		writeMember(".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", []byte("signature"))
	}
	writeMember(indexMemberName, []byte(entries))
	return archive.Bytes()
}

// The real C: field from Alpine 3.19's index for 7zip-23.01-r0.
const realChecksum = "Q1YCZ4e/kV0Uaynh14//zvTTyN7x8="

func indexEntry(name, version, arch, checksum string) string {
	return "C:" + checksum + "\nP:" + name + "\nV:" + version + "\nA:" + arch + "\nS:866787\n\n"
}

func TestIndexNamesEveryPackage(t *testing.T) {
	packages, err := ParseIndex(packIndexArchive(t,
		indexEntry("7zip", "23.01-r0", "x86_64", realChecksum)+
			indexEntry("busybox", "1.36.1-r15", "x86_64", realChecksum), false))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("read %d packages, want 2", len(packages))
	}
	// APKINDEX does not state a filename; apk derives it, and so must this.
	if packages[0].Filename() != "7zip-23.01-r0.apk" {
		t.Errorf("filename = %q", packages[0].Filename())
	}
	if packages[0].Size != 866787 {
		t.Errorf("size = %d", packages[0].Size)
	}
}

// APKINDEX.tar.gz is a concatenation of gzip streams: the signature, then the
// metadata. A reader that stops at the end of the first stream finds no entries at
// all, and would report an empty repository rather than an unread one.
func TestASignedIndexIsStillRead(t *testing.T) {
	archive := packIndexArchive(t, indexEntry("7zip", "23.01-r0", "x86_64", realChecksum), true)
	packages, err := ParseIndex(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 {
		t.Fatalf("read %d packages past the signature member, want 1", len(packages))
	}
	key, signed := Signed(archive)
	if !signed || !strings.Contains(key, "alpine-devel") {
		t.Errorf("Signed() = %q, %v; want the signing key named", key, signed)
	}
	if _, signed := Signed(packIndexArchive(t, indexEntry("a", "1-r0", "x86_64", realChecksum), false)); signed {
		t.Error("an unsigned index was reported as signed")
	}
}

// This is the fact that decides Alpine's provenance, so it is pinned here rather
// than left as a remark in a comment. The C: field decodes to twenty bytes that are
// the SHA-1 of the package's control section — not of the file. The value below and
// the file digest beside it are both from Alpine's own archive.
func TestTheIndexChecksumIsNotADigestOfTheFile(t *testing.T) {
	packages, err := ParseIndex(packIndexArchive(t, indexEntry("7zip", "23.01-r0", "x86_64", realChecksum), false))
	if err != nil {
		t.Fatal(err)
	}
	stated := hex.EncodeToString(packages[0].ControlSHA1)
	if stated != "6026787bf915d146b29e1d78fffcef4d3c8def1f" {
		t.Fatalf("decoded %q, want the control digest Alpine published", stated)
	}
	// 7zip-23.01-r0.apk actually hashes to this. The two differ because they are
	// digests of different things, which is why an imported apk is pinned to bytes
	// snailmail computed rather than to anything the index stated.
	if stated == "76a960426c3b96d593078c94c6ea40d2cf2373ed" {
		t.Error("the index checksum is the file's SHA-1 after all, so apk could be pinned from its index")
	}
}

// A C: field that is not Q1 is a checksum of some other kind. Decoding it as a
// SHA-1 anyway would attribute a meaning to bytes that do not carry it.
func TestAnUnknownChecksumPrefixIsNotDecoded(t *testing.T) {
	packages, err := ParseIndex(packIndexArchive(t, indexEntry("demo", "1.0-r0", "x86_64", "Q2abcdef"), false))
	if err != nil {
		t.Fatal(err)
	}
	if packages[0].ControlSHA1 != nil {
		t.Errorf("a non-Q1 checksum was decoded as %x", packages[0].ControlSHA1)
	}
}

// The filename is built from the name and version, so those are the fields that
// could direct a fetch elsewhere.
func TestAnIndexCannotBuildAPathOutOfTheRepository(t *testing.T) {
	for _, entry := range []string{
		"C:" + realChecksum + "\nP:../../etc/passwd\nV:1.0-r0\nA:x86_64\n\n",
		"C:" + realChecksum + "\nP:demo\nV:../../../evil\nA:x86_64\n\n",
	} {
		if _, err := ParseIndex(packIndexArchive(t, entry, false)); err == nil {
			t.Errorf("an index building a path outside the repository was accepted: %q", entry)
		}
	}
}

func TestAContradictoryEntryIsMarkedWithoutSpoilingTheRest(t *testing.T) {
	packages, err := ParseIndex(packIndexArchive(t,
		indexEntry("demo", "1.0-r0", "x86_64", realChecksum)+
			indexEntry("demo", "1.0-r0", "x86_64", "Q1AAA4e/kV0Uaynh14//zvTTyN7x8=")+
			indexEntry("sound", "2.0-r0", "x86_64", realChecksum), false))
	if err != nil {
		t.Fatalf("one contradictory entry made the whole index unreadable: %v", err)
	}
	if len(packages) != 2 || !packages[0].Ambiguous || packages[1].Ambiguous {
		t.Errorf("read %+v", packages)
	}
}

func TestAnArchiveWithNoIndexIsNamed(t *testing.T) {
	var archive bytes.Buffer
	compressor := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressor)
	writer.WriteHeader(&tar.Header{Name: "DESCRIPTION", Mode: 0o644, Size: 4})
	writer.Write([]byte("none"))
	writer.Close()
	compressor.Close()
	_, err := ParseIndex(archive.Bytes())
	if err == nil || !strings.Contains(err.Error(), "APKINDEX") {
		t.Errorf("error = %v, want the missing index named", err)
	}
}
