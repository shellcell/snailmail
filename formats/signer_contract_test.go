package formats

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/signer"
	apkrsa "github.com/shellcell/snailmail/signer/apkrsa"
	openpgpsigner "github.com/shellcell/snailmail/signer/openpgp"
)

// These exercise the signing behaviour of each format directly.
//
// The engine suite only ever signs a Debian repository, so before this every
// PlaceSignatures but deb's was reached by nothing automated — including the
// check each one makes that a signature verifies before it is published, which
// is the whole reason that code exists. What covered them was running real apt,
// dnf, apk and helm by hand, which CI cannot do.

const signingPassphrase = "a-passphrase-long-enough-for-the-key-store"

func openPGPKey(t *testing.T) (*openpgpsigner.Local, openpgpsigner.Generated) {
	t.Helper()
	generated, err := openpgpsigner.Generate("snailmail signing contract",
		time.Unix(1_700_000_000, 0).UTC(), 48*time.Hour, []byte(signingPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	local, err := openpgpsigner.Load(generated.PrivateArmor, []byte(signingPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	return local, generated
}

// signShape signs every output of a shape with the given key, the way the
// engine does once a plan has resolved its signatures.
func signShape(t *testing.T, local *openpgpsigner.Local, shape SigningShape, payloads map[string][]byte, at time.Time) map[string][]byte {
	t.Helper()
	signatures := make(map[string][]byte, len(shape.Outputs))
	for _, output := range shape.Outputs {
		response, err := local.Sign(context.Background(), signer.Request{
			Scheme: output.Scheme, Payload: payloads[output.Path], CreatedAt: at,
		})
		if err != nil {
			t.Fatalf("signing %s: %v", output.Path, err)
		}
		signatures[output.Path] = response.Content
	}
	return signatures
}

func debTestBlob(t *testing.T) domain.Blob {
	t.Helper()
	content, filename, err := testutil.Deb("demo", "1.2.3", "amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := For("deb")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := selected.Inspect(filename, strings.NewReader(string(content)), int64(len(content)), Identity{})
	if err != nil {
		t.Fatal(err)
	}
	return domain.Blob{
		Filename: filename, Size: int64(len(content)), Facts: facts,
		MD5:    "d41d8cd98f00b204e9800998ecf8427e",
		SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		SHA256: digestOfBytes(content),
	}
}

func digestOfBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// fixtureBlob reads a format's own test artifact and inspects it, so the
// repository below is built from bytes a real client would accept.
func fixtureBlob(t *testing.T, format, name string) domain.Blob {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(format, "testdata", name))
	if err != nil {
		t.Skipf("no %s fixture: %v", format, err)
	}
	selected, err := For(format)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := selected.Inspect(name, bytes.NewReader(content), int64(len(content)), Identity{})
	if err != nil {
		t.Fatal(err)
	}
	return domain.Blob{Filename: name, Size: int64(len(content)), Facts: facts, SHA256: digestOfBytes(content)}
}

// A signature that does not verify must never be published: a client reports
// one as tampering, which is worse than an unsigned repository. Every format
// that signs makes that check, and every one of them is checked here.
func TestPlaceSignaturesRefusesASignatureThatDoesNotVerify(t *testing.T) {
	local, generated := openPGPKey(t)
	at := time.Unix(1_700_000_100, 0).UTC()

	for _, format := range []struct {
		name       string
		repository Repository
		blob       func(*testing.T) domain.Blob
		content    ArtifactContent
	}{
		{"deb", Repository{Suite: "stable", Component: "main", Architectures: []string{"amd64"}}, debTestBlob, nil},
		{"rpm", Repository{}, func(t *testing.T) domain.Blob {
			return fixtureBlob(t, "rpm", "snail-demo-1.2.3-4.noarch.rpm")
		}, nil},
		{"helm", Repository{}, func(t *testing.T) domain.Blob {
			return fixtureBlob(t, "helm", "demo-1.2.3.tgz")
		}, helmFixtureContent(t)},
	} {
		t.Run(format.name, func(t *testing.T) {
			selected, err := For(format.name)
			if err != nil {
				t.Fatal(err)
			}
			blob := format.blob(t)
			artifact, err := selected.Build([]domain.Blob{blob}, BuildOptions{Repository: format.repository, GeneratedAt: at})
			if err != nil {
				t.Fatal(err)
			}
			signing, err := SignerFor(format.name)
			if err != nil {
				t.Fatal(err)
			}
			published := []string{}
			for _, file := range artifact.Files {
				if file.BlobSHA256 != "" {
					published = append(published, file.Path)
				}
			}
			shape, err := signing.SigningShape(format.repository, published)
			if err != nil {
				t.Fatal(err)
			}
			payloads, err := signing.SigningPayloads(artifact, format.repository, shape, format.content)
			if err != nil {
				t.Fatal(err)
			}
			material := SigningMaterial{
				Fingerprint: generated.Identity.Fingerprint, PublicBinary: generated.PublicBinary,
				PublicKeyring: generated.PublicBinary, PublicArmor: generated.PublicArmor,
				KeyringPath:         "keys/archive.gpg",
				TrustedFingerprints: []string{generated.Identity.Fingerprint}, SignatureTime: at,
				Signatures: signShape(t, local, shape, payloads, at),
			}
			if _, err := signing.PlaceSignatures(artifact, format.repository, material); err != nil {
				t.Fatalf("a sound signature was refused: %v", err)
			}

			// A signature that does not check out must be caught here rather
			// than by whoever installs from the repository.
			for _, output := range shape.Outputs {
				altered := material
				altered.Signatures = map[string][]byte{}
				for path, content := range material.Signatures {
					altered.Signatures[path] = append([]byte(nil), content...)
				}
				corrupted := altered.Signatures[output.Path]
				corrupted[len(corrupted)/2] ^= 0x01
				if _, err := signing.PlaceSignatures(artifact, format.repository, altered); err == nil {
					t.Errorf("a corrupted signature at %s was published", output.Path)
				}
			}
		})
	}
}

// helmFixtureContent serves the chart bytes provenance is built from.
func helmFixtureContent(t *testing.T) ArtifactContent {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("helm", "testdata", "demo-1.2.3.tgz"))
	if err != nil {
		return nil
	}
	return func(string) ([]byte, error) { return content, nil }
}

// Each format publishes the key in the shape its client reads, and they differ:
// apt takes a binary keyring, yum imports an armored key, apk holds a bare key
// under the name its index names.
func TestClientKeyPathsDifferByFormat(t *testing.T) {
	material := SigningMaterial{KeyringPath: "keys/archive.gpg", PublicArmorPath: "keys/alpine.rsa.pub"}
	for name, want := range map[string]string{
		"deb":  "keys/archive.gpg",
		"helm": "keys/archive.gpg",
		"rpm":  "keys/archive.asc",
		"apk":  "keys/alpine.rsa.pub",
	} {
		signing, err := SignerFor(name)
		if err != nil {
			t.Fatalf("format %q does not sign: %v", name, err)
		}
		if got := signing.ClientKeyPath(Repository{}, material); got != want {
			t.Errorf("format %q client key path = %q, want %q", name, got, want)
		}
	}
}

// A signing shape is what a reviewed plan is checked against, so each format's
// must be exactly what it publishes — no more, and nothing missing.
func TestSigningShapesAreWhatEachFormatPublishes(t *testing.T) {
	for name, expect := range map[string]struct {
		repository Repository
		published  []string
		payloadID  string
		paths      []string
	}{
		"deb": {Repository{Suite: "bookworm"}, nil, "deb-release",
			[]string{"dists/bookworm/InRelease", "dists/bookworm/Release.gpg"}},
		"rpm": {Repository{}, nil, "rpm-repomd", []string{"repodata/repomd.xml.asc"}},
		"apk": {Repository{Architectures: []string{"x86_64", "aarch64"}}, nil, "apk-index",
			[]string{"x86_64/APKINDEX.tar.gz", "aarch64/APKINDEX.tar.gz"}},
		"helm": {Repository{}, []string{"charts/aa/x-1.0.0.tgz"}, "helm-provenance",
			[]string{"charts/aa/x-1.0.0.tgz.prov"}},
	} {
		signing, err := SignerFor(name)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := signing.SigningShape(expect.repository, expect.published)
		if err != nil {
			t.Fatalf("format %q: %v", name, err)
		}
		if shape.PayloadID != expect.payloadID {
			t.Errorf("format %q payload id = %q, want %q", name, shape.PayloadID, expect.payloadID)
		}
		if len(shape.Outputs) != len(expect.paths) {
			t.Fatalf("format %q produced %d outputs, want %d", name, len(shape.Outputs), len(expect.paths))
		}
		for index, output := range shape.Outputs {
			if output.Path != expect.paths[index] {
				t.Errorf("format %q output %d is %q, want %q", name, index, output.Path, expect.paths[index])
			}
			if output.ID == "" || output.Scheme == "" {
				t.Errorf("format %q output %d has no identity or scheme", name, index)
			}
		}
	}
}

// An Alpine repository serving no architecture has no index to sign, which is a
// misconfiguration rather than an empty repository — unlike Helm, where having
// published no charts yet is the ordinary state of one just set up.
func TestSigningShapeEdgeCases(t *testing.T) {
	apk, err := SignerFor("apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apk.SigningShape(Repository{}, nil); err == nil {
		t.Error("an Alpine repository with no architectures produced a signing shape")
	}
	helm, err := SignerFor("helm")
	if err != nil {
		t.Fatal(err)
	}
	shape, err := helm.SigningShape(Repository{}, nil)
	if err != nil {
		t.Fatalf("an empty Helm repository was refused: %v", err)
	}
	if len(shape.Outputs) != 0 {
		t.Errorf("an empty Helm repository signs %d documents", len(shape.Outputs))
	}
}

// Formats that do not sign must say so rather than being asked to.
func TestSignerForRefusesUnsignedFormats(t *testing.T) {
	for _, name := range []string{"pypi", "raw"} {
		if _, err := SignerFor(name); err == nil {
			t.Errorf("format %q was offered as a signer", name)
		}
	}
	if _, err := SignerFor("not-a-format"); err == nil {
		t.Error("an unknown format was offered as a signer")
	}
}

// apk is the one format that does not verify with OpenPGP: its clients hold a
// bare RSA public key by filename, so it needs its own key and its own round
// trip. Its PlaceSignatures was the last one no automated test reached.
func TestAPKPlaceSignaturesRefusesASignatureThatDoesNotVerify(t *testing.T) {
	at := time.Unix(1_700_000_100, 0).UTC()
	generated, err := apkrsa.Generate(time.Unix(1_700_000_000, 0).UTC(), 48*time.Hour, []byte(signingPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	local, err := apkrsa.Open(generated.PrivateArmor, []byte(signingPassphrase), generated.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	selected, err := For("apk")
	if err != nil {
		t.Fatal(err)
	}
	blob := fixtureBlob(t, "apk", "snail-demo-1.2.3-r4.apk")
	// A noarch package is served under every architecture the repository has,
	// so the index architecture is the repository's rather than the package's.
	repository := Repository{Architectures: []string{"x86_64"}}
	artifact, err := selected.Build([]domain.Blob{blob}, BuildOptions{Repository: repository, GeneratedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	signing, err := SignerFor("apk")
	if err != nil {
		t.Fatal(err)
	}
	shape, err := signing.SigningShape(repository, nil)
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := signing.SigningPayloads(artifact, repository, shape, nil)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make(map[string][]byte, len(shape.Outputs))
	for _, output := range shape.Outputs {
		response, err := local.Sign(context.Background(), signer.Request{
			Scheme: output.Scheme, Payload: payloads[output.Path], CreatedAt: at,
		})
		if err != nil {
			t.Fatalf("signing %s: %v", output.Path, err)
		}
		signatures[output.Path] = response.Content
	}
	material := SigningMaterial{
		Fingerprint: generated.Identity.Fingerprint,
		PublicArmor: generated.PublicArmor, PublicArmorPath: "keys/alpine.rsa.pub",
		SignatureTime: at, Signatures: signatures,
	}
	if _, err := signing.PlaceSignatures(artifact, repository, material); err != nil {
		t.Fatalf("a sound apk signature was refused: %v", err)
	}

	// The check that matters: a signature which does not verify must not reach
	// a repository, because apk reports one as a corrupt index.
	for _, output := range shape.Outputs {
		altered := material
		altered.Signatures = map[string][]byte{}
		for path, content := range signatures {
			altered.Signatures[path] = append([]byte(nil), content...)
		}
		corrupted := altered.Signatures[output.Path]
		corrupted[len(corrupted)/2] ^= 0x01
		if _, err := signing.PlaceSignatures(artifact, repository, altered); err == nil {
			t.Errorf("a corrupted apk signature at %s was published", output.Path)
		}
	}
}

// A format that signs an index rather than each artifact predicts no paths:
// its signing shape follows from the repository's configuration alone, so it
// has nothing to say about which artifacts happen to be published.
func TestOnlyPerArtifactSignersPredictPaths(t *testing.T) {
	artifacts := []PublishedArtifact{{Filename: "x-1.0.0.tgz", SHA256: "aa"}}
	for _, name := range []string{"deb", "rpm", "apk"} {
		signing, err := SignerFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if paths := signing.PublishedPaths(artifacts); len(paths) != 0 {
			t.Errorf("format %q predicts %v, but signs an index", name, paths)
		}
	}
	helm, err := SignerFor("helm")
	if err != nil {
		t.Fatal(err)
	}
	if paths := helm.PublishedPaths(artifacts); len(paths) != 1 {
		t.Errorf("helm predicted %v, want one path per chart", paths)
	}
}

// The refusal an operator sees when a format cannot sign has to name it.
func TestUnsignedFormatErrorNamesTheFormat(t *testing.T) {
	_, err := SignerFor("pypi")
	if err == nil || !strings.Contains(err.Error(), "pypi") {
		t.Fatalf("error %v does not name the format", err)
	}
}

// A format declares the payload its signatures depend on and the schemes they
// use, and that declaration is what a plan is checked against before anything
// is rebuilt. It has to agree with what the format actually produces, or a
// valid plan is refused — or worse, an invalid one accepted.
func TestDeclaredNodesMatchTheShapes(t *testing.T) {
	realistic := map[string]struct {
		repository Repository
		published  []string
	}{
		"deb":  {Repository{Suite: "bookworm", Component: "main", Architectures: []string{"amd64", "arm64"}}, nil},
		"rpm":  {Repository{}, nil},
		"apk":  {Repository{Architectures: []string{"x86_64", "aarch64", "armv7"}}, nil},
		"helm": {Repository{}, []string{"charts/aa/x-1.0.0.tgz", "charts/bb/y-2.0.0.tgz"}},
	}
	for _, name := range Names() {
		signing, err := SignerFor(name)
		if err != nil {
			continue
		}
		shaped, covered := realistic[name]
		if !covered {
			t.Errorf("format %q signs but has no realistic repository here, so its declaration is unchecked", name)
			continue
		}
		shape, err := signing.SigningShape(shaped.repository, shaped.published)
		if err != nil {
			t.Fatalf("format %q: %v", name, err)
		}
		payloadID, schemes := signing.SigningNode()
		if payloadID != shape.PayloadID {
			t.Errorf("format %q declares payload %q but produces %q", name, payloadID, shape.PayloadID)
		}
		declared := map[string]bool{}
		for _, scheme := range schemes {
			declared[scheme] = true
		}
		produced := map[string]bool{}
		for _, output := range shape.Outputs {
			produced[output.Scheme] = true
			if !declared[output.Scheme] {
				t.Errorf("format %q produces scheme %q it does not declare", name, output.Scheme)
			}
		}
		// The other direction too: a declared scheme nothing produces would let
		// a plan carry a signature this format never makes.
		for scheme := range declared {
			if !produced[scheme] {
				t.Errorf("format %q declares scheme %q it never produces", name, scheme)
			}
		}
	}
}
