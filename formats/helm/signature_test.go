package helm

import (
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

func unsignedArtifact(t *testing.T, charts ...string) domain.RepositoryArtifact {
	t.Helper()
	files := []domain.File{{Path: "index.yaml", Content: []byte("apiVersion: v1\n")}}
	for _, chart := range charts {
		files = append(files, domain.File{Path: chart, BlobSHA256: strings.Repeat("a", 64), Size: 1})
	}
	return domain.RepositoryArtifact{Format: FormatID, Files: files}
}

// A repository where some charts are signed and others are not fails
// `helm install --verify` on exactly the charts nobody checked, which reads as
// a broken repository rather than as the partial signing it is.
func TestApplySigningRefusesPartialCoverage(t *testing.T) {
	artifact := unsignedArtifact(t, "charts/aa/one-1.0.0.tgz", "charts/bb/two-1.0.0.tgz")
	_, err := ApplySigning(artifact, SigningMaterial{
		Fingerprint: strings.Repeat("f", 40), KeyringPath: "keys/x.gpg",
		SignatureTime: time.Unix(1, 0).UTC(),
		Provenance:    map[string][]byte{"charts/aa/one-1.0.0.tgz": []byte("x")},
	})
	if err == nil || !strings.Contains(err.Error(), "2 charts but 1 provenance") {
		t.Fatalf("partial coverage was not refused: %v", err)
	}
}

// A provenance file naming something the repository does not publish would be
// a signature over bytes no client can fetch.
func TestApplySigningRefusesUnknownChart(t *testing.T) {
	artifact := unsignedArtifact(t, "charts/aa/one-1.0.0.tgz")
	_, err := ApplySigning(artifact, SigningMaterial{
		Fingerprint: strings.Repeat("f", 40), KeyringPath: "keys/x.gpg",
		SignatureTime: time.Unix(1, 0).UTC(),
		Provenance:    map[string][]byte{"charts/zz/other-9.9.9.tgz": []byte("x")},
	})
	if err == nil {
		t.Fatal("provenance for a chart the repository does not publish was accepted")
	}
}

// helm reads a binary keyring, not the armored form yum imports, so publishing
// the wrong shape would give a client a file it cannot use.
func TestApplySigningRequiresAKeyringPath(t *testing.T) {
	artifact := unsignedArtifact(t, "charts/aa/one-1.0.0.tgz")
	for _, keyringPath := range []string{"keys/x.asc", "x.gpg", "/keys/x.gpg", "keys/../x.gpg", ""} {
		_, err := ApplySigning(artifact, SigningMaterial{
			Fingerprint: strings.Repeat("f", 40), KeyringPath: keyringPath,
			SignatureTime: time.Unix(1, 0).UTC(),
			Provenance:    map[string][]byte{"charts/aa/one-1.0.0.tgz": []byte("x")},
		})
		if err == nil {
			t.Errorf("accepted %q as a published keyring path", keyringPath)
		}
	}
}

// The body is what the signature covers, so recovering it wrongly would check
// the signature against something other than what a client reads.
func TestClearSignedBody(t *testing.T) {
	document := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" +
		"name: demo\n\n...\nfiles:\n  demo-1.0.0.tgz: sha256:aa\n" +
		"\n-----BEGIN PGP SIGNATURE-----\nxx\n-----END PGP SIGNATURE-----\n"
	body, err := clearSignedBody([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "name: demo\n\n...\nfiles:\n  demo-1.0.0.tgz: sha256:aa\n" {
		t.Fatalf("recovered body is not the signed document: %q", body)
	}
	for _, broken := range []string{"", "no blank line", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nbody with no signature\n"} {
		if _, err := clearSignedBody([]byte(broken)); err == nil {
			t.Errorf("accepted a malformed clear-signed message: %q", broken)
		}
	}
}
