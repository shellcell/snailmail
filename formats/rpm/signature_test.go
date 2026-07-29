package rpm

import (
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

// A signature that does not verify is worse than none: a client reports it as
// tampering rather than as an unsigned repository, so it must never be
// published in the first place.
func TestApplySigningRefusesASignatureThatDoesNotVerify(t *testing.T) {
	artifact := buildRepository(t, realBlob(t))
	_, err := ApplySigning(artifact, SigningMaterial{
		Fingerprint: strings.Repeat("a", 40), PublicKey: []byte("not a key"),
		PublicArmor: []byte("not armored"), ArmorPath: "keys/demo-archive-keyring.asc",
		SignatureTime: time.Unix(1700000000, 0).UTC(), Signature: []byte("not a signature"),
	})
	if err == nil {
		t.Fatal("an unverifiable signature was published")
	}
}

func TestApplySigningRejectsUnusableInput(t *testing.T) {
	artifact := buildRepository(t, realBlob(t))
	for name, material := range map[string]SigningMaterial{
		"no signature":     {ArmorPath: "keys/k.asc", SignatureTime: time.Unix(1, 0).UTC()},
		"no time":          {ArmorPath: "keys/k.asc", Signature: []byte("x")},
		"absolute path":    {ArmorPath: "/keys/k.asc", SignatureTime: time.Unix(1, 0).UTC(), Signature: []byte("x")},
		"escaping path":    {ArmorPath: "keys/../k.asc", SignatureTime: time.Unix(1, 0).UTC(), Signature: []byte("x")},
		"outside keys":     {ArmorPath: "elsewhere/k.asc", SignatureTime: time.Unix(1, 0).UTC(), Signature: []byte("x")},
		"not armored form": {ArmorPath: "keys/k.gpg", SignatureTime: time.Unix(1, 0).UTC(), Signature: []byte("x")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ApplySigning(artifact, material); err == nil {
				t.Fatal("unusable signing input was accepted")
			}
		})
	}
}

// repomd.xml is the document every index is reached through, so it is the one
// a signature has to cover.
func TestRepomdPayloadIsTheDocumentClientsRead(t *testing.T) {
	artifact := buildRepository(t, realBlob(t))
	payload, err := RepomdPayload(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Files {
		if file.Path == RepomdPath {
			if string(payload) != string(file.Content) {
				t.Fatal("the signed payload is not the published repomd.xml")
			}
			return
		}
	}
	t.Fatal("no repomd.xml was generated")
}

func TestRepomdPayloadRejectsAnotherFormat(t *testing.T) {
	if _, err := RepomdPayload(domain.RepositoryArtifact{Format: "deb/v1"}); err == nil {
		t.Fatal("a foreign artifact was accepted")
	}
}
