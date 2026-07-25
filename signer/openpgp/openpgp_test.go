package openpgpsigner

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shellcell/snailmail/signer"
)

func TestGenerateLoadAndDeterministicallySign(t *testing.T) {
	createdAt := time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC)
	passphrase := []byte("correct horse battery staple")
	generated, err := Generate("archive-signing", createdAt, 365*24*time.Hour, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(generated.PrivateArmor, passphrase) {
		t.Fatal("encrypted private key contains plaintext passphrase")
	}
	binaryIdentity, err := InspectPublic(generated.PublicBinary)
	if err != nil {
		t.Fatal(err)
	}
	armorIdentity, err := InspectArmoredPublic(generated.PublicArmor)
	if err != nil {
		t.Fatal(err)
	}
	if binaryIdentity != generated.Identity || armorIdentity != generated.Identity || generated.Identity.Algorithm != signer.AlgorithmOpenPGPRSA4096 || generated.Identity.Bits != 4096 {
		t.Fatalf("inconsistent generated identity: %#v %#v %#v", generated.Identity, binaryIdentity, armorIdentity)
	}
	local, err := Load(generated.PrivateArmor, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	payload := []byte("Origin: snailmail\nSuite: stable\n")
	responses := make(map[string]signer.Response)
	for _, scheme := range []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached} {
		request := signer.Request{Scheme: scheme, Payload: payload, CreatedAt: createdAt.Add(time.Hour)}
		first, err := local.Sign(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		second, err := local.Sign(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Content, second.Content) {
			t.Fatalf("%s output is not deterministic", scheme)
		}
		if err := VerifyResponse(request, first, generated.PublicBinary, generated.Identity.Fingerprint); err != nil {
			t.Fatal(err)
		}
		responses[scheme] = first
		request.Payload = append([]byte(nil), payload...)
		request.Payload[0] ^= 1
		if err := VerifyResponse(request, first, generated.PublicBinary, generated.Identity.Fingerprint); err == nil {
			t.Fatalf("%s accepted changed payload", scheme)
		}
	}
	gpgv, err := exec.LookPath("gpgv")
	if err != nil {
		return
	}
	directory := t.TempDir()
	for name, content := range map[string][]byte{
		"archive.gpg": generated.PublicBinary,
		"Release":     payload,
		"Release.gpg": responses[signer.SchemeOpenPGPDetached].Content,
		"InRelease":   responses[signer.SchemeOpenPGPCleartext].Content,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arguments := range [][]string{
		{"--keyring", filepath.Join(directory, "archive.gpg"), filepath.Join(directory, "Release.gpg"), filepath.Join(directory, "Release")},
		{"--keyring", filepath.Join(directory, "archive.gpg"), filepath.Join(directory, "InRelease")},
	} {
		if output, err := exec.Command(gpgv, arguments...).CombinedOutput(); err != nil {
			t.Fatalf("gpgv interoperability: %v: %s", err, output)
		}
	}
	if aptGet, err := exec.LookPath("apt-get"); err == nil {
		verifyAPT(t, aptGet, local, generated.PublicBinary, createdAt.Add(2*time.Hour))
	}
}

func TestCombinedKeyringSupportsRotationSigners(t *testing.T) {
	gpgv, err := exec.LookPath("gpgv")
	if err != nil {
		t.Skip("gpgv is unavailable")
	}
	createdAt := time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC)
	passphrase := []byte("rotation interoperability secret")
	oldGenerated, err := Generate("archive-old", createdAt, 365*24*time.Hour, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	newGenerated, err := Generate("archive-new", createdAt.Add(time.Hour), 365*24*time.Hour, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	oldLocal, err := Load(oldGenerated.PrivateArmor, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer oldLocal.Close()
	newLocal, err := Load(newGenerated.PrivateArmor, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer newLocal.Close()
	combined := append(append([]byte(nil), oldGenerated.PublicBinary...), newGenerated.PublicBinary...)
	identities, err := InspectPublicKeyring(combined)
	if err != nil || len(identities) != 2 || identities[0].Fingerprint != oldGenerated.Identity.Fingerprint || identities[1].Fingerprint != newGenerated.Identity.Fingerprint {
		t.Fatalf("combined keyring identities=%#v err=%v", identities, err)
	}
	payload := []byte("Origin: snailmail\nSuite: stable\n")
	directory := t.TempDir()
	for label, fixture := range map[string]struct {
		local *Local
		time  time.Time
	}{"old": {oldLocal, createdAt.Add(2 * time.Hour)}, "new": {newLocal, createdAt.Add(2 * time.Hour)}} {
		response, err := fixture.local.Sign(context.Background(), signer.Request{Scheme: signer.SchemeOpenPGPDetached, Payload: payload, CreatedAt: fixture.time})
		if err != nil {
			t.Fatal(err)
		}
		keyringName := filepath.Join(directory, "combined.gpg")
		payloadName := filepath.Join(directory, "Release")
		signatureName := filepath.Join(directory, label+".gpg")
		for name, content := range map[string][]byte{keyringName: combined, payloadName: payload, signatureName: response.Content} {
			if err := os.WriteFile(name, content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if output, err := exec.Command(gpgv, "--keyring", keyringName, signatureName, payloadName).CombinedOutput(); err != nil {
			t.Fatalf("combined keyring rejected %s signer: %v: %s", label, err, output)
		}
	}
	if aptGet, err := exec.LookPath("apt-get"); err == nil {
		verifyAPT(t, aptGet, oldLocal, combined, createdAt.Add(3*time.Hour))
		verifyAPT(t, aptGet, newLocal, combined, createdAt.Add(3*time.Hour))
	}
}

func verifyAPT(t *testing.T, aptGet string, local *Local, publicKeyring []byte, signatureTime time.Time) {
	t.Helper()
	directory := t.TempDir()
	repository := filepath.Join(directory, "repository")
	packagesDirectory := filepath.Join(repository, "dists", "stable", "main", "binary-amd64")
	if err := os.MkdirAll(packagesDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	packages := []byte{}
	md5Digest := md5.Sum(packages)
	sha1Digest := sha1.Sum(packages)
	sha256Digest := sha256.Sum256(packages)
	relativePackages := "main/binary-amd64/Packages"
	release := []byte(fmt.Sprintf(
		"Origin: snailmail\nLabel: snailmail\nSuite: stable\nCodename: stable\nDate: %s\nArchitectures: amd64\nComponents: main\nDescription: signing interoperability\nMD5Sum:\n %s 0 %s\nSHA1:\n %s 0 %s\nSHA256:\n %s 0 %s\n",
		signatureTime.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"),
		hex.EncodeToString(md5Digest[:]), relativePackages, hex.EncodeToString(sha1Digest[:]), relativePackages, hex.EncodeToString(sha256Digest[:]), relativePackages,
	))
	responses := make(map[string]signer.Response)
	for _, scheme := range []string{signer.SchemeOpenPGPCleartext, signer.SchemeOpenPGPDetached} {
		response, err := local.Sign(context.Background(), signer.Request{Scheme: scheme, Payload: release, CreatedAt: signatureTime})
		if err != nil {
			t.Fatal(err)
		}
		responses[scheme] = response
	}
	files := map[string][]byte{
		filepath.Join(packagesDirectory, "Packages"):                packages,
		filepath.Join(repository, "dists", "stable", "Release"):     release,
		filepath.Join(repository, "dists", "stable", "InRelease"):   responses[signer.SchemeOpenPGPCleartext].Content,
		filepath.Join(repository, "dists", "stable", "Release.gpg"): responses[signer.SchemeOpenPGPDetached].Content,
		filepath.Join(directory, "archive.gpg"):                     publicKeyring,
	}
	for name, content := range files {
		if err := os.WriteFile(name, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sources := filepath.Join(directory, "sources.list")
	if err := os.WriteFile(sources, []byte(fmt.Sprintf("deb [signed-by=%s arch=amd64] file:%s stable main\n", filepath.Join(directory, "archive.gpg"), repository)), 0o600); err != nil {
		t.Fatal(err)
	}
	lists := filepath.Join(directory, "lists")
	archives := filepath.Join(directory, "archives")
	for _, name := range []string{filepath.Join(lists, "partial"), filepath.Join(archives, "partial")} {
		if err := os.MkdirAll(name, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	arguments := []string{
		"-o", "Dir::Etc::sourcelist=" + sources, "-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists=" + lists, "-o", "Dir::State::status=/var/lib/dpkg/status",
		"-o", "Dir::Cache::archives=" + archives, "-o", "APT::Sandbox::User=root",
		"-o", "Acquire::Languages=none", "-o", "Debug::NoLocking=1", "update",
	}
	if output, err := exec.Command(aptGet, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("apt signed-by interoperability: %v: %s", err, output)
	}
}
