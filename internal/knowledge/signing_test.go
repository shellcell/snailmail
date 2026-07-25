package knowledge

import "testing"

func TestSigningCompatibilityTable(t *testing.T) {
	if !Compatible("deb", "openpgp-rsa4096") || !Compatible("rpm", "openpgp-rsa4096") || Compatible("rpm", "openpgp-ed25519") || Compatible("nix", "openpgp-rsa4096") || Compatible("pypi", "openpgp-rsa4096") {
		t.Fatal("signing compatibility table does not enforce format constraints")
	}
	if len(SigningDigest()) != 64 || SigningDigest() != SigningDigest() {
		t.Fatal("signing knowledge digest is not stable")
	}
}
