package host

import (
	"slices"
	"testing"
)

// An unknown pair must be unsupported rather than accidentally permitted, so
// that a new host or format is opt-in.
func TestSupportsDeniesUnknownPairs(t *testing.T) {
	for _, pair := range [][2]string{
		{"", ""},
		{"rsync", "pypi"},
		// cargo has no format implementation, so no host can serve it.
		{"local", "cargo"},
		// An object store commits one object, so a format qualifies only if one
		// path makes a revision live: Debian needs a Release and its detached
		// signature together, Alpine has an index per architecture, raw has a
		// listing and a SHA256SUMS. A signed yum repository is in the same
		// position and would be refused by the adapter's path count. Helm and
		// unsigned yum qualify on path count and are still undeclared, for the
		// reason recorded in support.go.
		{"s3", "helm"},
		{"s3", "rpm"},
		{"s3", "deb"},
		{"s3", "apk"},
		{"s3", "raw"},
	} {
		support := Supports(pair[0], pair[1])
		if support.Publish || support.RemoteClientVerification || support.InstallDocument {
			t.Errorf("host %q format %q is permitted by default: %+v", pair[0], pair[1], support)
		}
	}
}

// A capability that implies publication cannot be declared without it, or a
// pair could be verified or documented but never served.
func TestDeclaredCapabilitiesImplyPublication(t *testing.T) {
	for _, hostType := range KnownHostTypes() {
		for _, format := range []string{"pypi", "deb", "helm"} {
			support := Supports(hostType, format)
			if (support.RemoteClientVerification || support.InstallDocument) && !support.Publish {
				t.Errorf("host %q format %q declares a capability without publication: %+v", hostType, format, support)
			}
		}
	}
}

// A local directory is verified against the directory itself, never through a
// served endpoint, so claiming the remote probe would route to code that does
// not run for it.
func TestLocalHostDeclaresNoRemoteCapabilities(t *testing.T) {
	for _, format := range SupportedFormats("local") {
		support := Supports("local", format)
		if support.RemoteClientVerification {
			t.Errorf("local host claims remote client verification for %q", format)
		}
		if support.InstallDocument {
			t.Errorf("local host claims an install document for %q, which needs a public endpoint", format)
		}
	}
}

// Publication without client verification would let a remote host commit bytes
// no official client ever installed, which is the guarantee the tool sells.
func TestRemotePublicationAlwaysCarriesClientVerification(t *testing.T) {
	for _, hostType := range KnownHostTypes() {
		if hostType == "local" {
			continue
		}
		for _, format := range SupportedFormats(hostType) {
			if !Supports(hostType, format).RemoteClientVerification {
				t.Errorf("remote host %q publishes %q without client verification", hostType, format)
			}
		}
	}
}

func TestSupportedFormatsIsStableAndPublishOnly(t *testing.T) {
	for _, hostType := range KnownHostTypes() {
		formats := SupportedFormats(hostType)
		if !slices.IsSorted(formats) {
			t.Errorf("host %q formats are unsorted: %v", hostType, formats)
		}
		for _, format := range formats {
			if !Supports(hostType, format).Publish {
				t.Errorf("host %q lists non-publishable format %q", hostType, format)
			}
		}
	}
	if len(SupportedFormats("nonexistent")) != 0 {
		t.Fatal("an unknown host type reports supported formats")
	}
}

// The matrix is the contract every host adapter is validated against, so the
// adapters that exist must appear in it.
func TestKnownHostTypesCoversEveryImplementedHost(t *testing.T) {
	for _, hostType := range []string{"local", "s3", "github-pages"} {
		if !slices.Contains(KnownHostTypes(), hostType) {
			t.Errorf("implemented host %q is absent from the support matrix", hostType)
		}
		if len(SupportedFormats(hostType)) == 0 {
			t.Errorf("implemented host %q serves no format", hostType)
		}
	}
}
