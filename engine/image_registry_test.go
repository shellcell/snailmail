package engine

import (
	"strings"
	"testing"
)

// A digest names the same bytes wherever it is served, so moving a pinned
// reference to a mirror changes the transport and nothing else.
func TestImageWithRegistryKeepsTheDigest(t *testing.T) {
	for reference, want := range map[string]string{
		DefaultDebianVerificationImage: "mirror.gcr.io/library/debian@" + digestOf(DefaultDebianVerificationImage),
		DefaultRPMVerificationImage:    "mirror.gcr.io/library/fedora@" + digestOf(DefaultRPMVerificationImage),
		DefaultAPKVerificationImage:    "mirror.gcr.io/library/alpine@" + digestOf(DefaultAPKVerificationImage),
		// alpine/helm is a Docker Hub organisation, not a registry host, so the
		// first segment is part of the repository and must survive the move.
		DefaultHelmVerificationImage: "mirror.gcr.io/alpine/helm@" + digestOf(DefaultHelmVerificationImage),
	} {
		got, err := ImageWithRegistry(reference, "mirror.gcr.io")
		if err != nil {
			t.Fatalf("%s: %v", reference, err)
		}
		if got != want {
			t.Errorf("ImageWithRegistry(%q) = %q, want %q", reference, got, want)
		}
	}
}

// A reference with no registry host at all is a Docker Hub short form; every
// segment of it is repository.
func TestImageWithRegistryHandlesShortForms(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	for reference, want := range map[string]string{
		"alpine" + digest:             "mirror.gcr.io/alpine" + digest,
		"library/alpine" + digest:     "mirror.gcr.io/library/alpine" + digest,
		"localhost:5000/x" + digest:   "mirror.gcr.io/x" + digest,
		"registry.example/x" + digest: "mirror.gcr.io/x" + digest,
		"docker.io/a/b/c" + digest:    "mirror.gcr.io/a/b/c" + digest,
		"quay.io/team/tool" + digest:  "mirror.gcr.io/team/tool" + digest,
		"ghcr.io/owner/name" + digest: "mirror.gcr.io/owner/name" + digest,
		"public.ecr.aws/x/y" + digest: "mirror.gcr.io/x/y" + digest,
	} {
		got, err := ImageWithRegistry(reference, "mirror.gcr.io")
		if err != nil {
			t.Fatalf("%s: %v", reference, err)
		}
		if got != want {
			t.Errorf("ImageWithRegistry(%q) = %q, want %q", reference, got, want)
		}
	}
}

// A tag means whatever the registry serving it decided, so moving one would
// change what is verified without saying so. That is the whole reason this is
// safe for digests, and it must not be quietly extended.
func TestImageWithRegistryRefusesAnUnpinnedReference(t *testing.T) {
	for _, reference := range []string{
		"alpine:3.21",
		"docker.io/library/alpine:latest",
		"docker.io/library/alpine",
		"docker.io/library/alpine@md5:abc",
	} {
		if _, err := ImageWithRegistry(reference, "mirror.gcr.io"); err == nil {
			t.Errorf("moved an unpinned reference: %q", reference)
		}
	}
}

// No override means no change, including for references this would otherwise
// refuse: a workspace that never asked for a mirror must not start failing
// because its image is tag-based.
func TestImageWithRegistryIsInertWithoutOne(t *testing.T) {
	for _, reference := range []string{"alpine:3.21", DefaultAPKVerificationImage, ""} {
		got, err := ImageWithRegistry(reference, "")
		if err != nil || got != reference {
			t.Errorf("ImageWithRegistry(%q, \"\") = %q, %v; want it left alone", reference, got, err)
		}
	}
}

func TestImageWithRegistryRejectsANonsenseRegistry(t *testing.T) {
	for _, registry := range []string{"mirror.gcr.io/", "/mirror.gcr.io", "a b", "host@x"} {
		if _, err := ImageWithRegistry(DefaultAPKVerificationImage, registry); err == nil {
			t.Errorf("accepted %q as a registry host", registry)
		}
	}
}

func digestOf(reference string) string {
	_, digest, _ := strings.Cut(reference, "@")
	return digest
}
