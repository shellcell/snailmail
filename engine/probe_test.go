package engine

import (
	"testing"

	"github.com/shellcell/snailmail/formats"
)

// knownSigningNode recognises a plan's signing nodes by asking each format what
// shape it produces, using fabricated inputs. This checks that answer against
// the shapes real repositories actually produce.
//
// It matters because the failure is quiet: an unrecognised node rejects a valid
// plan with a message about node identity, which is exactly how the hand-kept
// allow-list this replaced was found to be out of date.
func TestProbeMatchesRealShapes(t *testing.T) {
	real := []struct {
		name       string
		repository formats.Repository
		published  []string
	}{
		{"deb", formats.Repository{Suite: "bookworm", Component: "main", Architectures: []string{"amd64", "arm64"}}, nil},
		{"rpm", formats.Repository{}, nil},
		{"apk", formats.Repository{Architectures: []string{"x86_64", "aarch64", "armv7"}}, nil},
		{"helm", formats.Repository{}, []string{"charts/aa/x-1.0.0.tgz", "charts/bb/y-2.0.0.tgz"}},
	}
	// Every signing format must appear above. knownSigningNode probes the
	// formats with fabricated inputs, so a format whose shape depends on
	// something the probe does not supply would be silently unrecognised — the
	// same failure as the hand-kept allow-list this replaced, and harder to see.
	covered := make(map[string]bool, len(real))
	for _, c := range real {
		covered[c.name] = true
	}
	for _, name := range formats.Names() {
		if _, err := formats.SignerFor(name); err != nil {
			continue
		}
		if !covered[name] {
			t.Errorf("format %q signs but has no realistic shape here; the probe is unverified for it", name)
		}
	}
	for _, c := range real {
		signing, err := formats.SignerFor(c.name)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := signing.SigningShape(c.repository, c.published)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, output := range shape.Outputs {
			if !knownSigningNode(output.Scheme, shape.PayloadID) {
				t.Errorf("%s: a real node (%s, %s) is not recognised by the probe", c.name, output.Scheme, shape.PayloadID)
			}
		}
		if len(shape.Outputs) == 0 {
			t.Errorf("%s produced no outputs for a realistic repository", c.name)
		}
	}
	// And it must still reject what no format produces.
	if knownSigningNode("openpgp-cleartext-v4", "invented-payload") {
		t.Error("the probe accepted an invented payload identifier")
	}
	if knownSigningNode("invented-scheme", "deb-release") {
		t.Error("the probe accepted an invented scheme")
	}
}
