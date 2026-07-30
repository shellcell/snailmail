package engine

import (
	"os"
	"testing"
)

// The limit is a memory bound, not a statement about how large a package may be —
// and real packages exceed it. 0ad-data in Debian bookworm is over 128 MiB, so a
// constant would make it unadoptable at any setting.
func TestTheArtifactLimitCanBeRaised(t *testing.T) {
	if maximumArtifactBytes() != DefaultMaxArtifactBytes {
		t.Fatalf("default is %d", maximumArtifactBytes())
	}
	t.Setenv(MaxArtifactBytesEnvironment, "536870912")
	if got := maximumArtifactBytes(); got != 512<<20 {
		t.Errorf("raised limit = %d, want 512 MiB", got)
	}
}

// A typo must not refuse every artifact, which would be a worse failure than the
// one the limit prevents.
func TestNonsenseInTheArtifactLimitIsIgnored(t *testing.T) {
	for _, nonsense := range []string{"lots", "-1", "0", "128MB", " "} {
		t.Setenv(MaxArtifactBytesEnvironment, nonsense)
		if got := maximumArtifactBytes(); got != DefaultMaxArtifactBytes {
			t.Errorf("%q gave limit %d, want the default", nonsense, got)
		}
	}
	os.Unsetenv(MaxArtifactBytesEnvironment)
}
