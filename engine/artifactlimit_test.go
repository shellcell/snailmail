package engine

import (
	"os"
	"testing"
)

// The limit stops a server handing over something absurd; it is no longer a memory
// bound, because adoption spools to a file. It stays liftable for the same reason
// the lock limit is: someone who has read the message should be able to proceed.
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
