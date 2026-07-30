package engine

import (
	"testing"

	"github.com/shellcell/snailmail/internal/state"
)

// collect is the one operation here that deletes published bytes, and its policy
// used to live in whichever CI job someone wrote. These pin the order of
// precedence, because getting it backwards means a hand-run collection quietly
// reclaiming more than the team agreed.
func TestTheManifestIsThePolicyAndTheFlagIsTheOverride(t *testing.T) {
	declared := state.Repository{Keep: 3}
	if got := retentionFor(declared, nil); got != 3 {
		t.Errorf("with no override, retention = %d, want the declared 3", got)
	}
	override := 7
	if got := retentionFor(declared, &override); got != 7 {
		t.Errorf("with an override, retention = %d, want 7", got)
	}
}

// A repository that declares nothing keeps working exactly as before, which is
// every repository configured until now.
func TestAnUndeclaredRetentionFallsBackToTheDefault(t *testing.T) {
	if got := retentionFor(state.Repository{}, nil); got != DefaultKeep {
		t.Errorf("retention = %d, want the default %d", got, DefaultKeep)
	}
}

// Zero is a real answer — keep nothing beyond what the host protects — and must
// not be read as "unspecified". That is why the override is a pointer.
func TestZeroIsARetentionAndNotAnAbsentOne(t *testing.T) {
	none := 0
	if got := retentionFor(state.Repository{Keep: 9}, &none); got != 0 {
		t.Errorf("an explicit zero gave %d, want 0", got)
	}
}
