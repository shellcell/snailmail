package state

import "testing"

// Every lock written before this field existed recorded an origin only through
// adopt, where a person supplied the digest. So an absent value is not unknown,
// it is operator — and reading it any other way would relabel every existing
// workspace as weaker than it is.
func TestAnAbsentProvenanceReadsAsOperator(t *testing.T) {
	for name, blob := range map[string]LockedBlob{
		"no origin at all":          {SHA256: "aa"},
		"origin without provenance": {SHA256: "aa", Origin: &ArtifactOrigin{Kind: "https", URL: "https://example.test/a"}},
	} {
		if got := DigestProvenanceOf(blob); got != ProvenanceOperator {
			t.Errorf("%s read as %q, want %q", name, got, ProvenanceOperator)
		}
	}
}

func TestARecordedProvenanceIsReadBack(t *testing.T) {
	blob := LockedBlob{SHA256: "aa", Origin: &ArtifactOrigin{
		Kind: "https", URL: "https://example.test/a", Provenance: ProvenanceIndexStated,
	}}
	if got := DigestProvenanceOf(blob); got != ProvenanceIndexStated {
		t.Errorf("read %q, want %q", got, ProvenanceIndexStated)
	}
}

// The levels are ordered so a workspace can state a floor once rather than
// inspecting each artifact. The order is a claim about strength, so it is worth
// pinning: a signed index is stronger than an operator's word, which is stronger
// than a chain nobody authenticated, which beats a bare index statement, which
// beats a digest snailmail computed off whatever arrived.
func TestProvenanceIsOrderedByStrength(t *testing.T) {
	strongest := []DigestProvenance{
		ProvenanceSignedIndex, ProvenanceOperator, ProvenanceIndexChain,
		ProvenanceIndexStated, ProvenanceComputed,
	}
	for index := 1; index < len(strongest); index++ {
		stronger, weaker := strongest[index-1], strongest[index]
		if !stronger.AtLeast(weaker) {
			t.Errorf("%q does not meet the floor %q", stronger, weaker)
		}
		if weaker.AtLeast(stronger) {
			t.Errorf("%q meets the floor %q, but it is weaker", weaker, stronger)
		}
	}
	// A level always meets its own floor, which is what makes a floor usable as an
	// equality as well as a minimum.
	for _, provenance := range strongest {
		if !provenance.AtLeast(provenance) {
			t.Errorf("%q does not meet its own floor", provenance)
		}
	}
}

// A lock is reviewed and hand-editable, so a value nobody recognises has to be
// refused on read. Left unchecked it would compare as weaker than everything,
// which is the opposite of how an unrecognised claim should be treated.
func TestAnUnknownProvenanceIsRefused(t *testing.T) {
	if ValidProvenance("trust-me") {
		t.Error("an invented provenance was accepted")
	}
	for _, known := range []DigestProvenance{
		ProvenanceSignedIndex, ProvenanceIndexChain, ProvenanceIndexStated,
		ProvenanceComputed, ProvenanceOperator,
	} {
		if !ValidProvenance(known) {
			t.Errorf("%q is not recognised", known)
		}
	}
	err := ValidateArtifactOrigin(ArtifactOrigin{
		Kind: "https", URL: "https://example.test/a", Provenance: "trust-me",
	})
	if err == nil {
		t.Fatal("an origin carrying an invented provenance was accepted")
	}
	// An empty one is not invented, it is a lock written before the field existed.
	if err := ValidateArtifactOrigin(ArtifactOrigin{Kind: "https", URL: "https://example.test/a"}); err != nil {
		t.Errorf("an origin from an older lock was refused: %v", err)
	}
}
