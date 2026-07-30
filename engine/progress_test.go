package engine

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// collectProgress records every event, safely, because repositories are prepared
// concurrently and the callback is called from each of those goroutines.
type progressLog struct {
	mutex  sync.Mutex
	events []ApplyEvent
}

func (log *progressLog) record(event ApplyEvent) {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	log.events = append(log.events, event)
}

func (log *progressLog) snapshot() []ApplyEvent {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	return append([]ApplyEvent(nil), log.events...)
}

func (log *progressLog) phases() map[ApplyPhase]int {
	counts := make(map[ApplyPhase]int)
	for _, event := range log.snapshot() {
		counts[event.Phase]++
	}
	return counts
}

func appliedWithProgress(t *testing.T, formats ...string) *progressLog {
	t.Helper()
	root := multiRepositoryWorkspace(t, formats...)
	planName := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	log := &progressLog{}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true, Progress: log.record,
	}); err != nil {
		t.Fatal(err)
	}
	return log
}

// A publication takes minutes, and reporting nothing until it finishes means a
// caller cannot tell a slow apply from a hung one. Every phase has to report, or
// the silence just moves to whichever one does not.
func TestApplyReportsEveryPhase(t *testing.T) {
	log := appliedWithProgress(t, "pypi", "deb")
	counts := log.phases()
	for _, phase := range []ApplyPhase{PhasePrepare, PhaseAuthorize, PhaseStage, PhaseRecord, PhasePublish} {
		if counts[phase] == 0 {
			t.Errorf("phase %q reported nothing; events were %+v", phase, log.snapshot())
		}
	}
}

// The per-repository phases have to name their repository and place it in the
// run. "preparing" with no name tells a reader nothing when five repositories are
// being prepared at once.
func TestPerRepositoryEventsNameTheirRepository(t *testing.T) {
	log := appliedWithProgress(t, "pypi", "deb")
	seen := map[ApplyPhase]map[string]bool{}
	for _, event := range log.snapshot() {
		switch event.Phase {
		case PhasePrepare, PhaseAuthorize, PhaseStage:
			if event.Repository == "" {
				t.Errorf("%s reported no repository", event.Phase)
				continue
			}
			if event.Total != 2 {
				t.Errorf("%s on %q reported total %d, want 2", event.Phase, event.Repository, event.Total)
			}
			if event.Index < 1 || event.Index > event.Total {
				t.Errorf("%s on %q reported index %d of %d", event.Phase, event.Repository, event.Index, event.Total)
			}
			if seen[event.Phase] == nil {
				seen[event.Phase] = map[string]bool{}
			}
			seen[event.Phase][event.Repository] = true
		}
	}
	for phase, repositories := range seen {
		for _, want := range []string{"pypi", "deb"} {
			if !repositories[want] {
				t.Errorf("phase %s never reported repository %q", phase, want)
			}
		}
	}
}

// Prepare is the slow phase — building, fetching and verifying — so it is the one
// whose absence would leave the silence this exists to remove.
func TestPrepareReportsOncePerRepository(t *testing.T) {
	log := appliedWithProgress(t, "pypi", "deb", "helm")
	prepared := 0
	for _, event := range log.snapshot() {
		if event.Phase == PhasePrepare {
			prepared++
			if event.Detail == "" {
				t.Errorf("prepare on %q said nothing about the outcome", event.Repository)
			}
		}
	}
	if prepared != 3 {
		t.Errorf("prepare reported %d times for 3 repositories", prepared)
	}
}

// A nil callback is what every caller that only wants the result passes, and it
// must not be a special case anyone has to remember.
func TestApplyWithoutProgressStillWorks(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi")
	planName := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
}

// Events arrive in the order the phases happen. A reader watching the stream uses
// that order to know how far along a publication is, so record and publish must
// not appear before the repositories they cover have been staged.
func TestPhasesAreReportedInOrder(t *testing.T) {
	events := appliedWithProgress(t, "pypi", "deb").snapshot()
	rank := map[ApplyPhase]int{
		PhasePrepare: 0, PhaseAuthorize: 1, PhaseStage: 2, PhaseRecord: 3, PhasePublish: 4,
	}
	highest := -1
	for _, event := range events {
		at, known := rank[event.Phase]
		if !known {
			t.Fatalf("unknown phase %q", event.Phase)
		}
		if at < highest {
			t.Errorf("phase %q reported after a later phase; order was %+v", event.Phase, events)
			break
		}
		if at > highest {
			highest = at
		}
	}
}

// A dry run reaches no further than reads: nothing staged, no ledger committed,
// no revision switched. StructuralOnly does not do this — it only lowers
// verification depth and still publishes — so the two must not be confused.
func TestDryRunWritesNothingToTheHost(t *testing.T) {
	root := multiRepositoryWorkspace(t, "pypi")
	planName := filepath.Join(root, "plan.json")
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	log := &progressLog{}
	result, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true, DryRun: true, Progress: log.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun {
		t.Error("the result does not say it was a dry run, so Applied reads as published")
	}
	if result.Applied != 1 {
		t.Errorf("would apply %d, want 1", result.Applied)
	}
	// The host is a directory in the fixture, so its absence is the proof.
	if entries, err := os.ReadDir(filepath.Join(root, "public", "pypi")); err == nil && len(entries) != 0 {
		t.Errorf("a dry run wrote %d entries under public/", len(entries))
	}
	// It stops before staging, and says so by not claiming to have staged.
	for _, event := range log.snapshot() {
		if event.Phase == PhaseStage || event.Phase == PhaseRecord || event.Phase == PhasePublish {
			t.Errorf("a dry run reported phase %q", event.Phase)
		}
	}
	// And a real apply afterwards still publishes, so a dry run leaves nothing
	// behind that blocks the thing it was previewing.
	if _, err := PlanWorkspace(context.Background(), PlanWorkspaceRequest{
		Root: root, Output: planName, ExpiresIn: time.Hour, VerificationMode: "structural",
	}); err != nil {
		t.Fatal(err)
	}
	applied, err := ApplyWorkspace(context.Background(), ApplyWorkspaceRequest{
		Root: root, Plan: planName, StructuralOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.DryRun || applied.Applied != 1 {
		t.Errorf("the apply after a dry run gave %+v", applied)
	}
}
