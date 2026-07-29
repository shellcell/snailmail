package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shellcell/snailmail/internal/domain"
)

func cases(count int) []domain.VerificationCase {
	made := make([]domain.VerificationCase, 0, count)
	for index := range count {
		made = append(made, domain.VerificationCase{Package: fmt.Sprintf("p%d", index), Version: "1"})
	}
	return made
}

func TestVerifyCasesRunsEveryCase(t *testing.T) {
	var mutex sync.Mutex
	seen := map[string]bool{}
	if err := verifyCases(context.Background(), cases(9), func(_ context.Context, verification domain.VerificationCase) error {
		mutex.Lock()
		defer mutex.Unlock()
		if seen[verification.Package] {
			t.Errorf("case %s was verified twice", verification.Package)
		}
		seen[verification.Package] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 9 {
		t.Fatalf("verified %d cases, want 9", len(seen))
	}
}

// A failed publication must name the same case every time, or the same defect
// reads as a different problem on each run.
func TestVerifyCasesReportsTheFirstFailureInOrder(t *testing.T) {
	for range 20 {
		err := verifyCases(context.Background(), cases(8), func(_ context.Context, verification domain.VerificationCase) error {
			if verification.Package == "p3" || verification.Package == "p6" {
				return errors.New(verification.Package + " failed")
			}
			return nil
		})
		if err == nil || err.Error() != "p3 failed" {
			t.Fatalf("got %v, want the earliest failing case p3", err)
		}
	}
}

// Every case runs even once one has failed. That is what makes the reported
// case deterministic: a case skipped because a sibling failed first cannot be
// compared against the ones that did run, and the earliest failure would depend
// on which container won the race for a slot.
func TestVerifyCasesRunsEveryCaseEvenAfterAFailure(t *testing.T) {
	var started atomic.Int64
	err := verifyCases(context.Background(), cases(32), func(_ context.Context, verification domain.VerificationCase) error {
		started.Add(1)
		if verification.Package == "p0" {
			return errors.New("refused")
		}
		return nil
	})
	if err == nil || err.Error() != "refused" {
		t.Fatalf("got %v, want the failing case reported", err)
	}
	if count := started.Load(); count != 32 {
		t.Fatalf("ran %d of 32 cases; skipping any makes the reported failure depend on scheduling", count)
	}
}

// Cancelling the parent must not read as every case having passed.
func TestVerifyCasesHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyCases(ctx, cases(4), func(context.Context, domain.VerificationCase) error {
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// The bound is what keeps an emulated architecture from oversubscribing a small
// runner, so it has to actually hold.
func TestVerifyCasesRespectsItsConcurrencyBound(t *testing.T) {
	var running, peak atomic.Int64
	if err := verifyCases(context.Background(), cases(32), func(context.Context, domain.VerificationCase) error {
		current := running.Add(1)
		defer running.Add(-1)
		for {
			was := peak.Load()
			if current <= was || peak.CompareAndSwap(was, current) {
				break
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > maxConcurrentVerifications {
		t.Fatalf("%d cases ran at once, above the bound of %d", peak.Load(), maxConcurrentVerifications)
	}
}
