package app

import (
	"context"
	"sync"

	"github.com/shellcell/snailmail/internal/domain"
)

// maxConcurrentVerifications bounds how many client containers run at once.
//
// Each case is one container installing one package version, and they are
// independent: every one mounts the same repository read-only and writes
// nothing a sibling reads. Running them one at a time made publication cost
// grow with the number of versions a repository holds, which is the number that
// only ever goes up. The bound is small on purpose — verifying a foreign
// architecture runs under emulation, and oversubscribing a two-core runner with
// emulated containers spends more time context-switching than it saves.
const maxConcurrentVerifications = 4

// verifyCases runs one verification per case and reports the earliest failing
// case in the order the manifest lists them.
//
// It deliberately does not stop at the first failure. Cases acquire their slot
// in whatever order the scheduler hands them out, so cancelling the rest would
// leave an earlier case unrun — and a case that never ran cannot be known to
// have failed. The publication would then blame whichever container happened to
// finish first, and the same defect would be reported differently on every run.
// A refused publication is the rare path and is already going to be repeated;
// naming the same case every time is worth more there than finishing sooner.
func verifyCases(ctx context.Context, cases []domain.VerificationCase, verify func(context.Context, domain.VerificationCase) error) error {
	if len(cases) == 0 {
		return nil
	}
	if len(cases) == 1 {
		return verify(ctx, cases[0])
	}
	limit := maxConcurrentVerifications
	if len(cases) < limit {
		limit = len(cases)
	}
	slots := make(chan struct{}, limit)
	failures := make([]error, len(cases))
	var wait sync.WaitGroup
	for index, verification := range cases {
		wait.Add(1)
		go func(index int, verification domain.VerificationCase) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			// A cancelled parent still stops the run; that cancellation is the
			// caller giving up, not a verdict about any case.
			if err := ctx.Err(); err != nil {
				failures[index] = err
				return
			}
			failures[index] = verify(ctx, verification)
		}(index, verification)
	}
	wait.Wait()
	for _, err := range failures {
		if err != nil {
			return err
		}
	}
	return nil
}
