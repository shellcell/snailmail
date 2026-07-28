package s3host

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// defaultObjectConcurrency bounds in-flight object requests. Publication is
// dominated by round-trip latency rather than local work, so this is
// deliberately higher than the CPU count, but still low enough to stay well
// inside per-connection limits and to keep a failure from fanning out widely.
var defaultObjectConcurrency = min(16, max(4, runtime.GOMAXPROCS(0)*4))

// forEachObject runs work over every index in [0, count) with bounded
// concurrency and returns the error belonging to the lowest index, so that a
// failure is reported identically no matter which request lost the race.
//
// The first failure stops further indices being dispatched, but requests
// already in flight are allowed to finish against the caller's context rather
// than being cancelled. Cancelling them would replace a genuine failure at a
// lower index with a self-inflicted "context canceled", which is both
// misleading and non-deterministic.
func forEachObject(ctx context.Context, count int, work func(ctx context.Context, index int) error) error {
	if count == 0 {
		return nil
	}
	if count == 1 {
		return work(ctx, 0)
	}
	workers := min(defaultObjectConcurrency, count)
	errs := make([]error, count)
	var failed atomic.Bool
	next := make(chan int)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			for index := range next {
				if err := work(ctx, index); err != nil {
					errs[index] = err
					failed.Store(true)
				}
			}
		}()
	}
	for index := range count {
		if failed.Load() || ctx.Err() != nil {
			break
		}
		next <- index
	}
	close(next)
	waitGroup.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	// No request recorded a failure, so any stop came from the caller.
	return ctx.Err()
}
