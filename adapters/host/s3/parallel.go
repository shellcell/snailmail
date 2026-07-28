package s3host

import (
	"context"
	"runtime"
	"sync"
)

// defaultObjectConcurrency bounds in-flight object requests. Publication is
// dominated by round-trip latency rather than local work, so this is
// deliberately higher than the CPU count, but still low enough to stay well
// inside per-connection limits and to keep a failure from fanning out widely.
var defaultObjectConcurrency = min(16, max(4, runtime.GOMAXPROCS(0)*4))

// forEachObject runs work over every index in [0, count) with bounded
// concurrency and returns the error belonging to the lowest index, so that a
// failure is reported identically no matter which request lost the race.
func forEachObject(ctx context.Context, count int, work func(ctx context.Context, index int) error) error {
	if count == 0 {
		return nil
	}
	if count == 1 {
		return work(ctx, 0)
	}
	workers := min(defaultObjectConcurrency, count)
	// A cancelled context stops the remaining work as soon as one request fails.
	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make([]error, count)
	next := make(chan int)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			for index := range next {
				if groupCtx.Err() != nil {
					return
				}
				if err := work(groupCtx, index); err != nil {
					errs[index] = err
					cancel()
					return
				}
			}
		}()
	}
	for index := range count {
		select {
		case next <- index:
		case <-groupCtx.Done():
			close(next)
			waitGroup.Wait()
			return firstError(errs, ctx)
		}
	}
	close(next)
	waitGroup.Wait()
	return firstError(errs, ctx)
}

func firstError(errs []error, ctx context.Context) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	// No worker recorded a failure, so any stop came from the caller's context.
	return ctx.Err()
}
