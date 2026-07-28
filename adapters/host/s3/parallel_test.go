package s3host

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestForEachObjectRunsEveryIndexOnce(t *testing.T) {
	const count = 500
	var mutex sync.Mutex
	seen := make(map[int]int, count)
	if err := forEachObject(context.Background(), count, func(_ context.Context, index int) error {
		mutex.Lock()
		defer mutex.Unlock()
		seen[index]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != count {
		t.Fatalf("ran %d indices, want %d", len(seen), count)
	}
	for index, times := range seen {
		if times != 1 {
			t.Fatalf("index %d ran %d times", index, times)
		}
	}
}

// The pool must have several requests in flight at once. This waits for a
// rendezvous rather than sampling a counter: sampling measures parallelism,
// which a single-CPU machine cannot show even when the pool is working
// correctly, whereas independent progress is what the pool actually promises.
func TestForEachObjectOverlapsRequests(t *testing.T) {
	const overlapping = 2
	arrived := make(chan struct{}, overlapping)
	release := make(chan struct{})
	go func() {
		for range overlapping {
			<-arrived
		}
		close(release)
	}()
	err := forEachObject(context.Background(), 8, func(_ context.Context, index int) error {
		if index >= overlapping {
			return nil
		}
		arrived <- struct{}{}
		select {
		case <-release:
			return nil
		case <-time.After(30 * time.Second):
			// Only reachable if the pool ran these one after another, since the
			// release waits for both to have started.
			return fmt.Errorf("request %d ran alone; the pool did not overlap requests", index)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Whichever request loses the race, the reported failure must be the same one,
// otherwise an operator sees a different error for the same broken state.
func TestForEachObjectReportsLowestFailingIndex(t *testing.T) {
	for attempt := range 50 {
		err := forEachObject(context.Background(), 200, func(_ context.Context, index int) error {
			if index == 7 || index == 90 || index == 150 {
				return fmt.Errorf("object %d failed", index)
			}
			return nil
		})
		if err == nil || err.Error() != "object 7 failed" {
			t.Fatalf("attempt %d reported %v, want the lowest failing index", attempt, err)
		}
	}
}

func TestForEachObjectStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran atomic.Int64
	err := forEachObject(ctx, 100, func(_ context.Context, _ int) error {
		ran.Add(1)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if ran.Load() == 100 {
		t.Fatal("cancellation did not stop the remaining work")
	}
}

func TestForEachObjectHandlesEmptyAndSingle(t *testing.T) {
	if err := forEachObject(context.Background(), 0, func(context.Context, int) error {
		t.Fatal("empty work ran")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("single")
	if err := forEachObject(context.Background(), 1, func(context.Context, int) error {
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the sentinel", err)
	}
}
