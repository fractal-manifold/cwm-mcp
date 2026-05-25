package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type stubFetcher struct {
	mu     sync.Mutex
	calls  int
	delay  time.Duration
	snap   Snapshot
	err    error
	called func(int)
}

func (f *stubFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if f.called != nil {
		f.called(n)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
	return f.snap, f.err
}

func TestCache_FetchesOnFirstCall(t *testing.T) {
	stub := &stubFetcher{snap: Snapshot{SessionPct: 42}}
	c := NewCache(time.Minute, map[string]Fetcher{"x": stub})
	c.now = func() time.Time { return time.Unix(1000, 0) }

	got, err := c.Get(context.Background(), "x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.SessionPct != 42 {
		t.Errorf("session_pct: got %v want 42", got.SessionPct)
	}
	if got.FetchedAtUnix != 1000 {
		t.Errorf("fetched_at: got %v want 1000", got.FetchedAtUnix)
	}
	if stub.calls != 1 {
		t.Errorf("calls: %d", stub.calls)
	}
}

func TestCache_ServesFromCacheInsideTTL(t *testing.T) {
	stub := &stubFetcher{snap: Snapshot{SessionPct: 5}}
	c := NewCache(time.Minute, map[string]Fetcher{"x": stub})
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.Get(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	got, err := c.Get(context.Background(), "x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("expected exactly 1 upstream call, got %d", stub.calls)
	}
	if got.StaleSeconds != 30 {
		t.Errorf("stale_seconds: got %d want 30", got.StaleSeconds)
	}
}

func TestCache_RefetchAfterTTL(t *testing.T) {
	stub := &stubFetcher{snap: Snapshot{SessionPct: 5}}
	c := NewCache(10*time.Second, map[string]Fetcher{"x": stub})
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.Get(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if _, err := c.Get(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 2 {
		t.Errorf("expected refetch, got %d calls", stub.calls)
	}
}

func TestCache_ReturnsStaleOnError(t *testing.T) {
	// First fetch succeeds; second fetch (after TTL) errors. The cache
	// must return the previous good snapshot AND the error, leaving the
	// broker to decide whether to surface stale-with-200 or propagate.
	stub := &stubFetcher{snap: Snapshot{SessionPct: 11}}
	c := NewCache(1*time.Second, map[string]Fetcher{"x": stub})
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.Get(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	stub.err = ErrUpstream
	now = now.Add(2 * time.Second)
	got, err := c.Get(context.Background(), "x")
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("expected ErrUpstream, got %v", err)
	}
	if got.SessionPct != 11 {
		t.Errorf("expected stale value 11, got %v", got.SessionPct)
	}
	if got.StaleSeconds != 2 {
		t.Errorf("stale_seconds: got %d want 2", got.StaleSeconds)
	}
}

func TestCache_UnknownProvider(t *testing.T) {
	c := NewCache(time.Minute, map[string]Fetcher{"x": &stubFetcher{}})
	_, err := c.Get(context.Background(), "y")
	if !errors.Is(err, ErrNotImpl) {
		t.Fatalf("expected ErrNotImpl, got %v", err)
	}
}

func TestCache_Singleflight(t *testing.T) {
	// Two concurrent gets for the same cold cache entry should result in
	// exactly one upstream call.
	stub := &stubFetcher{snap: Snapshot{SessionPct: 7}, delay: 50 * time.Millisecond}
	c := NewCache(time.Minute, map[string]Fetcher{"x": stub})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "x"); err != nil {
				t.Errorf("get: %v", err)
			}
		}()
	}
	wg.Wait()
	if stub.calls != 1 {
		t.Errorf("expected 1 upstream call under singleflight, got %d", stub.calls)
	}
}
