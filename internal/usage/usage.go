// Package usage fetches per-provider Claude Code / Codex / Gemini usage
// directly from each provider's upstream API and exposes a single uniform
// shape over HTTP at /usage/{claude,codex,gemini}. The firmware uses one
// parser instead of three reverse-engineered ones.
//
// Wire format is documented in compat/USAGE_WIRE.md.
package usage

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Snapshot is the cross-provider shape the broker serves. Field names
// match the JSON wire format byte-for-byte; the firmware already parses
// these in gemini_client.c.
type Snapshot struct {
	SessionPct             float64 `json:"session_pct"`
	WeeklyPct              float64 `json:"weekly_pct"`
	DesignPct              float64 `json:"design_pct"`
	DesignPresent          bool    `json:"design_present"`
	SessionResetETASeconds uint32  `json:"session_reset_eta_seconds"`
	WeeklyResetETASeconds  uint32  `json:"weekly_reset_eta_seconds"`
	DesignResetETASeconds  uint32  `json:"design_reset_eta_seconds"`
	SessionWindowSeconds   uint32  `json:"session_window_seconds"`
	WeeklyWindowSeconds    uint32  `json:"weekly_window_seconds"`
	Tier                   string  `json:"tier"`
	FetchedAtUnix          int64   `json:"fetched_at_unix"`
	StaleSeconds           uint32  `json:"stale_seconds"`
	// Slots is the optional per-card override surfaced by Gemini (and
	// reserved for any future provider with N model-scoped buckets). When
	// non-empty, the firmware ignores SessionPct/WeeklyPct/DesignPct and
	// uses these entries instead. See compat/USAGE_WIRE.md.
	Slots []Slot `json:"slots,omitempty"`
}

// Slot is one entry in Snapshot.Slots. The firmware caps the rendered
// count at 3 to match the dashboard's fixed card slots.
type Slot struct {
	Label            string  `json:"label"`
	Pct              float64 `json:"pct"`
	WindowSeconds    uint32  `json:"window_seconds"`
	ResetETASeconds  uint32  `json:"reset_eta_seconds"`
}

// Provider names served at /usage/{name}.
const (
	ProviderClaude = "claude"
	ProviderCodex  = "codex"
	ProviderGemini = "gemini"
)

// Standardised errors. The broker maps these to HTTP statuses; tests
// assert on the sentinel rather than the message.
var (
	ErrCredsMissing  = errors.New("usage: creds file missing")
	ErrTokenExpired  = errors.New("usage: token expired, refresh on laptop")
	ErrUnauthorized  = errors.New("usage: upstream rejected token")
	ErrRateLimited   = errors.New("usage: upstream rate limited")
	ErrUpstream      = errors.New("usage: upstream non-2xx")
	ErrTransport     = errors.New("usage: transport error")
	ErrParseUpstream = errors.New("usage: cannot parse upstream response")
	ErrNotImpl       = errors.New("usage: provider not implemented")
	ErrDisabled      = errors.New("usage: provider disabled in cwm.toml")
)

// RateLimitedError carries the Retry-After hint when upstream answered 429.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return ErrRateLimited.Error() }
func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// Fetcher is what every provider implementation provides. The cache calls
// Fetch when its entry is stale; the broker never calls a Fetcher directly.
type Fetcher interface {
	Fetch(ctx context.Context) (Snapshot, error)
}

// Cache memoises one Snapshot per provider with a per-entry TTL. When an
// entry is stale the cache calls Fetch synchronously in the calling
// goroutine — there are very few clients (one device on the LAN), so the
// extra goroutine bookkeeping isn't worth it. On upstream failure, the
// cache returns the last good Snapshot with updated StaleSeconds and the
// underlying error, leaving the broker to decide whether to surface 502
// or keep serving the stale value.
type Cache struct {
	ttl       time.Duration
	now       func() time.Time
	fetchers  map[string]Fetcher
	mu        sync.Mutex
	entries   map[string]entry
	inFlights map[string]chan result // per-provider singleflight
}

type entry struct {
	snap     Snapshot
	fetched  time.Time
	lastErr  error
	hasValue bool
}

type result struct {
	snap Snapshot
	err  error
}

// NewCache wires the provider Fetchers under a TTL. ttl=0 forces a fetch
// on every call; useful for tests.
func NewCache(ttl time.Duration, fetchers map[string]Fetcher) *Cache {
	return &Cache{
		ttl:       ttl,
		now:       time.Now,
		fetchers:  fetchers,
		entries:   make(map[string]entry, len(fetchers)),
		inFlights: make(map[string]chan result),
	}
}

// Get returns a Snapshot for `provider`, refreshing from upstream if the
// cached entry is older than the TTL. On upstream error, returns the
// stale value (if any) with StaleSeconds updated AND the error; callers
// must decide whether stale-with-error is acceptable. If no value has
// ever been cached, returns (zero, err).
func (c *Cache) Get(ctx context.Context, provider string) (Snapshot, error) {
	f, ok := c.fetchers[provider]
	if !ok {
		return Snapshot{}, ErrNotImpl
	}

	c.mu.Lock()
	e, hadValue := c.entries[provider], false
	hadValue = e.hasValue
	if hadValue && c.now().Sub(e.fetched) < c.ttl {
		snap := e.snap
		snap.StaleSeconds = uint32(c.now().Sub(e.fetched) / time.Second)
		c.mu.Unlock()
		return snap, nil
	}

	// Singleflight: if a fetch for this provider is already in flight,
	// wait on its channel instead of issuing a duplicate request.
	if ch, busy := c.inFlights[provider]; busy {
		c.mu.Unlock()
		select {
		case res := <-ch:
			return res.snap, res.err
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
	ch := make(chan result, 1)
	c.inFlights[provider] = ch
	c.mu.Unlock()

	snap, err := f.Fetch(ctx)
	now := c.now()

	c.mu.Lock()
	delete(c.inFlights, provider)
	if err == nil {
		snap.FetchedAtUnix = now.Unix()
		snap.StaleSeconds = 0
		c.entries[provider] = entry{snap: snap, fetched: now, hasValue: true}
	} else if hadValue {
		// Return the previous good value with bumped stale_seconds AND
		// the error, so the broker can pick between "serve stale" and
		// "propagate". The cached entry itself stays untouched so the
		// next request can still serve it until it ages out.
		stale := e.snap
		stale.StaleSeconds = uint32(now.Sub(e.fetched) / time.Second)
		// Track the last error for visibility but don't overwrite the
		// snapshot — a transient 502 shouldn't poison the cache.
		e.lastErr = err
		c.entries[provider] = e
		c.mu.Unlock()
		ch <- result{snap: stale, err: err}
		close(ch)
		return stale, err
	}
	c.mu.Unlock()

	ch <- result{snap: snap, err: err}
	close(ch)
	return snap, err
}

// GeminiFetcher returns the cached GeminiFetcher when one is wired up,
// for the broker's per-device override path. Returns (nil, false) when
// Gemini is disabled or wired with a non-Gemini fetcher (tests).
func (c *Cache) GeminiFetcher() (*GeminiFetcher, bool) {
	f, ok := c.fetchers[ProviderGemini]
	if !ok {
		return nil, false
	}
	gf, ok := f.(*GeminiFetcher)
	return gf, ok
}

// Providers returns the names registered with this cache, in stable order.
// Used by the broker to mount /usage/{name} routes.
func (c *Cache) Providers() []string {
	out := make([]string, 0, len(c.fetchers))
	for k := range c.fetchers {
		out = append(out, k)
	}
	return out
}
