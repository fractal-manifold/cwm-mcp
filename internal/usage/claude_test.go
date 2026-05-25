package usage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// claudeSample is the real response shape captured from
// scripts/proto-usage-claude.py on 2026-05-25. Drift tests live in
// live_test.go (env-gated); this one only checks that we map the
// canonical shape into a Snapshot correctly.
const claudeSample = `{
  "five_hour":          {"utilization": 70.0, "resets_at": "2026-05-25T02:50:00.000000+00:00"},
  "seven_day":          {"utilization": 93.0, "resets_at": "2026-05-25T08:00:00.000000+00:00"},
  "seven_day_omelette": {"utilization": 0.0,  "resets_at": null},
  "seven_day_sonnet":   {"utilization": 4.0,  "resets_at": "2026-05-25T08:00:00.000000+00:00"},
  "extra_usage":        {"is_enabled": false, "monthly_limit": null}
}`

func writeClaudeCreds(t *testing.T, expiresAt int64) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".credentials.json")
	doc := map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken": "tok-test",
			"expiresAt":   expiresAt,
		},
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaudeFetcher_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-test" {
			t.Errorf("auth header: %q", got)
		}
		if got := r.Header.Get("anthropic-beta"); got != claudeBetaHdr {
			t.Errorf("beta header: %q", got)
		}
		_, _ = w.Write([]byte(claudeSample))
	}))
	defer srv.Close()

	// Pretend "now" is one minute before the resets_at timestamps so the
	// ETAs are computable independently of the test clock.
	now, _ := time.Parse(time.RFC3339, "2026-05-25T02:49:00Z")
	f := &ClaudeFetcher{
		OAuthPath: writeClaudeCreds(t, now.Add(time.Hour).UnixMilli()),
		HTTP:      srv.Client(),
		Now:       func() time.Time { return now },
	}
	// Override the URL: ClaudeFetcher hardcodes it, so we patch by going
	// through the http.Client's Transport. Simpler: replace claudeUsageURL
	// via a roundtrip on the test server.
	f.HTTP = &http.Client{Transport: rewriteHost(srv.URL)}

	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SessionPct != 70 {
		t.Errorf("session_pct: %v", snap.SessionPct)
	}
	if snap.WeeklyPct != 93 {
		t.Errorf("weekly_pct: %v", snap.WeeklyPct)
	}
	if !snap.DesignPresent {
		t.Errorf("design_present: want true")
	}
	if snap.DesignPct != 0 {
		t.Errorf("design_pct: %v", snap.DesignPct)
	}
	if snap.DesignResetETASeconds != 0 {
		t.Errorf("design_reset_eta: want 0 (resets_at null), got %d", snap.DesignResetETASeconds)
	}
	if snap.SessionResetETASeconds != 60 {
		t.Errorf("session_reset_eta: want 60 (= 1 min), got %d", snap.SessionResetETASeconds)
	}
	if snap.SessionWindowSeconds != claudeSessionWindow {
		t.Errorf("session_window: %d", snap.SessionWindowSeconds)
	}
	if snap.WeeklyWindowSeconds != claudeWeeklyWindow {
		t.Errorf("weekly_window: %d", snap.WeeklyWindowSeconds)
	}
}

func TestClaudeFetcher_TokenExpired(t *testing.T) {
	f := &ClaudeFetcher{
		OAuthPath: writeClaudeCreds(t, time.Now().Add(-time.Hour).UnixMilli()),
		Now:       time.Now,
	}
	_, err := f.Fetch(context.Background())
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestClaudeFetcher_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	f := &ClaudeFetcher{
		OAuthPath: writeClaudeCreds(t, time.Now().Add(time.Hour).UnixMilli()),
		HTTP:      &http.Client{Transport: rewriteHost(srv.URL)},
		Now:       time.Now,
	}
	_, err := f.Fetch(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestClaudeFetcher_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "42")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	f := &ClaudeFetcher{
		OAuthPath: writeClaudeCreds(t, time.Now().Add(time.Hour).UnixMilli()),
		HTTP:      &http.Client{Transport: rewriteHost(srv.URL)},
		Now:       time.Now,
	}
	_, err := f.Fetch(context.Background())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	var rl *RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
	if rl.RetryAfter != 42*time.Second {
		t.Errorf("retry_after: %v", rl.RetryAfter)
	}
}

// rewriteHost is a tiny RoundTripper that redirects every request to
// `target`, preserving the path/query. Lets the test drop the hard-coded
// upstream URLs without exposing them via constructor arguments.
type hostRewriter struct {
	target string
}

func rewriteHost(target string) http.RoundTripper {
	return &hostRewriter{target: target}
}

func (h *hostRewriter) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	u, err := req.URL.Parse(h.target)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	req.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}
