package usage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// codexSample is the real shape captured by scripts/proto-usage-codex.py
// on 2026-05-25 from a Plus plan.
const codexSample = `{
  "plan_type": "plus",
  "rate_limit": {
    "primary_window":   {"used_percent": 33, "limit_window_seconds": 18000, "reset_after_seconds": 14007, "reset_at": 1779678515},
    "secondary_window": {"used_percent": 6,  "limit_window_seconds": 604800, "reset_after_seconds": 582744, "reset_at": 1780247253}
  },
  "credits": {"has_credits": false}
}`

func makeJWT(t *testing.T, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"exp": exp})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func writeCodexAuth(t *testing.T, exp int64) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	doc := map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"access_token": makeJWT(t, exp),
			"account_id":   "acct-test",
		},
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodexFetcher_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("ChatGPT-Account-Id"); got != "acct-test" {
			t.Errorf("account header: %q", got)
		}
		if got := r.Header.Get("Authorization"); got == "" || got[:7] != "Bearer " {
			t.Errorf("auth header: %q", got)
		}
		_, _ = w.Write([]byte(codexSample))
	}))
	defer srv.Close()

	f := &CodexFetcher{
		AuthPath: writeCodexAuth(t, time.Now().Add(time.Hour).Unix()),
		HTTP:     &http.Client{Transport: rewriteHost(srv.URL)},
		Now:      time.Now,
	}
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SessionPct != 33 {
		t.Errorf("session_pct: %v", snap.SessionPct)
	}
	if snap.WeeklyPct != 6 {
		t.Errorf("weekly_pct: %v", snap.WeeklyPct)
	}
	if snap.SessionWindowSeconds != 18000 {
		t.Errorf("session_window: %d", snap.SessionWindowSeconds)
	}
	if snap.WeeklyWindowSeconds != 604800 {
		t.Errorf("weekly_window: %d", snap.WeeklyWindowSeconds)
	}
	if snap.SessionResetETASeconds != 14007 {
		t.Errorf("session_reset_eta: %d", snap.SessionResetETASeconds)
	}
	if snap.WeeklyResetETASeconds != 582744 {
		t.Errorf("weekly_reset_eta: %d", snap.WeeklyResetETASeconds)
	}
	if snap.Tier != "plus" {
		t.Errorf("tier: %q", snap.Tier)
	}
	if snap.DesignPresent {
		t.Errorf("design_present: want false for codex")
	}
}

func TestCodexFetcher_MissingRateLimit(t *testing.T) {
	// Make sure absent windows yield 0% without crashing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"plan_type":"plus","rate_limit":{}}`))
	}))
	defer srv.Close()
	f := &CodexFetcher{
		AuthPath: writeCodexAuth(t, time.Now().Add(time.Hour).Unix()),
		HTTP:     &http.Client{Transport: rewriteHost(srv.URL)},
		Now:      time.Now,
	}
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SessionPct != 0 || snap.WeeklyPct != 0 {
		t.Errorf("expected zeros, got %+v", snap)
	}
	if snap.SessionWindowSeconds != codexSessionWindowFallback {
		t.Errorf("session_window fallback: %d", snap.SessionWindowSeconds)
	}
}
