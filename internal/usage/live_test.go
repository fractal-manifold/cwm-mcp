//go:build live

// Live tests for /usage/{provider}. These hit real upstream APIs using
// the operator's on-disk credentials, so they're gated behind the
// `live` build tag (and a couple of env vars) to keep CI honest. Run
// locally with:
//
//	go test -tags=live -run TestLiveClaude  ./internal/usage/
//	CWM_LIVE_CODEX=1  go test -tags=live -run TestLiveCodex  ./internal/usage/
//	CWM_LIVE_GEMINI=1 go test -tags=live -run TestLiveGemini ./internal/usage/
//
// What they really catch: drift in upstream URLs or response shapes
// — when Anthropic / ChatGPT / Google rename a field or move an endpoint
// these tests fail loudly so we can patch the parser before the wall
// monitor goes silent.

package usage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func liveSkipUnless(t *testing.T, env string) {
	t.Helper()
	if os.Getenv(env) == "" {
		t.Skipf("set %s=1 to enable this live test (hits real upstream)", env)
	}
}

func homePath(t *testing.T, rel string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	return filepath.Join(home, rel)
}

func TestLiveClaude(t *testing.T) {
	// Claude is the primary provider — opt-in via a single flag.
	liveSkipUnless(t, "CWM_LIVE_USAGE")
	path := homePath(t, ".claude/.credentials.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no Claude creds at %s: %v", path, err)
	}
	f := &ClaudeFetcher{OAuthPath: path}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	snap, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Claude live fetch failed (URL or schema may have drifted): %v", err)
	}
	if snap.SessionWindowSeconds == 0 || snap.WeeklyWindowSeconds == 0 {
		t.Errorf("expected non-zero window seconds, snapshot=%+v", snap)
	}
	// session_pct must be in [0,100] — anything else means we picked the
	// wrong field.
	if snap.SessionPct < 0 || snap.SessionPct > 100 {
		t.Errorf("session_pct out of range: %v", snap.SessionPct)
	}
	if snap.WeeklyPct < 0 || snap.WeeklyPct > 100 {
		t.Errorf("weekly_pct out of range: %v", snap.WeeklyPct)
	}
	t.Logf("Claude live OK: %+v", snap)
}

func TestLiveCodex(t *testing.T) {
	liveSkipUnless(t, "CWM_LIVE_CODEX")
	path := homePath(t, ".codex/auth.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no Codex auth at %s: %v", path, err)
	}
	f := &CodexFetcher{AuthPath: path}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	snap, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Codex live fetch failed (URL or schema may have drifted): %v", err)
	}
	if snap.SessionWindowSeconds == 0 || snap.WeeklyWindowSeconds == 0 {
		t.Errorf("expected non-zero window seconds, snapshot=%+v", snap)
	}
	if snap.SessionPct < 0 || snap.SessionPct > 100 {
		t.Errorf("session_pct out of range: %v", snap.SessionPct)
	}
	if snap.WeeklyPct < 0 || snap.WeeklyPct > 100 {
		t.Errorf("weekly_pct out of range: %v", snap.WeeklyPct)
	}
	if snap.Tier == "" || snap.Tier == "unknown" {
		t.Errorf("tier should reflect plan_type, got %q", snap.Tier)
	}
	t.Logf("Codex live OK: %+v", snap)
}

func TestLiveGemini(t *testing.T) {
	liveSkipUnless(t, "CWM_LIVE_GEMINI")
	creds := homePath(t, ".gemini/oauth_creds.json")
	projects := homePath(t, ".gemini/projects.json")
	if _, err := os.Stat(creds); err != nil {
		t.Skipf("no Gemini creds at %s: %v", creds, err)
	}
	f := &GeminiFetcher{CredsPath: creds, ProjectsPath: projects}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	snap, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Gemini live fetch failed (URL or schema may have drifted): %v", err)
	}
	if snap.Tier == "" || snap.Tier == "unknown" {
		t.Errorf("tier should be free-tier or a paid id, got %q", snap.Tier)
	}
	// We can't strongly assert percentages — free tier returns 0 with
	// no quota signal, and paid tier mapping is still TODO. Just smoke.
	t.Logf("Gemini live OK: %+v", snap)
}
