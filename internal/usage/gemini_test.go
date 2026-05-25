package usage

import (
	"testing"
	"time"
)

func TestGeminiApplyQuota_DefaultProAndFlash(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		{ModelId: "gemini-2.5-flash", TokenType: "REQUESTS", RemainingFraction: 0.4, ResetTime: "2026-05-26T12:00:00Z"},
		{ModelId: "gemini-2.5-pro", TokenType: "REQUESTS", RemainingFraction: 0.75, ResetTime: "2026-05-26T12:00:00Z"},
		{ModelId: "gemini-2.5-flash-lite", TokenType: "REQUESTS", RemainingFraction: 0.9, ResetTime: "2026-05-26T12:00:00Z"},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now, []string{"gemini-2.5-pro", "gemini-2.5-flash"})
	// First model (Pro) mirrored to SessionPct for legacy firmware.
	if snap.SessionPct != 25 {
		t.Errorf("session_pct: got %v want 25", snap.SessionPct)
	}
	if snap.SessionResetETASeconds != 86400 {
		t.Errorf("session reset eta: got %d want 86400", snap.SessionResetETASeconds)
	}
	// Slots array carries both models in order.
	if len(snap.Slots) != 2 {
		t.Fatalf("slots: got %d entries want 2", len(snap.Slots))
	}
	if snap.Slots[0].Label != "Pro" || snap.Slots[0].Pct != 25 {
		t.Errorf("slot[0]: %+v", snap.Slots[0])
	}
	if snap.Slots[1].Label != "Flash" || snap.Slots[1].Pct != 60 {
		t.Errorf("slot[1]: %+v", snap.Slots[1])
	}
	if snap.Slots[0].WindowSeconds != 86400 {
		t.Errorf("slot window: %d", snap.Slots[0].WindowSeconds)
	}
	// Weekly stays empty — Gemini has no weekly cadence.
	if snap.WeeklyPct != 0 || snap.WeeklyResetETASeconds != 0 {
		t.Errorf("weekly must stay empty for gemini, got pct=%v eta=%d",
			snap.WeeklyPct, snap.WeeklyResetETASeconds)
	}
}

func TestGeminiApplyQuota_ThreeModels(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		{ModelId: "gemini-2.5-pro", RemainingFraction: 0.5, ResetTime: "2026-05-26T00:00:00Z"},
		{ModelId: "gemini-2.5-flash", RemainingFraction: 0.2, ResetTime: "2026-05-26T00:00:00Z"},
		{ModelId: "gemini-2.5-flash-lite", RemainingFraction: 0.9, ResetTime: "2026-05-26T00:00:00Z"},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now,
		[]string{"gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite"})
	if len(snap.Slots) != 3 {
		t.Fatalf("slots: got %d want 3", len(snap.Slots))
	}
	if got := snap.Slots[2].Label; got != "Flash-Lite" {
		t.Errorf("flash-lite label: got %q want %q", got, "Flash-Lite")
	}
}

func TestGeminiApplyQuota_PrefixFallback(t *testing.T) {
	// If the exact modelId is gone (Google rotates -2.5 → -3.x), pick the
	// next bucket whose id has the same prefix.
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		{ModelId: "gemini-2.5-pro-002", RemainingFraction: 0.2, ResetTime: "2026-05-25T18:00:00Z"},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now, []string{"gemini-2.5-pro"})
	if snap.SessionPct != 80 {
		t.Errorf("session_pct: got %v want 80 (prefix fallback)", snap.SessionPct)
	}
	if snap.SessionResetETASeconds != 6*3600 {
		t.Errorf("session reset eta: got %d want %d", snap.SessionResetETASeconds, 6*3600)
	}
}

func TestGeminiApplyQuota_ClampsAndExpiredReset(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		// Bucket reports >1 fraction (shouldn't happen, but be defensive).
		{ModelId: "gemini-2.5-pro", RemainingFraction: 1.5, ResetTime: "2020-01-01T00:00:00Z"},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now, []string{"gemini-2.5-pro"})
	if snap.SessionPct != 0 {
		t.Errorf("session_pct: clamp to 0 used, got %v", snap.SessionPct)
	}
	if snap.SessionResetETASeconds != 0 {
		t.Errorf("session_reset_eta: past reset must be 0, got %d", snap.SessionResetETASeconds)
	}
}

func TestGeminiApplyQuota_NegativeFraction(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		// Negative fraction → fully used.
		{ModelId: "gemini-2.5-pro", RemainingFraction: -0.1, ResetTime: ""},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now, []string{"gemini-2.5-pro"})
	if snap.SessionPct != 100 {
		t.Errorf("session_pct: clamp to 100 used, got %v", snap.SessionPct)
	}
}

func TestGeminiApplyQuota_NoOpOnNil(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	snap := Snapshot{SessionPct: 11}
	geminiApplyQuota(&snap, nil, now, []string{"gemini-2.5-pro"})
	if snap.SessionPct != 11 {
		t.Errorf("nil quota must leave snap untouched, got %+v", snap)
	}
}

func TestGeminiApplyQuota_EmptyModelsDefaultsToPro(t *testing.T) {
	// Empty model list falls back to the Pro bucket so the snapshot
	// always has at least the legacy SessionPct populated.
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Buckets: []geminiBucket{
		{ModelId: "gemini-2.5-pro", RemainingFraction: 0.3, ResetTime: "2026-05-26T12:00:00Z"},
	}}
	snap := Snapshot{}
	geminiApplyQuota(&snap, q, now, nil)
	if snap.SessionPct != 70 {
		t.Errorf("session_pct: got %v want 70", snap.SessionPct)
	}
	if len(snap.Slots) != 1 || snap.Slots[0].Label != "Pro" {
		t.Errorf("slots fallback: %+v", snap.Slots)
	}
}

func TestGeminiLabel(t *testing.T) {
	cases := map[string]string{
		"gemini-2.5-pro":         "Pro",
		"gemini-2.5-flash":       "Flash",
		"gemini-2.5-flash-lite":  "Flash-Lite",
		"gemini-3.0-pro":         "Pro",
		"":                       "",
		"weird":                  "Weird",
	}
	for in, want := range cases {
		if got := geminiLabel(in); got != want {
			t.Errorf("geminiLabel(%q) = %q want %q", in, got, want)
		}
	}
}
