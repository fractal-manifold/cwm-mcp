package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/creds"
)

const (
	codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"
	codexUA       = "cwm-mcp/usage"
	// Codex windows DO come back in the response (limit_window_seconds),
	// so these are only fallbacks when upstream omits them.
	codexSessionWindowFallback = 5 * 3600
	codexWeeklyWindowFallback  = 7 * 86400
)

// CodexFetcher reads ~/.codex/auth.json and hits ChatGPT's wham/usage
// endpoint. Refresh-token handling is intentionally NOT done here: the
// Codex CLI manages auth.json with its own write semantics, and racing
// against it from the broker risks corrupting the file. When the JWT
// expires we return ErrTokenExpired and the user runs `codex login`.
type CodexFetcher struct {
	AuthPath string
	HTTP     *http.Client
	Now      func() time.Time
}

func (f *CodexFetcher) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *CodexFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *CodexFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	c, err := creds.LoadCodex(f.AuthPath)
	if err != nil {
		if errors.Is(err, creds.ErrFileMissing) {
			return Snapshot{}, fmt.Errorf("%w: %v", ErrCredsMissing, err)
		}
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if c.IsExpired(f.now()) {
		return Snapshot{}, ErrTokenExpired
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	if c.AccountID != "" {
		req.Header.Set("ChatGPT-Account-Id", c.AccountID)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", codexUA)
	req.Header.Set("OpenAI-Beta", "chatgpt-account=enabled")

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == 401:
		return Snapshot{}, ErrUnauthorized
	case resp.StatusCode == 429:
		return Snapshot{}, &RateLimitedError{RetryAfter: retryAfter(resp)}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return Snapshot{}, fmt.Errorf("%w: status=%d", ErrUpstream, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var doc codexUsageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	return codexMap(doc), nil
}

// codexUsageDoc captures the fields we need from
//
//	GET /backend-api/wham/usage
//
// (sampled 2026-05-25 from a Plus plan). Other top-level keys we don't
// use: code_review_rate_limit, additional_rate_limits, spend_control,
// promo, referral_beacon, rate_limit_reset_credits.
type codexUsageDoc struct {
	PlanType  string `json:"plan_type"`
	RateLimit struct {
		PrimaryWindow   *codexWindow `json:"primary_window"`
		SecondaryWindow *codexWindow `json:"secondary_window"`
	} `json:"rate_limit"`
}

type codexWindow struct {
	UsedPercent        *float64 `json:"used_percent"`
	LimitWindowSeconds *uint32  `json:"limit_window_seconds"`
	ResetAfterSeconds  *uint32  `json:"reset_after_seconds"`
	ResetAt            *int64   `json:"reset_at"`
}

func codexMap(d codexUsageDoc) Snapshot {
	snap := Snapshot{
		SessionWindowSeconds: codexSessionWindowFallback,
		WeeklyWindowSeconds:  codexWeeklyWindowFallback,
		Tier:                 d.PlanType,
	}
	if w := d.RateLimit.PrimaryWindow; w != nil {
		if w.UsedPercent != nil {
			snap.SessionPct = *w.UsedPercent
		}
		if w.LimitWindowSeconds != nil && *w.LimitWindowSeconds > 0 {
			snap.SessionWindowSeconds = *w.LimitWindowSeconds
		}
		snap.SessionResetETASeconds = codexResetETA(w)
	}
	if w := d.RateLimit.SecondaryWindow; w != nil {
		if w.UsedPercent != nil {
			snap.WeeklyPct = *w.UsedPercent
		}
		if w.LimitWindowSeconds != nil && *w.LimitWindowSeconds > 0 {
			snap.WeeklyWindowSeconds = *w.LimitWindowSeconds
		}
		snap.WeeklyResetETASeconds = codexResetETA(w)
	}
	if snap.Tier == "" {
		snap.Tier = "unknown"
	}
	return snap
}

// codexResetETA prefers the upstream's pre-computed reset_after_seconds
// (no clock skew between broker and CLI) and falls back to reset_at minus
// the broker's local clock.
func codexResetETA(w *codexWindow) uint32 {
	if w.ResetAfterSeconds != nil {
		return *w.ResetAfterSeconds
	}
	if w.ResetAt != nil {
		eta := *w.ResetAt - time.Now().Unix()
		if eta > 0 {
			return uint32(eta)
		}
	}
	return 0
}
