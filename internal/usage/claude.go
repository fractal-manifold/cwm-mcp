package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/creds"
)

const (
	claudeUsageURL = "https://api.anthropic.com/api/oauth/usage"
	claudeBetaHdr  = "oauth-2025-04-20"
	// Claude session/weekly windows are not returned by the API — they're
	// product constants.
	claudeSessionWindow = 5 * 3600
	claudeWeeklyWindow  = 7 * 86400
)

// ClaudeFetcher reads ~/.claude/.credentials.json and hits the Anthropic
// OAuth usage endpoint. Anthropic does not (yet) expose a refresh token in
// the on-disk shape, so when the access token expires we return
// ErrTokenExpired and let the user re-login on the laptop.
type ClaudeFetcher struct {
	OAuthPath string
	HTTP      *http.Client
	Now       func() time.Time
}

func (f *ClaudeFetcher) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *ClaudeFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *ClaudeFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	c, err := creds.Load(f.OAuthPath)
	if err != nil {
		if errors.Is(err, creds.ErrFileMissing) {
			return Snapshot{}, fmt.Errorf("%w: %v", ErrCredsMissing, err)
		}
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if c.IsExpired(f.now()) {
		return Snapshot{}, ErrTokenExpired
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, claudeUsageURL, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("anthropic-beta", claudeBetaHdr)
	req.Header.Set("Accept", "application/json")

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

	var doc claudeUsageDoc
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	return claudeMap(doc, f.now()), nil
}

// claudeUsageDoc captures the fields we need from
//
//	GET /api/oauth/usage
//
// (sampled 2026-05-25 from a Max plan). Extra keys
// `seven_day_sonnet`, `tangelo`, `iguana_necktie`,
// `omelette_promotional`, `seven_day_cowork`, `seven_day_oauth_apps` are
// ignored — they're either codenames or unused tiers.
type claudeUsageDoc struct {
	FiveHour          *claudeWindow `json:"five_hour"`
	SevenDay          *claudeWindow `json:"seven_day"`
	SevenDayOmelette  *claudeWindow `json:"seven_day_omelette"`
	ExtraUsage        *struct {
		IsEnabled bool `json:"is_enabled"`
	} `json:"extra_usage"`
}

type claudeWindow struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    *string  `json:"resets_at"`
}

func claudeMap(d claudeUsageDoc, now time.Time) Snapshot {
	snap := Snapshot{
		SessionWindowSeconds: claudeSessionWindow,
		WeeklyWindowSeconds:  claudeWeeklyWindow,
		Tier:                 "unknown",
	}
	if d.FiveHour != nil {
		if d.FiveHour.Utilization != nil {
			snap.SessionPct = *d.FiveHour.Utilization
		}
		if d.FiveHour.ResetsAt != nil {
			snap.SessionResetETASeconds = secondsUntilISO(*d.FiveHour.ResetsAt, now)
		}
	}
	if d.SevenDay != nil {
		if d.SevenDay.Utilization != nil {
			snap.WeeklyPct = *d.SevenDay.Utilization
		}
		if d.SevenDay.ResetsAt != nil {
			snap.WeeklyResetETASeconds = secondsUntilISO(*d.SevenDay.ResetsAt, now)
		}
	}
	// `seven_day_omelette` (Claude Design codename) is an object even for
	// users without access — we report design_present iff the object
	// exists. Utilization may be 0 with resets_at=null, which we encode
	// as a present-but-unused card.
	if d.SevenDayOmelette != nil {
		snap.DesignPresent = true
		if d.SevenDayOmelette.Utilization != nil {
			snap.DesignPct = *d.SevenDayOmelette.Utilization
		}
		if d.SevenDayOmelette.ResetsAt != nil {
			snap.DesignResetETASeconds = secondsUntilISO(*d.SevenDayOmelette.ResetsAt, now)
		}
	}
	if d.ExtraUsage != nil && d.ExtraUsage.IsEnabled {
		snap.Tier = "paid"
	}
	return snap
}

func secondsUntilISO(iso string, now time.Time) uint32 {
	// Anthropic uses microsecond precision with explicit "+00:00".
	// time.RFC3339Nano handles that; fall back to RFC3339 just in case.
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return 0
		}
	}
	if !t.After(now) {
		return 0
	}
	d := t.Sub(now)
	return uint32(d / time.Second)
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
