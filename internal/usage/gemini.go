package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	geminiCodeAssistURL = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
	geminiUserQuotaURL  = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
	geminiTokenURL      = "https://oauth2.googleapis.com/token"

	// Gemini only has a daily quota — no weekly window. We surface the
	// Pro bucket (the headline model users care about most) as session
	// (24h) and leave weekly empty so the device hides that card.
	geminiSessionWindowFallback = 24 * 60 * 60

	geminiSessionModel = "gemini-2.5-pro"
)

// GeminiFetcher reads ~/.gemini/oauth_creds.json, refreshes the Google
// access token in memory when needed, and asks Code Assist for the user's
// tier. For free tier (the common case today), no usage signal is
// returned by Google — we surface tier="free" with zero percentages so
// the UI can render "Free tier — no quota signal". For paid tiers we map
// availableCredits into session/weekly buckets (TODO: needs a real paid
// account to validate; see compat/USAGE_WIRE.md).
//
// Models is the ordered list of Gemini model IDs to expose as cards.
// Each entry becomes a Snapshot.Slots row plus, for backwards compat
// with pre-slots firmware, the first model also lands in SessionPct.
// Empty falls back to a single Pro bucket.
//
// ModelsFor lets the broker swap the model list per request (e.g. honour
// a per-device override stored in the registry). When set, Models is
// ignored and ModelsFor(ctx) is invoked on every Fetch.
type GeminiFetcher struct {
	CredsPath    string
	ProjectsPath string
	Models       []string
	ModelsFor    func(ctx context.Context) []string
	HTTP         *http.Client
	Now          func() time.Time

	mu        sync.Mutex
	cachedTok geminiAccessToken
}

func (f *GeminiFetcher) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *GeminiFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

type geminiAccessToken struct {
	Token        string
	ExpiresAtMS  int64
}

// FetchWithModels is like Fetch but uses the supplied model list
// instead of f.Models / f.ModelsFor. The broker uses this to serve a
// per-device override without instantiating a second fetcher (and
// duplicating the token cache). Concurrent-safe — `models` is passed
// through the call stack, never written onto the receiver.
func (f *GeminiFetcher) FetchWithModels(ctx context.Context, models []string) (Snapshot, error) {
	return f.fetchInternal(ctx, models)
}

// Fetch loads creds, refreshes if needed (in memory), and POSTs to
// cloudcode-pa.
func (f *GeminiFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	return f.fetchInternal(ctx, f.modelsForRequest(ctx))
}

func (f *GeminiFetcher) fetchInternal(ctx context.Context, models []string) (Snapshot, error) {
	tok, err := f.token(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	body := map[string]any{
		"metadata": map[string]any{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	if proj := f.activeProject(); proj != "" {
		body["cloudaicompanionProject"] = proj
		body["metadata"].(map[string]any)["duetProject"] = proj
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiCodeAssistURL, bytes.NewReader(raw))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var doc geminiLoadCodeAssistDoc
	if err := json.Unmarshal(respBody, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	snap := geminiMap(doc)

	// retrieveUserQuota is the endpoint gemini-cli polls to drive its own
	// usage UI. It returns per-model buckets with remainingFraction and
	// resetTime — exactly what we need to surface session/weekly bars.
	// loadCodeAssist alone never carries usage numbers, which is why the
	// device was stuck at 0% for accounts that had been actively used.
	quotaProj := doc.CloudAICompanionProject
	if quotaProj == "" {
		quotaProj = f.activeProject()
	}
	if q, qerr := f.fetchQuota(ctx, tok, quotaProj); qerr == nil {
		geminiApplyQuota(&snap, q, f.now(), models)
	}
	return snap, nil
}

// modelsForRequest returns the list of model IDs to surface, preferring
// the per-request ModelsFor hook (used to honour a per-device override)
// over the fetcher's static Models list. Falls back to the default Pro
// bucket when both are empty.
func (f *GeminiFetcher) modelsForRequest(ctx context.Context) []string {
	if f.ModelsFor != nil {
		if m := f.ModelsFor(ctx); len(m) > 0 {
			return m
		}
	}
	if len(f.Models) > 0 {
		return f.Models
	}
	return []string{geminiSessionModel}
}

func (f *GeminiFetcher) fetchQuota(ctx context.Context, tok, project string) (*geminiQuotaDoc, error) {
	body := map[string]any{}
	if project != "" {
		body["project"] = project
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiUserQuotaURL, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status=%d", ErrUpstream, resp.StatusCode)
	}
	body2, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var q geminiQuotaDoc
	if err := json.Unmarshal(body2, &q); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	return &q, nil
}

// geminiLoadCodeAssistDoc captures the fields we care about from the
// loadCodeAssist response. Free-tier returns paidTier=null with no usage
// info; paid tier returns availableCredits we can derive percentages from.
type geminiLoadCodeAssistDoc struct {
	CurrentTier *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"currentTier"`
	PaidTier *struct {
		ID               string                `json:"id"`
		Name             string                `json:"name"`
		AvailableCredits []geminiAvailCredit   `json:"availableCredits"`
	} `json:"paidTier"`
	CloudAICompanionProject string `json:"cloudaicompanionProject"`
}

type geminiAvailCredit struct {
	CreditType   string `json:"creditType"`
	CreditAmount *struct {
		Value json.Number `json:"value"`
	} `json:"creditAmount"`
	ValidUntil *string `json:"validUntil"`
}

func geminiMap(d geminiLoadCodeAssistDoc) Snapshot {
	snap := Snapshot{
		SessionWindowSeconds: geminiSessionWindowFallback,
		WeeklyWindowSeconds:  0,
		Tier:                 "unknown",
	}
	if d.PaidTier != nil {
		snap.Tier = d.PaidTier.ID
	} else if d.CurrentTier != nil {
		snap.Tier = d.CurrentTier.ID // typically "free-tier"
	}
	return snap
}

// geminiQuotaDoc mirrors the response shape of v1internal:retrieveUserQuota.
// Sampled 2026-05-25 from a free-tier account; identical structure is
// produced for paid tiers, with the buckets reflecting paid limits.
type geminiQuotaDoc struct {
	Buckets []geminiBucket `json:"buckets"`
}

type geminiBucket struct {
	ModelId           string  `json:"modelId"`
	TokenType         string  `json:"tokenType"`
	RemainingAmount   string  `json:"remainingAmount"`
	RemainingFraction float64 `json:"remainingFraction"`
	ResetTime         string  `json:"resetTime"`
}

// geminiApplyQuota mutates snap to emit one Slot per configured model
// and, for backwards compat with pre-slots firmware, mirrors the first
// matched bucket into SessionPct/SessionResetETASeconds. Gemini has no
// weekly cadence, so weekly_* stays zero and the device hides that
// card on legacy firmware.
//
// pct = 100 * (1 - remainingFraction); reset ETA derived from resetTime
// (RFC3339).
func geminiApplyQuota(snap *Snapshot, q *geminiQuotaDoc, now time.Time, models []string) {
	if q == nil {
		return
	}
	if len(models) == 0 {
		models = []string{geminiSessionModel}
	}
	if len(models) > 3 {
		models = models[:3]
	}
	first := true
	for _, m := range models {
		b := geminiPickBucket(q.Buckets, m)
		if b == nil {
			continue
		}
		pct := geminiUsedPct(b.RemainingFraction)
		eta := geminiResetETA(b.ResetTime, now)
		snap.Slots = append(snap.Slots, Slot{
			Label:           geminiLabel(m),
			Pct:             pct,
			WindowSeconds:   geminiSessionWindowFallback,
			ResetETASeconds: eta,
		})
		if first {
			snap.SessionPct = pct
			snap.SessionResetETASeconds = eta
			first = false
		}
	}
}

// geminiLabel turns a model ID into the short pill text shown on the
// dashboard card. "gemini-2.5-pro" → "Pro"; "gemini-2.5-flash" →
// "Flash"; "gemini-2.5-flash-lite" → "Flash-Lite". Anything that doesn't
// match the gemini-X.Y- prefix falls back to title-casing the raw id.
func geminiLabel(modelID string) string {
	tail := modelID
	if i := strings.Index(tail, "-"); i >= 0 && strings.HasPrefix(tail, "gemini-") {
		tail = tail[len("gemini-"):]
		// Strip the version segment (e.g. "2.5-") so "gemini-2.5-pro"
		// becomes "pro" rather than "2.5-pro". Versions may contain
		// dots or digits; we just chop the first dash-delimited token.
		if j := strings.Index(tail, "-"); j >= 0 {
			tail = tail[j+1:]
		}
	}
	if tail == "" {
		return modelID
	}
	parts := strings.Split(tail, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	out := strings.Join(parts, "-")
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

func geminiPickBucket(buckets []geminiBucket, modelId string) *geminiBucket {
	for i := range buckets {
		if buckets[i].ModelId == modelId {
			return &buckets[i]
		}
	}
	// Fallback: any bucket whose modelId has the same prefix (covers
	// version drift like gemini-2.5-flash-lite vs gemini-2.5-flash).
	for i := range buckets {
		if strings.HasPrefix(buckets[i].ModelId, modelId) {
			return &buckets[i]
		}
	}
	return nil
}

func geminiUsedPct(remainingFraction float64) float64 {
	if remainingFraction < 0 {
		remainingFraction = 0
	} else if remainingFraction > 1 {
		remainingFraction = 1
	}
	return (1 - remainingFraction) * 100
}

func geminiResetETA(resetTime string, now time.Time) uint32 {
	if resetTime == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, resetTime)
	if err != nil {
		return 0
	}
	eta := t.Sub(now).Seconds()
	if eta <= 0 {
		return 0
	}
	return uint32(eta)
}

// token returns a valid access token, refreshing the on-disk one (in
// memory only — we never write back to ~/.gemini/oauth_creds.json) when
// it has less than 60s of life left.
func (f *GeminiFetcher) token(ctx context.Context) (string, error) {
	f.mu.Lock()
	cached := f.cachedTok
	f.mu.Unlock()

	now := f.now()
	if cached.Token != "" && cached.ExpiresAtMS-now.UnixMilli() > 60_000 {
		return cached.Token, nil
	}

	disk, err := loadGeminiCreds(f.CredsPath)
	if err != nil {
		return "", err
	}
	// Honour the on-disk token if it's still fresh.
	if disk.AccessToken != "" && disk.ExpiryDateMS-now.UnixMilli() > 60_000 {
		f.mu.Lock()
		f.cachedTok = geminiAccessToken{Token: disk.AccessToken, ExpiresAtMS: disk.ExpiryDateMS}
		f.mu.Unlock()
		return disk.AccessToken, nil
	}
	if disk.RefreshToken == "" {
		return "", ErrTokenExpired
	}

	// Refresh via Google OAuth. The installed-app credentials live in
	// @google/gemini-cli's published bundle; we resolve them lazily.
	oauth, err := resolveGeminiOAuthClient(ctx, f.httpClient().Do)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("client_id", oauth.ID)
	form.Set("client_secret", oauth.Secret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", disk.RefreshToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("%w: refresh failed status=%d body=%s", ErrUnauthorized, resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransport, err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("%w: refresh returned empty access_token", ErrParseUpstream)
	}
	expMS := now.UnixMilli() + int64(out.ExpiresIn)*1000
	f.mu.Lock()
	f.cachedTok = geminiAccessToken{Token: out.AccessToken, ExpiresAtMS: expMS}
	f.mu.Unlock()
	return out.AccessToken, nil
}

// activeProject returns whatever the Gemini CLI thinks the active GCP
// project is for some cwd in its projects.json. We don't need to match
// the exact cwd — loadCodeAssist works with any of the user's projects.
// Returns "" if the file doesn't exist; cloudcode-pa accepts that too.
func (f *GeminiFetcher) activeProject() string {
	raw, err := os.ReadFile(f.ProjectsPath)
	if err != nil {
		return ""
	}
	var doc struct {
		Projects map[string]string `json:"projects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	for _, p := range doc.Projects {
		return p
	}
	return ""
}

type geminiOnDiskCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiryDateMS int64  `json:"expiry_date"`
}

func loadGeminiCreds(path string) (*geminiOnDiskCreds, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCredsMissing, path)
		}
		return nil, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	var c geminiOnDiskCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if c.AccessToken == "" && c.RefreshToken == "" {
		return nil, fmt.Errorf("%w: empty creds in %s", ErrCredsMissing, path)
	}
	return &c, nil
}
