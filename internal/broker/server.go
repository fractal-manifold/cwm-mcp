// Package broker exposes the HTTP /credentials endpoint that the ESP32
// polls. The handler validates the request's HMAC headers, then reads the
// Claude CLI credentials file and returns the bearer token.
//
// Serve(ctx, ln, cfg, st, logger) accepts an already-bound listener so
// the leader-election layer can hand it the socket without races, and a
// *state.State that the handler updates after each request so the MCP
// tools can introspect activity.
package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/logbuf"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
	"github.com/fractal-manifold/cwm-mcp/internal/state"
	"github.com/fractal-manifold/cwm-mcp/internal/usage"
)

// FirmwareLogSource is the read-side interface the broker needs to serve
// /firmware-logs. The serial tailer owns the *logbuf.Buffer (which already
// satisfies this); tests can plug in a stub. Connected() lets the handler
// flag "device unplugged" vs "no logs yet".
type FirmwareLogSource interface {
	Tail(n int) []string
	Len() int
	Connected() bool
}

// nullFirmwareLogs is the placeholder used when serial tailing is
// disabled in the config. /firmware-logs still answers 200 (with an empty
// list) so callers can distinguish "auth ok, nothing to show" from "broker
// unreachable / signature wrong".
type nullFirmwareLogs struct{}

func (nullFirmwareLogs) Tail(int) []string { return nil }
func (nullFirmwareLogs) Len() int          { return 0 }
func (nullFirmwareLogs) Connected() bool   { return false }

// NewFirmwareLogs builds the FirmwareLogSource the broker handler expects
// from a logbuf and a connectedness probe. Lives here so cmd/main.go can
// pass the result straight into NewMux without leaking adapter types.
func NewFirmwareLogs(buf *logbuf.Buffer, connected func() bool) FirmwareLogSource {
	if buf == nil {
		return nullFirmwareLogs{}
	}
	if connected == nil {
		connected = func() bool { return false }
	}
	return firmwareLogsView{buf: buf, connected: connected}
}

type firmwareLogsView struct {
	buf       *logbuf.Buffer
	connected func() bool
}

func (v firmwareLogsView) Tail(n int) []string { return v.buf.Tail(n) }
func (v firmwareLogsView) Len() int            { return v.buf.Len() }
func (v firmwareLogsView) Connected() bool     { return v.connected() }

// statusRecorder lets us learn the response code chosen by the handler
// so we can record it on the shared *state.State. Every code path in
// this package calls WriteHeader explicitly, so the default of 200 is
// only used in the unlikely "wrote a body without WriteHeader" case.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(s int) {
	r.status = s
	r.ResponseWriter.WriteHeader(s)
}

// NewMux returns the HTTP handler used by both Serve and tests. The
// returned mux records every /credentials hit on `st` (remote addr +
// response code). `fwLogs` may be nil — the handler substitutes a
// null source that answers 200 with an empty list. `reg` may be nil
// — when missing, /credentials falls back to the global PSK in cfg
// (legacy mode) and /device/* answers 404.
func NewMux(cfg *config.Config, cache *auth.NonceCache, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry, usageCache *usage.Cache) *http.ServeMux {
	if fwLogs == nil {
		fwLogs = nullFirmwareLogs{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCredentials(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/credentials/codex", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCodexCredentials(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/firmware-logs", func(w http.ResponseWriter, r *http.Request) {
		handleFirmwareLogs(cfg, cache, logger, fwLogs, w, r)
	})
	mux.HandleFunc("/device/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleDeviceSync(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/usage/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleUsage(cfg, cache, logger, reg, usageCache, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/firmware/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleFirmware(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux
}

// firmwareSHACache memoises SHA-256 hashes of artifacts in FirmwareDir
// keyed by abs path + mtime + size. Computing SHA on every range request
// would be wasteful (and noticeable for big .bin files), and the device
// expects a stable ETag across resume attempts.
type firmwareSHACacheEntry struct {
	mtime time.Time
	size  int64
	hex   string
}

var (
	firmwareSHACache   = map[string]firmwareSHACacheEntry{}
	firmwareSHACacheMu sync.Mutex
)

func firmwareSHA(path string, fi os.FileInfo) (string, error) {
	firmwareSHACacheMu.Lock()
	if e, ok := firmwareSHACache[path]; ok && e.mtime.Equal(fi.ModTime()) && e.size == fi.Size() {
		firmwareSHACacheMu.Unlock()
		return e.hex, nil
	}
	firmwareSHACacheMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	firmwareSHACacheMu.Lock()
	firmwareSHACache[path] = firmwareSHACacheEntry{mtime: fi.ModTime(), size: fi.Size(), hex: sum}
	firmwareSHACacheMu.Unlock()
	return sum, nil
}

// handleFirmware serves binaries from config.FirmwarePath() to devices
// that have been armed with an OTA update. Authenticates with the same
// HMAC-v2 scheme as /credentials, accepting either the device's active
// or pending PSK (so a freshly-rotated device can still pull). Supports
// Range: requests via http.ServeContent so resume-on-reconnect works.
//
// Path traversal is the obvious risk; filepath.Clean and the dir-prefix
// check below close it. Unknown device IDs cannot be derived from the
// request (the URL only carries the file name), so we fall back to the
// global PSK in cfg — same fallback /credentials uses for legacy mode.
func handleFirmware(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/firmware/")
	if name == "" || strings.ContainsAny(name, "/\\") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	baseDir := config.FirmwarePath()
	full := filepath.Join(baseDir, name)
	cleanBase, _ := filepath.Abs(baseDir)
	cleanFull, _ := filepath.Abs(full)
	if !strings.HasPrefix(cleanFull, cleanBase+string(os.PathSeparator)) && cleanFull != cleanBase {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	// Auth: same canonical v2 as everything else. We accept either the
	// global PSK or any registered device's active/pending PSK so the
	// HMAC layer doesn't have to know which device asked.
	signedPath := r.URL.Path
	psks := [][]byte{cfg.PSK()}
	if reg != nil {
		// Look up by X-Cwm-Device when present — cheaper than scanning
		// the whole registry on every request, which a chunked Range
		// download can hit many times in a row.
		if devID := r.Header.Get("X-Cwm-Device"); registry.ValidDeviceID(devID) {
			if a, p, err := reg.PSKsFor(devID); err == nil {
				if len(a) == 32 {
					psks = append(psks, a)
				}
				if len(p) == 32 {
					psks = append(psks, p)
				}
			}
		}
	}
	if _, verr := auth.VerifyMulti(
		psks,
		"GET", signedPath,
		r.Header.Get("X-Cwm-Timestamp"),
		r.Header.Get("X-Cwm-Nonce"),
		r.Header.Get("X-Cwm-Signature"),
		r.Header.Get("X-Cwm-Device"),
		r.Header.Get("X-Cwm-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected /firmware/%s from %s: %v", name, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	f, err := os.Open(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "firmware not found")
			return
		}
		logger.Printf("open %s: %v", full, err)
		writeError(w, http.StatusInternalServerError, "io error")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat failed")
		return
	}
	if sum, err := firmwareSHA(full, fi); err == nil {
		w.Header().Set("ETag", `"`+sum+`"`)
		w.Header().Set("X-Cwm-Firmware-SHA256", sum)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

func handleFirmwareLogs(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, fwLogs FirmwareLogSource, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Sign over the bare path (no query) so the limit param can change
	// without forcing the client to recompute the signature for the same
	// fetch — it's a read-only diagnostic anyway.
	if err := auth.Verify(
		cfg.PSK(),
		"GET", "/firmware-logs",
		r.Header.Get("X-Cwm-Timestamp"),
		r.Header.Get("X-Cwm-Nonce"),
		r.Header.Get("X-Cwm-Signature"),
		r.Header.Get("X-Cwm-Device"),
		r.Header.Get("X-Cwm-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); err != nil {
		logger.Printf("auth rejected /firmware-logs from %s: %v", r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			switch {
			case n < 1:
				limit = 1
			case n > 2000:
				limit = 2000
			default:
				limit = n
			}
		}
	}
	lines := fwLogs.Tail(limit)
	if lines == nil {
		lines = []string{}
	}
	body, _ := json.Marshal(struct {
		Connected bool     `json:"connected"`
		Total     int      `json:"total_available"`
		Lines     []string `json:"lines"`
	}{
		Connected: fwLogs.Connected(),
		Total:     fwLogs.Len(),
		Lines:     lines,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func handleCredentials(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !verifyCredentialRequest(cfg, cache, logger, reg, w, r, "/credentials") {
		return
	}

	c, err := creds.Load(cfg.OAuthPath())
	switch {
	case errors.Is(err, creds.ErrFileMissing):
		writeError(w, http.StatusNotFound, "credentials file missing")
		return
	case err != nil:
		logger.Printf("cannot parse credentials: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot read credentials")
		return
	}
	if c.IsExpired(time.Now()) {
		writeError(w, http.StatusServiceUnavailable, "token expired, refresh on laptop")
		return
	}

	body, _ := json.Marshal(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}{
		AccessToken: c.AccessToken,
		ExpiresAt:   c.ExpiresAtISO(),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func handleCodexCredentials(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !verifyCredentialRequest(cfg, cache, logger, reg, w, r, "/credentials/codex") {
		return
	}
	if !cfg.Codex.Enabled {
		writeError(w, http.StatusNotFound, "codex provider disabled")
		return
	}

	c, err := creds.LoadCodex(cfg.CodexAuthPath())
	switch {
	case errors.Is(err, creds.ErrFileMissing):
		// Missing auth is recoverable: keep the firmware retrying instead
		// of treating Codex as absent for the rest of the boot.
		writeError(w, http.StatusServiceUnavailable, "codex credentials file missing")
		return
	case err != nil:
		logger.Printf("cannot parse codex credentials: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot read codex credentials")
		return
	}
	if c.IsExpired(time.Now()) {
		writeError(w, http.StatusServiceUnavailable, "codex token expired, refresh on laptop")
		return
	}

	body, _ := json.Marshal(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		AccountID   string `json:"account_id"`
	}{
		AccessToken: c.AccessToken,
		ExpiresAt:   c.ExpiresAtISO(),
		AccountID:   c.AccountID,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func verifyCredentialRequest(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request, path string) bool {
	// Per-device path: when X-Cwm-Device is present AND we have a
	// registry, look up the device's PSKs and verify with VerifyMulti.
	// A successful pending-PSK signature plus the version it implies
	// triggers MaybePromote so the broker tracks the rotation. When the
	// header is missing or no registry exists, fall back to the legacy
	// global-PSK path so field devices keep working.
	deviceID := r.Header.Get("X-Cwm-Device")
	if reg != nil && deviceID != "" {
		if !registry.ValidDeviceID(deviceID) {
			writeError(w, http.StatusBadRequest, "invalid device_id")
			return false
		}
		active, pending, perr := reg.PSKsFor(deviceID)
		if errors.Is(perr, registry.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
			return false
		} else if perr != nil {
			logger.Printf("registry lookup %s: %v", deviceID, perr)
			writeError(w, http.StatusInternalServerError, "registry error")
			return false
		}
		res, verr := auth.VerifyMulti(
			[][]byte{active, pending},
			"GET", path,
			r.Header.Get("X-Cwm-Timestamp"),
			r.Header.Get("X-Cwm-Nonce"),
			r.Header.Get("X-Cwm-Signature"),
			r.Header.Get("X-Cwm-Device"),
			r.Header.Get("X-Cwm-Config-Version"),
			cache,
			time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
			time.Now(),
		)
		if verr != nil {
			logger.Printf("auth rejected %s device=%s from %s: %v", path, deviceID, r.RemoteAddr, verr)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return false
		}
		obs, _ := parseUint32Header(r.Header.Get("X-Cwm-Config-Version"))
		if _, perr := reg.MaybePromote(deviceID, obs, res.PSKIndex == 1); perr != nil {
			logger.Printf("registry promote %s: %v", deviceID, perr)
		}
		if terr := reg.Touch(deviceID); terr != nil {
			logger.Printf("registry touch %s: %v", deviceID, terr)
		}
		return true
	}

	if err := auth.Verify(
		cfg.PSK(),
		"GET", path,
		r.Header.Get("X-Cwm-Timestamp"),
		r.Header.Get("X-Cwm-Nonce"),
		r.Header.Get("X-Cwm-Signature"),
		r.Header.Get("X-Cwm-Device"),
		r.Header.Get("X-Cwm-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); err != nil {
		logger.Printf("auth rejected %s from %s: %v", path, r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

// handleUsage serves GET /usage/{provider}. Authenticates with the same
// HMAC envelope as /credentials (per-device or legacy global PSK). On
// upstream success returns the cached Snapshot as JSON; on upstream
// failure with a previously-cached value, returns the stale snapshot
// with 200 + an X-Cwm-Stale-Reason header so the firmware can keep
// rendering while logging the drift.
func handleUsage(cfg *config.Config, nonceCache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, usageCache *usage.Cache, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path is /usage/<provider>; reject anything deeper to avoid
	// silently serving /usage/claude/extra as claude.
	provider := strings.TrimPrefix(r.URL.Path, "/usage/")
	if provider == "" || strings.ContainsRune(provider, '/') {
		writeError(w, http.StatusNotFound, "unknown usage provider")
		return
	}
	if !verifyCredentialRequest(cfg, nonceCache, logger, reg, w, r, "/usage/"+provider) {
		return
	}
	if usageCache == nil {
		writeError(w, http.StatusServiceUnavailable, "usage disabled (no providers configured)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Per-device Gemini override: when the device's registry record has
	// a non-empty gemini_models list, bypass the shared cache so we
	// serve the requested model slice. The token cache inside the
	// GeminiFetcher is still reused, so this is only one extra
	// upstream round-trip per poll.
	deviceID := r.Header.Get("X-Cwm-Device")
	if provider == usage.ProviderGemini && reg != nil && deviceID != "" && registry.ValidDeviceID(deviceID) {
		if models := deviceGeminiModels(reg, deviceID); len(models) > 0 {
			if gf, ok := usageCache.GeminiFetcher(); ok {
				snap, ferr := gf.FetchWithModels(ctx, models)
				if ferr != nil {
					status, msg := usageErrorToHTTP(ferr)
					writeError(w, status, msg)
					return
				}
				snap.FetchedAtUnix = time.Now().Unix()
				writeJSON(w, http.StatusOK, snap)
				return
			}
		}
	}

	snap, err := usageCache.Get(ctx, provider)
	if err != nil {
		// Stale-with-error: cache returned the last good snapshot
		// alongside a transient error. Surface the snapshot and a
		// header so the firmware can log the staleness without
		// blanking the UI.
		if snap.FetchedAtUnix > 0 {
			w.Header().Set("X-Cwm-Stale-Reason", err.Error())
			writeJSON(w, http.StatusOK, snap)
			return
		}
		status, msg := usageErrorToHTTP(err)
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// deviceGeminiModels returns the registry's per-device gemini_models
// override for the given device. Prefers an in-flight pending list (so
// the override applies as soon as it's staged, without waiting for a
// promotion) but falls back to the active value. Returns nil when no
// record exists or the field is empty.
func deviceGeminiModels(reg *registry.Registry, deviceID string) []string {
	dev, err := reg.Load(deviceID)
	if err != nil || dev == nil {
		return nil
	}
	if dev.Pending != nil && len(dev.Pending.GeminiModels) > 0 {
		out := make([]string, len(dev.Pending.GeminiModels))
		copy(out, dev.Pending.GeminiModels)
		return out
	}
	if len(dev.Active.GeminiModels) > 0 {
		out := make([]string, len(dev.Active.GeminiModels))
		copy(out, dev.Active.GeminiModels)
		return out
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func usageErrorToHTTP(err error) (int, string) {
	switch {
	case errors.Is(err, usage.ErrCredsMissing):
		return http.StatusNotFound, "creds file missing"
	case errors.Is(err, usage.ErrTokenExpired):
		return http.StatusServiceUnavailable, "token expired, refresh on laptop"
	case errors.Is(err, usage.ErrUnauthorized):
		return http.StatusUnauthorized, "upstream rejected token"
	case errors.Is(err, usage.ErrRateLimited):
		return http.StatusTooManyRequests, "rate limited"
	case errors.Is(err, usage.ErrNotImpl), errors.Is(err, usage.ErrDisabled):
		return http.StatusNotImplemented, "provider not enabled"
	case errors.Is(err, usage.ErrTransport):
		return http.StatusBadGateway, "transport error"
	case errors.Is(err, usage.ErrUpstream), errors.Is(err, usage.ErrParseUpstream):
		return http.StatusBadGateway, "upstream error"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

// pendingBlob is the wire format of an encrypted pending payload.
// payload_b64 is the AES-CTR ciphertext (base64-std), nonce_b64 is the
// 16-byte IV (also base64-std). Decryption requires the device's
// currently-active PSK; the new PSK lives *inside* the payload, so a
// passive attacker watching one rotation can't learn the next key
// unless they already broke the active one.
type pendingBlob struct {
	Version    uint32 `json:"version"`
	NonceB64   string `json:"nonce_b64"`
	PayloadB64 string `json:"payload_b64"`
}

type syncResponse struct {
	ActiveVersion uint32       `json:"active_version"`
	Pending       *pendingBlob `json:"pending,omitempty"`
}

// pendingPayloadJSON serialises a registry.ConfigPayload to the canonical
// JSON the firmware decrypts. Kept separate so changes to TOML
// representation in registry don't leak into the wire format.
func pendingPayloadJSON(p registry.ConfigPayload) ([]byte, error) {
	wire := map[string]any{
		"version": p.Version,
	}
	if p.BrokerURL != "" {
		wire["broker_url"] = p.BrokerURL
	}
	if p.PSKHex != "" {
		wire["psk_hex"] = p.PSKHex
	}
	if p.City != "" {
		wire["city"] = p.City
	}
	if p.BrDay != nil && *p.BrDay != 0 {
		wire["br_day"] = *p.BrDay
	}
	if p.BrNight != nil && *p.BrNight != 0 {
		wire["br_night"] = *p.BrNight
	}
	if p.Vol != nil {
		// vol == 0 is "muted", which is a legitimate state the device
		// must be able to receive; only nil means "no change".
		wire["vol"] = *p.Vol
	}
	if p.Providers != nil {
		wire["providers"] = map[string]bool{
			"claude": p.Providers.Claude,
			"codex":  p.Providers.Codex,
			"gemini": p.Providers.Gemini,
		}
	}
	if p.AutorotateEnabled != nil {
		wire["autorotate_enabled"] = *p.AutorotateEnabled
	}
	if p.AutorotateIntervalS != nil {
		wire["autorotate_interval_s"] = *p.AutorotateIntervalS
	}
	if p.ThemeMode != "" {
		// firmware/config_sync.c reads "theme_mode" from the decrypted
		// blob and writes it to KEY_THEME_MD. Omitting it here would
		// silently no-op /wall-monitor:theme switches.
		wire["theme_mode"] = p.ThemeMode
	}
	if len(p.GeminiModels) > 0 {
		// firmware/config_sync.c reads "gemini_models" as a CSV string
		// and writes it to NVS key cwm_gem_mdls. The device uses it
		// purely as a hint for /usage/gemini polling (the broker also
		// looks at the registry override directly); persisting it on
		// device makes the override observable in Settings and survive
		// broker restarts before the next sync.
		wire["gemini_models"] = strings.Join(p.GeminiModels, ",")
	}
	// OTA staging fields. firmware/components/net/src/config_sync.c
	// requires ALL THREE to be present and well-formed before arming
	// the on-device cwm_ota_* NVS keys, so we send them together or
	// not at all. The SHA-256 is the integrity anchor for the .bin.
	if p.FirmwareURL != "" && p.FirmwareSHA256 != "" && p.FirmwareVersion != "" {
		wire["firmware_url"] = p.FirmwareURL
		wire["firmware_sha256"] = p.FirmwareSHA256
		wire["firmware_version"] = p.FirmwareVersion
	}
	// Signed manifest delivery (schema v2). The firmware verifies the
	// Ed25519 signature over the canonical manifest BEFORE downloading
	// the .bin, so missing either field on a firmware-bearing pending
	// turns the OTA into a no-op (production firmware refuses unsigned
	// manifests unless built with CWM_OTA_UNSIGNED=y). We forward
	// whichever fields are present and let the device-side gate apply
	// the policy.
	if p.FirmwareManifestB64 != "" {
		wire["firmware_manifest_b64"] = p.FirmwareManifestB64
	}
	if p.FirmwareManifestSigB64 != "" {
		wire["firmware_manifest_sig_b64"] = p.FirmwareManifestSigB64
	}
	return json.Marshal(wire)
}

// handleDeviceSync implements GET /device/{id}/sync. Verifies the
// signature with active+pending PSKs (so a device freshly rotated to
// pending PSK can fetch and confirm), promotes if the device has
// adopted pending, and returns the (encrypted) pending blob whenever
// the device's reported config_version lags behind.
func handleDeviceSync(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if reg == nil {
		writeError(w, http.StatusNotFound, "device registry not configured")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path is /device/{id}/sync; reject anything else under /device/.
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/device/"), "/")
	if len(parts) != 2 || parts[1] != "sync" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	deviceID := parts[0]
	if !registry.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	active, pending, perr := reg.PSKsFor(deviceID)
	if errors.Is(perr, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	} else if perr != nil {
		logger.Printf("registry lookup %s: %v", deviceID, perr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	// Path used in the signature is the literal URL path so the firmware
	// signs the same string the router parses. Query string is not in
	// scope today; if /sync ever gets one, both ends update together.
	signedPath := r.URL.Path
	res, verr := auth.VerifyMulti(
		[][]byte{active, pending},
		"GET", signedPath,
		r.Header.Get("X-Cwm-Timestamp"),
		r.Header.Get("X-Cwm-Nonce"),
		r.Header.Get("X-Cwm-Signature"),
		r.Header.Get("X-Cwm-Device"),
		r.Header.Get("X-Cwm-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	)
	if verr != nil {
		logger.Printf("auth rejected /device/%s/sync from %s: %v", deviceID, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	observed, _ := parseUint32Header(r.Header.Get("X-Cwm-Config-Version"))

	// Promote opportunistically on every authenticated /sync. For key
	// rotations the device must sign with the pending PSK (PSKIndex==1);
	// for non-rotation updates (theme / city / brightness / providers)
	// the version header on a valid active-PSK signature is enough.
	if _, perr := reg.MaybePromote(deviceID, observed, res.PSKIndex == 1); perr != nil {
		logger.Printf("registry promote %s: %v", deviceID, perr)
	}
	if terr := reg.Touch(deviceID); terr != nil {
		logger.Printf("registry touch %s: %v", deviceID, terr)
	}
	// Schema v2: capture the device's reported factory serial + SKU
	// when present. These headers are NOT bound to the HMAC (see
	// CLAUDE.md "Things NOT to assume" — the X-Cwm-Sku is metadata of
	// routing, not a security control). The Ed25519 manifest on a
	// pending firmware is what actually enforces SKU at install time.
	if serial := r.Header.Get("X-Cwm-Serial"); serial != "" {
		sku := r.Header.Get("X-Cwm-Sku")
		if serr := reg.SetSerial(deviceID, serial, sku); serr != nil {
			logger.Printf("registry set-serial %s: %v", deviceID, serr)
		}
	}
	// Mirror the device's anti-rollback floor. BumpMinSV is monotonic
	// in the registry; a spoofed-high value can only lock the device
	// out of downgrade attacks, not enable one.
	if msv := r.Header.Get("X-Cwm-Min-Sv"); msv != "" {
		if sv, err := strconv.ParseUint(msv, 10, 32); err == nil {
			if berr := reg.BumpMinSV(deviceID, uint32(sv)); berr != nil {
				logger.Printf("registry bump-min-sv %s: %v", deviceID, berr)
			}
		}
	}

	dev, lerr := reg.Load(deviceID)
	if lerr != nil {
		logger.Printf("registry reload %s: %v", deviceID, lerr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	resp := syncResponse{ActiveVersion: dev.Active.Version}
	if dev.Pending != nil && observed < dev.Pending.Version {
		// Encrypt the pending payload with the device's *currently active*
		// PSK. The device decrypts with what it already has, learns the
		// new key from inside, and only the next rotation needs the new
		// key. Bricked-broker captures see ciphertext, not the next PSK.
		if len(active) != 32 {
			logger.Printf("device %s active PSK not 32 bytes (%d) — cannot encrypt pending", deviceID, len(active))
			writeError(w, http.StatusInternalServerError, "broker config invalid")
			return
		}
		pt, perr := pendingPayloadJSON(dev.Pending.ConfigPayload)
		if perr != nil {
			logger.Printf("pending JSON marshal %s: %v", deviceID, perr)
			writeError(w, http.StatusInternalServerError, "pending serialize")
			return
		}
		nonce, ct, eerr := registry.EncryptPending(active, pt)
		if eerr != nil {
			logger.Printf("pending encrypt %s: %v", deviceID, eerr)
			writeError(w, http.StatusInternalServerError, "pending encrypt")
			return
		}
		resp.Pending = &pendingBlob{
			Version:    dev.Pending.Version,
			NonceB64:   base64.StdEncoding.EncodeToString(nonce),
			PayloadB64: base64.StdEncoding.EncodeToString(ct),
		}
	}

	body, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func parseUint32Header(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: msg})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Serve takes ownership of an already-bound listener and runs the HTTP
// broker until ctx is cancelled. On cancellation it shuts down with a 1s
// drain so the leader-election follower can grab the port quickly.
// `fwLogs` is the read-side of the serial tailer; pass nil to keep
// /firmware-logs answering 200 with an empty list. `reg` may be nil
// to disable the per-device control plane (legacy global-PSK mode).
func Serve(ctx context.Context, ln net.Listener, cfg *config.Config, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry, usageCache *usage.Cache) error {
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	srv := &http.Server{
		Handler:           NewMux(cfg, cache, st, logger, fwLogs, reg, usageCache),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("broker: serving on %s", ln.Addr())
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Printf("broker: shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	}
}
