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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/logbuf"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
	"github.com/fractal-manifold/cwm-mcp/internal/state"
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
func NewMux(cfg *config.Config, cache *auth.NonceCache, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry) *http.ServeMux {
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
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux
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
		res, verr := auth.VerifyMulti(
			[][]byte{active, pending},
			"GET", "/credentials",
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
			logger.Printf("auth rejected /credentials device=%s from %s: %v", deviceID, r.RemoteAddr, verr)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// Attempt promotion on every authenticated request. MaybePromote
		// itself decides whether the signature proves the rotation
		// (pending PSK used) or — for non-key-rotation pending updates
		// like theme / city / brightness — whether the version header
		// alone with the active PSK is enough.
		obs, _ := parseUint32Header(r.Header.Get("X-Cwm-Config-Version"))
		if _, perr := reg.MaybePromote(deviceID, obs, res.PSKIndex == 1); perr != nil {
			logger.Printf("registry promote %s: %v", deviceID, perr)
		}
		if terr := reg.Touch(deviceID); terr != nil {
			logger.Printf("registry touch %s: %v", deviceID, terr)
		}
	} else {
		if err := auth.Verify(
			cfg.PSK(),
			"GET", "/credentials",
			r.Header.Get("X-Cwm-Timestamp"),
			r.Header.Get("X-Cwm-Nonce"),
			r.Header.Get("X-Cwm-Signature"),
			r.Header.Get("X-Cwm-Device"),
			r.Header.Get("X-Cwm-Config-Version"),
			cache,
			time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
			time.Now(),
		); err != nil {
			logger.Printf("auth rejected from %s: %v", r.RemoteAddr, err)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
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
func Serve(ctx context.Context, ln net.Listener, cfg *config.Config, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry) error {
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	srv := &http.Server{
		Handler:           NewMux(cfg, cache, st, logger, fwLogs, reg),
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
