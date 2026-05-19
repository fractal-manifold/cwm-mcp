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
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/logbuf"
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
// null source that answers 200 with an empty list.
func NewMux(cfg *config.Config, cache *auth.NonceCache, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource) *http.ServeMux {
	if fwLogs == nil {
		fwLogs = nullFirmwareLogs{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCredentials(cfg, cache, logger, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/firmware-logs", func(w http.ResponseWriter, r *http.Request) {
		handleFirmwareLogs(cfg, cache, logger, fwLogs, w, r)
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

func handleCredentials(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	err := auth.Verify(
		cfg.PSK(),
		"GET", "/credentials",
		r.Header.Get("X-Cwm-Timestamp"),
		r.Header.Get("X-Cwm-Nonce"),
		r.Header.Get("X-Cwm-Signature"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	)
	if err != nil {
		// Never leak the reason to the client.
		logger.Printf("auth rejected from %s: %v", r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
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
// /firmware-logs answering 200 with an empty list.
func Serve(ctx context.Context, ln net.Listener, cfg *config.Config, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource) error {
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	srv := &http.Server{
		Handler:           NewMux(cfg, cache, st, logger, fwLogs),
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
