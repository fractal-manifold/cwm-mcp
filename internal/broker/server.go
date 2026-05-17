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
	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

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
// response code).
func NewMux(cfg *config.Config, cache *auth.NonceCache, st *state.State, logger *log.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCredentials(cfg, cache, logger, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux
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
func Serve(ctx context.Context, ln net.Listener, cfg *config.Config, st *state.State, logger *log.Logger) error {
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	srv := &http.Server{
		Handler:           NewMux(cfg, cache, st, logger),
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
