package broker

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

func writeCredsFile(t *testing.T, expiresAt int64) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	body := `{"claudeAiOauth":{"accessToken":"tok-xyz","expiresAt":` +
		strconv.FormatInt(expiresAt, 10) + `}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCodexCredsFile(t *testing.T, expiresAt int64) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-auth.json")
	body := `{"tokens":{"access_token":"codex-token","account_id":"acct_123"},"expires_at":` +
		strconv.FormatInt(expiresAt, 10) + `}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testConfig builds a Config with a deterministic PSK. We bypass config.Load
// because that requires a TOML file; constructing the struct directly is
// fine for tests since we only need PSK + paths + security settings.
type testCfg struct {
	psk []byte
	*config.Config
}

func newTestConfig(t *testing.T, credsPath string) *config.Config {
	return newTestConfigWithCodex(t, credsPath, false, "~/.codex/auth.json")
}

func newTestConfigWithCodex(t *testing.T, credsPath string, codexEnabled bool, codexPath string) *config.Config {
	t.Helper()
	// We can't set pskBytes from outside the package, so write a tiny TOML
	// to a temp file and let config.Load do its job.
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "cwm.toml")
	body := `
[server]
bind = "127.0.0.1"
port = 0
[auth]
psk_passphrase = "test-passphrase-1234567890"
[credentials]
oauth_path = "` + credsPath + `"
[codex]
enabled = ` + strconv.FormatBool(codexEnabled) + `
auth_path = "` + codexPath + `"
[security]
max_timestamp_skew_seconds = 60
nonce_cache_ttl_seconds = 300
[logging]
level = "INFO"
`
	if err := os.WriteFile(tomlPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newCodexTestServer(t *testing.T, codexPath string, enabled bool) (*httptest.Server, *config.Config) {
	t.Helper()
	cfg := newTestConfigWithCodex(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()), enabled, codexPath)
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	ts := httptest.NewServer(NewMux(cfg, cache, state.New(), logger, nil, nil, nil))
	t.Cleanup(ts.Close)
	return ts, cfg
}

func newTestServer(t *testing.T, credsPath string) (*httptest.Server, *config.Config) {
	t.Helper()
	cfg := newTestConfig(t, credsPath)
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	ts := httptest.NewServer(NewMux(cfg, cache, state.New(), logger, nil, nil, nil))
	t.Cleanup(ts.Close)
	return ts, cfg
}

func signedRequest(t *testing.T, ts *httptest.Server, cfg *config.Config, nonce string) *http.Response {
	return signedRequestPath(t, ts, cfg, "/credentials", nonce)
}

func signedRequestPath(t *testing.T, ts *httptest.Server, cfg *config.Config, path string, nonce string) *http.Response {
	t.Helper()
	now := time.Now().Unix()
	tsHdr := strconv.FormatInt(now, 10)
	sig := auth.ComputeSignature(cfg.PSK(), "GET", path, tsHdr, nonce, "", "")

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Cwm-Timestamp", tsHdr)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestServer_HappyPath(t *testing.T) {
	creds := writeCredsFile(t, time.Now().Add(1*time.Hour).UnixMilli())
	ts, cfg := newTestServer(t, creds)

	resp := signedRequest(t, ts, cfg, "0123456789abcdef0123456789abcdef")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "tok-xyz" {
		t.Errorf("token: got %q", got.AccessToken)
	}
	if got.ExpiresAt == "" {
		t.Error("expires_at empty")
	}
}

func TestServer_UnauthorizedNoHeaders(t *testing.T) {
	creds := writeCredsFile(t, time.Now().Add(1*time.Hour).UnixMilli())
	ts, _ := newTestServer(t, creds)

	resp, err := http.Get(ts.URL + "/credentials")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServer_WrongSignature(t *testing.T) {
	creds := writeCredsFile(t, time.Now().Add(1*time.Hour).UnixMilli())
	ts, _ := newTestServer(t, creds)

	now := time.Now().Unix()
	req, _ := http.NewRequest("GET", ts.URL+"/credentials", nil)
	req.Header.Set("X-Cwm-Timestamp", strconv.FormatInt(now, 10))
	req.Header.Set("X-Cwm-Nonce", "0123456789abcdef0123456789abcdef")
	req.Header.Set("X-Cwm-Signature", "deadbeef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServer_CredsMissing(t *testing.T) {
	ts, cfg := newTestServer(t, "/nonexistent/path/creds.json")
	resp := signedRequest(t, ts, cfg, "0123456789abcdef0123456789abcdef")
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestServer_TokenExpired(t *testing.T) {
	creds := writeCredsFile(t, time.Now().Add(-1*time.Hour).UnixMilli())
	ts, cfg := newTestServer(t, creds)
	resp := signedRequest(t, ts, cfg, "0123456789abcdef0123456789abcdef")
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestServer_CodexHappyPath(t *testing.T) {
	codex := writeCodexCredsFile(t, time.Now().Add(time.Hour).UnixMilli())
	ts, cfg := newCodexTestServer(t, codex, true)

	resp := signedRequestPath(t, ts, cfg, "/credentials/codex", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		AccountID   string `json:"account_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "codex-token" {
		t.Errorf("token: got %q", got.AccessToken)
	}
	if got.AccountID != "acct_123" {
		t.Errorf("account_id: got %q", got.AccountID)
	}
	if got.ExpiresAt == "" {
		t.Error("expires_at empty")
	}
}

func TestServer_CodexDisabled(t *testing.T) {
	codex := writeCodexCredsFile(t, time.Now().Add(time.Hour).UnixMilli())
	ts, cfg := newCodexTestServer(t, codex, false)

	resp := signedRequestPath(t, ts, cfg, "/credentials/codex", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestServer_CodexMissingCredsIsRetryable(t *testing.T) {
	ts, cfg := newCodexTestServer(t, "/nonexistent/path/codex-auth.json", true)

	resp := signedRequestPath(t, ts, cfg, "/credentials/codex", "cccccccccccccccccccccccccccccccc")
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestServer_NonceReplay(t *testing.T) {
	creds := writeCredsFile(t, time.Now().Add(1*time.Hour).UnixMilli())
	ts, cfg := newTestServer(t, creds)

	r1 := signedRequest(t, ts, cfg, "fedcba9876543210fedcba9876543210")
	io.Copy(io.Discard, r1.Body)
	r1.Body.Close()
	if r1.StatusCode != 200 {
		t.Fatalf("first request: %d", r1.StatusCode)
	}

	now := time.Now().Unix()
	tsHdr := strconv.FormatInt(now, 10)
	nonce := "fedcba9876543210fedcba9876543210"
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/credentials", tsHdr, nonce, "", "")
	req, _ := http.NewRequest("GET", ts.URL+"/credentials", nil)
	req.Header.Set("X-Cwm-Timestamp", tsHdr)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 on replay, got %d", resp.StatusCode)
	}
}

func TestServer_NotFound(t *testing.T) {
	ts, _ := newTestServer(t, "/tmp/whatever")
	resp, err := http.Get(ts.URL + "/whatever")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
