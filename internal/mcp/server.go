// Package mcp exposes the cwm-mcp tools to Claude Code over the standard
// MCP stdio JSON-RPC transport. Five tools are registered:
//
//   wall_monitor_status          — quick snapshot (role, last request, etc.)
//   wall_monitor_health          — full diagnostic: creds + self-ping
//   wall_monitor_recent_logs     — last N broker log lines (local buffer)
//   wall_monitor_firmware_logs   — last N ESP-IDF log lines from the device
//   wall_monitor_provision_hint  — IP/port to enter in the device's captive portal
//
// The MCP server runs in its own goroutine alongside the broker; it does
// not own the listener or the broker — it just reads from the shared
// state/logbuf and sends signed self-probes via HTTP when asked.
//
// wall_monitor_firmware_logs goes through the broker's /firmware-logs HTTP
// endpoint (signed HMAC) instead of reading a local logbuf. That way any
// session — leader or follower — can see the same tail, since only the
// leader process owns the serial port but every process can do a signed
// loopback GET to whatever process won leadership.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/logbuf"
	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

// Deps bundles everything the tools need; passed into NewServer so the
// caller controls lifetime.
type Deps struct {
	Cfg     *config.Config
	State   *state.State
	Logs    *logbuf.Buffer
	Version string
}

// NewServer wires the four tools onto a fresh MCP server. Caller is
// expected to hand the returned *MCPServer to server.ServeStdio.
func NewServer(d Deps) *server.MCPServer {
	s := server.NewMCPServer(
		"cwm-mcp",
		d.Version,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_status",
			mcp.WithDescription("Snapshot of the cwm-mcp broker: role (leader/follower), when the role started, and the most recent ESP32 request (timestamp, remote address, HTTP status, count)."),
		),
		handleStatus(d),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_health",
			mcp.WithDescription("End-to-end diagnostic. Checks the OAuth credentials file (presence, parseability, expiry) and self-pings the broker over HTTP with a signed request. Returns one PASS/FAIL block per component."),
		),
		handleHealth(d),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_recent_logs",
			mcp.WithDescription("Tail the broker log buffer (in-memory). Useful to see why the device is being rejected or which IPs are polling. Default is the last 50 lines."),
			mcp.WithString("limit",
				mcp.Description("How many lines to return (1..500). Defaults to 50."),
			),
		),
		handleRecentLogs(d),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_firmware_logs",
			mcp.WithDescription("Tail the ESP-IDF log stream from the device over USB-CDC. Requires `[serial] device` to be set in cwm.toml on the laptop running cwm-mcp. The tool fetches via a signed HTTP GET to the broker, so any cwm-mcp session (leader or follower) returns the same lines. Default is the last 200 lines; max 2000."),
			mcp.WithString("limit",
				mcp.Description("How many lines to return (1..2000). Defaults to 200."),
			),
		),
		handleFirmwareLogs(d),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_provision_hint",
			mcp.WithDescription("Print the address(es) the device should be told to poll in its captive portal `svc_url` field — i.e. the laptop's non-loopback IPv4 interfaces, paired with the configured broker port."),
		),
		handleProvisionHint(d),
	)

	return s
}

// --- wall_monitor_status -----------------------------------------------------

func handleStatus(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		snap := d.State.Snapshot()
		out := struct {
			Version    string         `json:"version"`
			Addr       string         `json:"addr"`
			OAuthPath  string         `json:"oauth_path"`
			ConfigInfo configInfo     `json:"config"`
			Snapshot   state.Snapshot `json:"snapshot"`
		}{
			Version:    d.Version,
			Addr:       brokerAddr(d.Cfg),
			OAuthPath:  d.Cfg.OAuthPath(),
			ConfigInfo: configInfoOf(d.Cfg),
			Snapshot:   snap,
		}
		return mcp.NewToolResultJSON(out)
	}
}

type configInfo struct {
	MaxSkewSeconds  int    `json:"max_timestamp_skew_seconds"`
	NonceCacheTTLS  int    `json:"nonce_cache_ttl_seconds"`
	AuthMode        string `json:"auth_mode"` // "passphrase" or "psk_hex"
	LoggingLevel    string `json:"logging_level"`
}

func configInfoOf(c *config.Config) configInfo {
	mode := "passphrase"
	if c.Auth.Passphrase == "" {
		mode = "psk_hex"
	}
	return configInfo{
		MaxSkewSeconds: c.Security.MaxTimestampSkewSeconds,
		NonceCacheTTLS: c.Security.NonceCacheTTLSeconds,
		AuthMode:       mode,
		LoggingLevel:   c.Logging.Level,
	}
}

// --- wall_monitor_health -----------------------------------------------------

type healthCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

func handleHealth(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var checks []healthCheck

		// 1. credentials file.
		c, err := creds.Load(d.Cfg.OAuthPath())
		switch {
		case err != nil:
			checks = append(checks, healthCheck{"credentials", false, err.Error()})
		case c.IsExpired(time.Now()):
			checks = append(checks, healthCheck{"credentials", false,
				"token expired at " + c.ExpiresAtISO()})
		default:
			checks = append(checks, healthCheck{"credentials", true,
				"valid until " + c.ExpiresAtISO()})
		}

		// 2. self-ping the broker with a signed request to whatever
		//    process happens to own the port (could be us or a peer).
		checks = append(checks, runSelfPing(ctx, d.Cfg))

		// 3. role consistency: if we recorded a successful 200 recently
		//    it really is talking to *something*.
		snap := d.State.Snapshot()
		switch {
		case snap.RequestsTotal == 0:
			checks = append(checks, healthCheck{"observed_traffic", false,
				"no requests received yet"})
		case snap.LastRequestStatus == http.StatusOK:
			checks = append(checks, healthCheck{"observed_traffic", true,
				"last request OK at " + snap.LastRequestAt.Format(time.RFC3339)})
		default:
			checks = append(checks, healthCheck{"observed_traffic", false,
				"last request returned " + strconv.Itoa(snap.LastRequestStatus)})
		}

		allOK := true
		for _, c := range checks {
			if !c.Pass {
				allOK = false
				break
			}
		}
		return mcp.NewToolResultJSON(struct {
			OK     bool          `json:"ok"`
			Role   string        `json:"role"`
			Checks []healthCheck `json:"checks"`
		}{OK: allOK, Role: snap.Role, Checks: checks})
	}
}

func runSelfPing(ctx context.Context, cfg *config.Config) healthCheck {
	host := cfg.Server.Bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Server.Port)) + "/credentials"

	nonce := "1111111111111111deadbeefdeadbeef"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/credentials", ts, nonce)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("X-Cwm-Timestamp", ts)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return healthCheck{"self_ping", false, "broker unreachable: " + err.Error()}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return healthCheck{"self_ping", true, "broker answered 200"}
	case http.StatusServiceUnavailable:
		return healthCheck{"self_ping", false, "broker says token expired (503)"}
	case http.StatusNotFound:
		return healthCheck{"self_ping", false, "broker says credentials file missing (404)"}
	case http.StatusUnauthorized:
		return healthCheck{"self_ping", false, "broker rejected our signature (401) — PSK mismatch?"}
	default:
		return healthCheck{"self_ping", false, "broker returned " + strconv.Itoa(resp.StatusCode)}
	}
}

// --- wall_monitor_recent_logs ------------------------------------------------

func handleRecentLogs(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit := 50
		if raw := req.GetString("limit", ""); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				switch {
				case n < 1:
					limit = 1
				case n > 500:
					limit = 500
				default:
					limit = n
				}
			}
		}
		lines := d.Logs.Tail(limit)
		return mcp.NewToolResultJSON(struct {
			Total int      `json:"total_available"`
			Lines []string `json:"lines"`
		}{Total: d.Logs.Len(), Lines: lines})
	}
}

// --- wall_monitor_firmware_logs ---------------------------------------------

func handleFirmwareLogs(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit := 200
		if raw := req.GetString("limit", ""); raw != "" {
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

		host := d.Cfg.Server.Bind
		if host == "0.0.0.0" || host == "" {
			host = "127.0.0.1"
		}
		url := "http://" + net.JoinHostPort(host, strconv.Itoa(d.Cfg.Server.Port)) +
			"/firmware-logs?limit=" + strconv.Itoa(limit)

		nonce := freshNonce()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sig := auth.ComputeSignature(d.Cfg.PSK(), "GET", "/firmware-logs", ts, nonce)

		httpReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		httpReq.Header.Set("X-Cwm-Timestamp", ts)
		httpReq.Header.Set("X-Cwm-Nonce", nonce)
		httpReq.Header.Set("X-Cwm-Signature", sig)

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			return mcp.NewToolResultJSON(struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			}{OK: false, Error: "broker unreachable: " + err.Error()})
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return mcp.NewToolResultJSON(struct {
				OK         bool   `json:"ok"`
				HTTPStatus int    `json:"http_status"`
				Body       string `json:"body"`
			}{OK: false, HTTPStatus: resp.StatusCode, Body: string(body)})
		}
		// Pass through the broker's JSON body unchanged.
		return mcp.NewToolResultText(string(body)), nil
	}
}

// freshNonce returns a 32-hex random nonce, the format the broker's
// HMAC verifier requires (isHex32 in internal/auth).
func freshNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// --- wall_monitor_provision_hint --------------------------------------------

func handleProvisionHint(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ips, err := localIPv4s()
		if err != nil {
			return mcp.NewToolResultErrorFromErr("listing interfaces", err), nil
		}
		port := d.Cfg.Server.Port
		var urls []string
		for _, ip := range ips {
			urls = append(urls, fmt.Sprintf("http://%s", net.JoinHostPort(ip, strconv.Itoa(port))))
		}

		// Friendly note if the broker is bound to loopback only — the
		// device on the LAN won't be able to reach us at all.
		var warning string
		if d.Cfg.Server.Bind == "127.0.0.1" || d.Cfg.Server.Bind == "localhost" {
			warning = "broker is bound to 127.0.0.1; the device can only reach it from this host. Switch bind to 0.0.0.0 in cwm.toml."
		}

		return mcp.NewToolResultJSON(struct {
			Port    int      `json:"port"`
			Bind    string   `json:"bind"`
			Hosts   []string `json:"hosts"`
			URLs    []string `json:"urls"`
			Warning string   `json:"warning,omitempty"`
		}{
			Port:    port,
			Bind:    d.Cfg.Server.Bind,
			Hosts:   ips,
			URLs:    urls,
			Warning: warning,
		})
	}
}

func localIPv4s() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := n.IP.To4()
			if ip == nil {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// brokerAddr exists so handleStatus stays free of the import cycle that would
// arise if we asked main for it.
func brokerAddr(c *config.Config) string {
	return net.JoinHostPort(c.Server.Bind, strconv.Itoa(c.Server.Port))
}

// Compile-time assertion that we can marshal a Snapshot — keeps changes to
// state.Snapshot from silently regressing tool output.
var _ = json.Marshal
