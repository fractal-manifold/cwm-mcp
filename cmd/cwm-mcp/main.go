// cwm-mcp serves OAuth credentials to the Claude Wall Monitor device.
//
// Default mode (no flags) is "MCP-stdio + bind-elected broker": several
// Claude Code sessions can each launch this binary; one of them wins the
// TCP port and runs the credentials broker, the rest probe in the
// background and take over if the leader exits. See internal/leader.
//
// Flags:
//   --daemon   Standalone broker. Just binds and serves; no leader probing.
//              Use this when running under systemd or any always-on supervisor.
//   --once     Validate that the credentials file is readable + not expired,
//              print a one-line summary, and exit. Useful for smoke tests.
//   --status   Probe the local broker (if any) for a status JSON dump.
//   --config   Path to cwm.toml (default: ~/.config/claude-wall-monitor/cwm.toml,
//              with fallback to service.toml for legacy installations).
//   --version  Print version and exit.
//   --probe    Report the runtime ("go") plus version to stderr and exit
//              0 if this binary is healthy enough for the launcher to
//              dispatch to it. Used by cwm-mcp-launcher (POSIX sh) to
//              pick between the Go, Python and JS impls.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/broker"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/leader"
	"github.com/fractal-manifold/cwm-mcp/internal/logbuf"
	"github.com/fractal-manifold/cwm-mcp/internal/mcp"
	"github.com/fractal-manifold/cwm-mcp/internal/mdns"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
	"github.com/fractal-manifold/cwm-mcp/internal/serial"
	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	configPath := flag.String("config", "", "Path to cwm.toml (default: ~/.config/claude-wall-monitor/cwm.toml)")
	daemonMode := flag.Bool("daemon", false, "Standalone broker — bind unconditionally, no leader-election")
	onceMode := flag.Bool("once", false, "Validate credentials file and exit")
	statusMode := flag.Bool("status", false, "Probe local broker and print status JSON")
	logsMode := flag.Bool("logs", false, "Tail firmware logs from the running broker (Ctrl-C to stop)")
	logsTail := flag.Int("logs-tail", 50, "How many backlog lines to print before following live (with --logs)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	probeFlag := flag.Bool("probe", false, "Report runtime+version on stderr and exit 0 (used by cwm-mcp-launcher)")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		return
	}
	if *probeFlag {
		// Launcher convention: stderr only; stdout stays clean. Format
		// is "<runtime> <version>" so the launcher can use it to
		// disambiguate which impl answered.
		fmt.Fprintf(os.Stderr, "go %s\n", Version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	// All log output goes to stderr (stdio MCP reserves stdout for
	// JSON-RPC). We also tee into a small ring buffer so the
	// wall_monitor_recent_logs tool has something to return.
	logs := logbuf.New(200)
	logger := log.New(io.MultiWriter(os.Stderr, logs), "cwm-mcp ", log.LstdFlags|log.Lmicroseconds)

	switch {
	case *onceMode:
		os.Exit(runOnce(cfg))
	case *statusMode:
		os.Exit(runStatus(cfg))
	case *logsMode:
		os.Exit(runLogs(cfg, *logsTail))
	case *daemonMode:
		os.Exit(runDaemon(cfg, logger, logs))
	default:
		os.Exit(runMCP(cfg, logger, logs))
	}
}

func addrOf(cfg *config.Config) string {
	return net.JoinHostPort(cfg.Server.Bind, strconv.Itoa(cfg.Server.Port))
}

// openRegistry opens the per-device store under
// ~/.config/claude-wall-monitor/devices/. A failure is logged but does
// not abort the broker — the legacy global-PSK path still works without
// it, and the next /credentials call from a registered device will 401
// instead of brick-flashing a working setup.
func openRegistry(logger *log.Logger) *registry.Registry {
	reg, err := registry.New(config.DevicesPath())
	if err != nil {
		logger.Printf("registry: %v (per-device control plane disabled)", err)
		return nil
	}
	return reg
}

func runOnce(cfg *config.Config) int {
	c, err := creds.Load(cfg.OAuthPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "creds: %v\n", err)
		return 1
	}
	if c.IsExpired(time.Now()) {
		fmt.Fprintf(os.Stderr, "creds: expired at %s\n", c.ExpiresAtISO())
		return 1
	}
	fmt.Printf("creds OK (expires_at=%s)\n", c.ExpiresAtISO())
	return 0
}

func runDaemon(cfg *config.Config, logger *log.Logger, logs *logbuf.Buffer) int {
	addr := addrOf(cfg)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Printf("listen %s: %v", addr, err)
		return 1
	}
	st := state.New()
	st.SetRole(state.RoleLeader)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fwBuf, fwLogs, stopTailer := startFirmwareTailer(ctx, cfg, logger)
	defer stopTailer()

	reg := openRegistry(logger)
	mdnsPub := startMDNS(ctx, cfg, reg, logger)
	defer mdnsPub.Close()
	if err := broker.Serve(ctx, ln, cfg, st, logger, fwLogs, reg); err != nil {
		logger.Printf("broker: %v", err)
		return 1
	}
	_, _ = logs, fwBuf // retained for symmetry / future diagnostics
	return 0
}

// startMDNS launches the broker advertisement. Returns a non-nil
// *mdns.Publisher even on failure so the caller can defer Close
// unconditionally. Loopback binds and registry-less setups both yield
// the no-op publisher.
func startMDNS(ctx context.Context, cfg *config.Config, reg *registry.Registry, logger *log.Logger) *mdns.Publisher {
	if reg == nil {
		return &mdns.Publisher{}
	}
	p, err := mdns.Start(ctx, cfg.Server.Bind, cfg.Server.Port, reg, logger)
	if err != nil {
		logger.Printf("mdns: %v (broker discovery disabled)", err)
		return &mdns.Publisher{}
	}
	return p
}

// startFirmwareTailer creates the firmware logbuf and (if configured)
// launches the USB-CDC tailer in a background goroutine. The returned
// FirmwareLogSource is what the broker mux serves on /firmware-logs.
// stopTailer is a no-op when the tailer is disabled; otherwise it cancels
// the goroutine's context.
func startFirmwareTailer(ctx context.Context, cfg *config.Config, logger *log.Logger) (*logbuf.Buffer, broker.FirmwareLogSource, func()) {
	size := cfg.Serial.Lines
	if size <= 0 {
		size = 2000
	}
	buf := logbuf.New(size)
	if cfg.Serial.Device == "" {
		return buf, broker.NewFirmwareLogs(buf, func() bool { return false }), func() {}
	}
	tailer := &serial.Tailer{
		Device: cfg.Serial.Device,
		Writer: buf,
		Logger: logger,
	}
	tailCtx, cancel := context.WithCancel(ctx)
	go tailer.Run(tailCtx)
	return buf, broker.NewFirmwareLogs(buf, tailer.Connected), cancel
}

// runMCP launches the broker (under leader-election) and the MCP stdio
// server in parallel. Either returning is treated as a normal shutdown
// signal for the whole process — Claude Code expects an MCP server to
// exit cleanly when its stdio peer closes.
func runMCP(cfg *config.Config, logger *log.Logger, logs *logbuf.Buffer) int {
	st := state.New()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		mcpSrv := mcp.NewServer(mcp.Deps{
			Cfg:      cfg,
			State:    st,
			Logs:     logs,
			Registry: openRegistry(logger),
			Version:  Version,
		})
		if err := mcpserver.ServeStdio(mcpSrv); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("mcp stdio: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		// The serial tailer must run only inside the leader's lifecycle so
		// the device port has exactly one reader. We start it here, scoped
		// to the listener's context, so it dies cleanly when this peer
		// loses leadership (or shuts down).
		reg := openRegistry(logger)
		err := leader.Run(ctx, addrOf(cfg), st, logger, func(c context.Context, ln net.Listener) error {
			_, fwLogs, stopTailer := startFirmwareTailer(c, cfg, logger)
			defer stopTailer()
			// mDNS publication is scoped to the leader: only the
			// process that actually owns the bound port should be
			// answering "I'm the broker" on the LAN.
			mdnsPub := startMDNS(c, cfg, reg, logger)
			defer mdnsPub.Close()
			return broker.Serve(c, ln, cfg, st, logger, fwLogs, reg)
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("leader: %v", err)
		}
	}()

	wg.Wait()
	return 0
}

// runStatus performs a signed GET against the local broker and reports
// what it sees. Three outcomes:
//   - 200            → another process is the leader (we'd be follower)
//   - connection err → no broker is running on the port
//   - other          → broker running but rejecting us (e.g. wrong PSK)
//
// Output is a single-line JSON to stdout for easy scripting.
func runStatus(cfg *config.Config) int {
	addr := addrOf(cfg)
	host := cfg.Server.Bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Server.Port)) + "/credentials"

	nonce := "0123456789abcdef0123456789abcdef"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/credentials", ts, nonce, "", "")

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Cwm-Timestamp", ts)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)

	out := map[string]any{"addr": addr, "probe_url": url}
	switch {
	case err != nil:
		out["broker"] = "down"
		out["error"] = err.Error()
	case resp.StatusCode == http.StatusOK:
		out["broker"] = "leader_elsewhere"
		out["http_status"] = resp.StatusCode
		resp.Body.Close()
	default:
		out["broker"] = "up_but_rejecting"
		out["http_status"] = resp.StatusCode
		resp.Body.Close()
	}

	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	return 0
}

// runLogs follows the broker's /firmware-logs endpoint. It prints `tail`
// backlog lines, then polls every 500ms and prints whatever is new. We
// rely on the broker's monotonic `total_available` counter to detect new
// lines without re-printing the buffer: keep the high-water mark, ask for
// `delta` lines, print the last `delta` of the response. If the ring
// evicted faster than we polled, we surface a "[N lines lost]" notice so
// the gap is obvious.
//
// Exit codes:
//
//	0 — Ctrl-C
//	1 — broker unreachable (after a couple of retries on first hit)
//	2 — auth / config error (PSK mismatch, etc.)
func runLogs(cfg *config.Config, tail int) int {
	if tail < 0 {
		tail = 0
	}
	if tail > 2000 {
		tail = 2000
	}

	host := cfg.Server.Bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	base := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Server.Port)) + "/firmware-logs"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// First fetch: ask for the backlog so the user sees something
	// immediately, even if the device hasn't said anything since they
	// last looked.
	resp, lostInitial, err := fetchLogs(ctx, cfg, base, tail)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cwm-mcp logs: %v\n", err)
		return 1
	}
	_ = lostInitial // backlog fetch — nothing to "lose" yet.
	if !resp.Connected && cfg.Serial.Device == "" {
		fmt.Fprintln(os.Stderr, "cwm-mcp logs: no [serial] device configured in cwm.toml; the broker has nothing to stream.")
		return 2
	}
	for _, l := range resp.Lines {
		fmt.Println(l)
	}
	highWater := resp.Total

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	connected := resp.Connected
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
		}
		// Cap requested limit so a momentary giant burst doesn't pull a
		// 2000-line block: if delta>1000 we already missed live and just
		// catch up with the recent tail.
		want := 1000
		next, lost, err := fetchLogs(ctx, cfg, base, want)
		if err != nil {
			// Transient: the leader may be re-electing. Note it once
			// and keep polling.
			fmt.Fprintf(os.Stderr, "cwm-mcp logs: %v (retrying)\n", err)
			continue
		}
		if next.Connected != connected {
			if next.Connected {
				fmt.Fprintln(os.Stderr, "[serial: reconnected]")
			} else {
				fmt.Fprintln(os.Stderr, "[serial: device disconnected]")
			}
			connected = next.Connected
		}
		if next.Total <= highWater {
			continue
		}
		delta := next.Total - highWater
		if delta > len(next.Lines) {
			fmt.Fprintf(os.Stderr, "[%d lines lost — ring evicted faster than polling]\n", delta-len(next.Lines))
			delta = len(next.Lines)
		}
		for _, l := range next.Lines[len(next.Lines)-delta:] {
			fmt.Println(l)
		}
		highWater = next.Total
		_ = lost
	}
}

type firmwareLogsBody struct {
	Connected bool     `json:"connected"`
	Total     int      `json:"total_available"`
	Lines     []string `json:"lines"`
}

// fetchLogs issues one signed GET to /firmware-logs?limit=…. The second
// return value is reserved for future "lost lines" plumbing exposed by
// the broker (currently unused).
func fetchLogs(ctx context.Context, cfg *config.Config, base string, limit int) (firmwareLogsBody, int, error) {
	if limit < 1 {
		limit = 1
	}
	url := base + "?limit=" + strconv.Itoa(limit)
	nonce := freshHexNonce()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/firmware-logs", ts, nonce, "", "")

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("X-Cwm-Timestamp", ts)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return firmwareLogsBody{}, 0, fmt.Errorf("broker unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return firmwareLogsBody{}, 0, fmt.Errorf("broker http %d: %s", resp.StatusCode, string(body))
	}
	var out firmwareLogsBody
	if err := json.Unmarshal(body, &out); err != nil {
		return firmwareLogsBody{}, 0, fmt.Errorf("decode body: %w", err)
	}
	return out, 0, nil
}

// freshHexNonce mirrors the MCP-side helper: 32 hex chars from crypto/rand
// so the broker's isHex32 check accepts it.
func freshHexNonce() string {
	var b [16]byte
	_, _ = cryptorand.Read(b[:])
	return hex.EncodeToString(b[:])
}
