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
package main

import (
	"context"
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
	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	configPath := flag.String("config", "", "Path to cwm.toml (default: ~/.config/claude-wall-monitor/cwm.toml)")
	daemonMode := flag.Bool("daemon", false, "Standalone broker — bind unconditionally, no leader-election")
	onceMode := flag.Bool("once", false, "Validate credentials file and exit")
	statusMode := flag.Bool("status", false, "Probe local broker and print status JSON")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
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
	case *daemonMode:
		os.Exit(runDaemon(cfg, logger, logs))
	default:
		os.Exit(runMCP(cfg, logger, logs))
	}
}

func addrOf(cfg *config.Config) string {
	return net.JoinHostPort(cfg.Server.Bind, strconv.Itoa(cfg.Server.Port))
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
	if err := broker.Serve(ctx, ln, cfg, st, logger); err != nil {
		logger.Printf("broker: %v", err)
		return 1
	}
	_ = logs // referenced for symmetry; not consumed in daemon mode
	return 0
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
			Cfg:     cfg,
			State:   st,
			Logs:    logs,
			Version: Version,
		})
		if err := mcpserver.ServeStdio(mcpSrv); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("mcp stdio: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		err := leader.Run(ctx, addrOf(cfg), st, logger, func(c context.Context, ln net.Listener) error {
			return broker.Serve(c, ln, cfg, st, logger)
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
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/credentials", ts, nonce)

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
