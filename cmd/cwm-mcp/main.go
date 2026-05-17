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
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/broker"
	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/creds"
	"github.com/fractal-manifold/cwm-mcp/internal/leader"
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

	logger := log.New(os.Stderr, "cwm-mcp ", log.LstdFlags|log.Lmicroseconds)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	switch {
	case *onceMode:
		os.Exit(runOnce(cfg))
	case *statusMode:
		os.Exit(runStatus(cfg))
	case *daemonMode:
		os.Exit(runDaemon(cfg, logger))
	default:
		os.Exit(runMCP(cfg, logger))
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

func runDaemon(cfg *config.Config, logger *log.Logger) int {
	addr := addrOf(cfg)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Printf("listen %s: %v", addr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := broker.Serve(ctx, ln, cfg, logger); err != nil {
		logger.Printf("broker: %v", err)
		return 1
	}
	return 0
}

func runMCP(cfg *config.Config, logger *log.Logger) int {
	addr := addrOf(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// TODO(mcp-layer): start the MCP stdio JSON-RPC server here in parallel
	// once we pick an SDK. For now the binary already covers its main job
	// (broker + leader-election) and Claude Code is happy to spawn it via
	// stdio even without tools exposed.

	err := leader.Run(ctx, addr, logger, func(c context.Context, ln net.Listener) error {
		return broker.Serve(c, ln, cfg, logger)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("leader: %v", err)
		return 1
	}
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
	url := "http://" + addr + "/credentials"

	nonce := "0123456789abcdef0123456789abcdef"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(cfg.PSK(), "GET", "/credentials", ts, nonce)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Cwm-Timestamp", ts)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)

	out := map[string]any{"addr": addr}
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
