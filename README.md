# cwm-mcp

Local broker that serves Claude OAuth credentials to the
[Claude Wall Monitor](https://github.com/fractal-manifold/claude-wall-monitor)
ESP32 device, packaged as an MCP server so it gets launched automatically
with your Claude Code sessions.

It is the spiritual successor to `service-go/` inside the device repo: same
HMAC-authenticated `GET /credentials` endpoint, same OAuth-token-from-disk
behaviour, same wire protocol — but with three additions:

- **Lives with your Claude Code session.** Registered as an MCP server in
  `.mcp.json` (or `~/.claude.json`), Claude Code spawns it on session start
  and reaps it on session end. No systemd unit required.
- **Multi-session safe.** Several Claude Code sessions can run at once; the
  first one wins the TCP port, the rest sit silently as followers and take
  over within ~5 s if the leader exits.
- **Coexists with an existing daemon.** If you already have `service-go`
  running as a systemd user unit, `cwm-mcp` notices the busy port and
  stays in follower mode permanently — your existing setup keeps serving
  the device, no migration required.

## Install

```sh
go install github.com/fractal-manifold/cwm-mcp/cmd/cwm-mcp@latest
```

Or download a prebuilt binary from the
[releases page](https://github.com/fractal-manifold/cwm-mcp/releases)
once they're cut. Confirm with:

```sh
cwm-mcp --version
```

## Configure

Create `~/.config/claude-wall-monitor/cwm.toml`:

```toml
[server]
# 0.0.0.0 to accept connections from the ESP32 over your LAN. Use
# 127.0.0.1 only if the device polls a reverse-proxy on this host.
bind = "0.0.0.0"
port = 8765

[auth]
# The passphrase you typed into the device's captive portal during
# provisioning. Both sides SHA-256 this string to derive a 32-byte HMAC
# key. Must be at least 8 characters.
psk_passphrase = "change-me-please"

# Alternative: a raw 32-byte key as 64 hex chars (e.g. from
# `openssl rand -hex 32`). Passphrase takes precedence if both are set.
# psk_hex = ""

[credentials]
# Where the Claude CLI writes its OAuth token file. The default is
# correct on Linux and macOS.
oauth_path = "~/.claude/.credentials.json"

[security]
max_timestamp_skew_seconds = 60
nonce_cache_ttl_seconds = 300

[logging]
level = "INFO"
```

**Legacy compatibility**: if `cwm.toml` is missing, `cwm-mcp` falls back to
`~/.config/claude-wall-monitor/service.toml` (same schema), so existing
`service-go` users don't need to move files.

## Register in Claude Code

Pick one:

**Per-user** — every Claude Code session of yours launches it:

```sh
claude mcp add cwm-mcp -- cwm-mcp
```

Or, by hand, in `~/.claude.json`:

```json
{
  "mcpServers": {
    "cwm-mcp": {
      "command": "cwm-mcp"
    }
  }
}
```

**Per-project** — only inside this repo:

```json
// .mcp.json at the project root
{
  "mcpServers": {
    "cwm-mcp": {
      "command": "cwm-mcp"
    }
  }
}
```

Verify with `claude mcp list` and `/mcp` inside Claude Code.

## Coexistence with an existing broker

If `service-go` (or any other broker) is already serving on port 8765,
`cwm-mcp` will detect that on every retry and stay as a quiet follower:

```text
cwm-mcp leader: 0.0.0.0:8765 busy, running as follower (probing every 5s)
```

That is fine — your device keeps talking to the old daemon. When you're
ready to migrate:

```sh
systemctl --user stop claude-wall-monitor-service
systemctl --user disable claude-wall-monitor-service
```

Within ~5 s, the next session's `cwm-mcp` will promote itself to leader and
take over with zero device-side configuration changes.

## Standalone mode (no Claude Code)

If you want the broker up 24/7 even when no Claude Code session is open:

```sh
cwm-mcp --daemon
```

Drop something like this in `~/.config/systemd/user/cwm-mcp.service`:

```ini
[Unit]
Description=Claude Wall Monitor credential broker
After=network-online.target

[Service]
ExecStart=%h/.local/bin/cwm-mcp --daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Then `systemctl --user enable --now cwm-mcp`. Your Claude Code sessions
will still spawn `cwm-mcp` in stdio mode and will simply observe the
daemon's port (follower mode, no-op).

## Modes & flags

| Flag         | Behaviour                                                              |
|--------------|------------------------------------------------------------------------|
| *(none)*     | MCP-stdio + leader-elected broker. The mode Claude Code uses.          |
| `--daemon`   | Standalone broker. Bind unconditionally, no probe loop.                |
| `--once`     | Read & validate the credentials file, print a one-line OK/expired summary, exit. |
| `--status`   | Probe the local broker and print a status JSON. Useful for scripting.  |
| `--config`   | Override the config file location.                                     |
| `--version`  | Print the build version and exit.                                      |

## Smoke tests

After `cwm-mcp --daemon` is running:

```sh
cwm-mcp --once
# → creds OK (expires_at=2026-05-17T15:34:21.123Z)

cwm-mcp --status
# → {"addr":"0.0.0.0:8765","broker":"leader_elsewhere","http_status":200}
```

And a manual signed request mirroring what the device sends:

```sh
PSK_HEX="$(printf '%s' "your-passphrase-here" | sha256sum | cut -d' ' -f1)"
TS=$(date +%s)
NONCE=$(openssl rand -hex 16)
PAYLOAD="GET
/credentials
${TS}
${NONCE}"
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${PSK_HEX}" -hex | awk '{print $2}')

curl -sS http://127.0.0.1:8765/credentials \
  -H "X-Cwm-Timestamp: ${TS}" \
  -H "X-Cwm-Nonce: ${NONCE}" \
  -H "X-Cwm-Signature: ${SIG}"
```

## Troubleshooting

- **`follower (port busy)` in the logs**: another broker is bound. Use
  `lsof -i :8765` to find it. If it's the old `service-go` daemon you
  meant to keep, you're done — `cwm-mcp` will just be a quiet follower.
- **`credentials file missing` returned to the device**: you're not logged
  in with the Claude CLI on this host. `~/.claude/.credentials.json` must
  exist and contain a `claudeAiOauth` object.
- **Device shows `Token: PSK rejected (401/403)`**: the `psk_passphrase`
  in `cwm.toml` doesn't match what was typed in the device's captive
  portal. Either fix the TOML or re-provision the device.
- **Device shows `Token: laptop unreachable`**: the broker isn't running,
  the host firewall is blocking 8765, or the IP/hostname in the device's
  `svc_url` doesn't resolve to this machine.

## Security model

Threat model is "trusted LAN". The broker authenticates every request with
HMAC-SHA256(PSK, …) and rejects replays via a timestamp + nonce window. It
does not implement TLS. **Do not expose port 8765 to the public internet.**

## Status & roadmap

- [x] HTTP `/credentials` endpoint with HMAC auth (parity with `service-go`)
- [x] Leader election via TCP bind, 5 s probe interval
- [x] `--daemon`, `--once`, `--status`, `--config`, `--version` CLI surface
- [x] Configuration fallback from `cwm.toml` to legacy `service.toml`
- [ ] MCP stdio JSON-RPC surface (`wall_monitor_status`,
      `wall_monitor_refresh_credentials`) — placeholder, lands once we
      pick a Go MCP SDK we like.
- [ ] GitHub Actions release pipeline (GoReleaser, linux+macOS, amd64+arm64)

## License

Apache-2.0. See [LICENSE](LICENSE).
