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

## Register with MCP-aware CLIs

`cwm-mcp` speaks stdio MCP, so any MCP-aware CLI can launch it as a
subprocess. The leader-election in the binary means it is safe to register
it in several CLIs at once — the first instance to bind `:8765` becomes the
broker, the rest stay as silent followers.

In every command below, pass an **absolute path** (`$(command -v cwm-mcp)`)
rather than relying on the CLI inheriting your shell `PATH` — Codex and
Gemini both spawn the server from a non-login environment where
`~/.local/bin` may not be on `PATH`.

### Claude Code

Per-user (every session of yours launches it):

```sh
claude mcp add cwm-mcp -- "$(command -v cwm-mcp)"
```

Or, by hand, in `~/.claude.json`:

```json
{
  "mcpServers": {
    "cwm-mcp": {
      "command": "/absolute/path/to/cwm-mcp"
    }
  }
}
```

Per-project (only inside one repo):

```json
// .mcp.json at the project root
{
  "mcpServers": {
    "cwm-mcp": {
      "command": "/absolute/path/to/cwm-mcp"
    }
  }
}
```

Verify with `claude mcp list` and `/mcp` inside Claude Code.

### Codex CLI

```sh
codex mcp add cwm-mcp -- "$(command -v cwm-mcp)"
```

Writes `[mcp_servers.cwm-mcp]` to `~/.codex/config.toml`. Verify with
`codex mcp list` and `codex mcp get cwm-mcp` — transport should read
`stdio` and the command path should be absolute.

In interactive `codex`, the first tool invocation prompts you to approve
the MCP call. In non-interactive `codex exec`, that prompt has no UI to
answer it and the call is auto-cancelled with `user cancelled MCP tool
call`. To use the tools from `codex exec` (CI, scripts), disable the
review feature for that invocation:

```sh
codex exec -c features.mcp_tool_call_review=false "..."
```

Or persist it globally in `~/.codex/config.toml`:

```toml
[features]
mcp_tool_call_review = false
```

### Gemini CLI

```sh
gemini mcp add -s user --trust cwm-mcp "$(command -v cwm-mcp)"
```

- `-s user` writes to `~/.gemini/settings.json` (global). Without it the
  default scope is `project` and Gemini would write to
  `<cwd>/.gemini/settings.json`, which is rarely what you want for a
  host-level utility.
- `--trust` suppresses the per-call confirmation prompt — the server is
  local-only and behind HMAC auth, the prompt is just friction.

Verify with `gemini mcp list`; the server should report `✓ Connected`.

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

## MCP tools

When launched without `--daemon`, `cwm-mcp` exposes the following tools
to Claude Code over stdio JSON-RPC. The model invokes them when you ask
diagnostic questions about your wall monitor.

| Tool                          | What it does |
|-------------------------------|--------------|
| `wall_monitor_status`         | Snapshot: leader/follower role, since when, last ESP32 request (time, remote, HTTP status), request count. |
| `wall_monitor_health`         | End-to-end check: credentials file readable + unexpired, broker reachable via a self-signed self-ping, observed traffic in the last window. Returns PASS/FAIL per component. |
| `wall_monitor_recent_logs`    | Tail of the in-memory broker log (default 50 lines, max 500). Shows auth rejections, peer IPs, role transitions. |
| `wall_monitor_provision_hint` | The laptop's LAN IPv4 addresses + the configured port, formatted as `http://…` URLs to paste into the device's captive portal. |
| `wall_monitor_list_devices`   | Every device in the local registry, with active config version, whether a pending update is queued, last seen, providers enabled. |
| `wall_monitor_register_device`| Register an existing device — needed once for any device originally provisioned through the captive portal. Args: `device_id` (8 hex), `broker_url`, `psk_hex` (64 hex), optional `city`/`br_day`/`br_night`/`vol`. |
| `wall_monitor_set_device_pending` | Stage a pending config change. Args (all optional except `device_id`): `broker_url`, `psk_hex`, `city`, `br_day`, `br_night`, `vol`, `provider_claude`, `provider_codex`, `provider_gemini`, `autorotate_enabled`, `autorotate_interval_s`. The device applies it within ~60 s under candidate/rollback. |
| `wall_monitor_discover_devices` | Scan the local network via mDNS (`_cwm._tcp.local.`) for devices in BOOT_NEEDS_CONFIG. Default 4 s scan, max 15 s. Returns `device_id`, `fw`, `ipv4`, `provision_url`. The pairing code is **not** returned — it lives only on the device's screen. |
| `wall_monitor_provision`      | POST `/provision` on a discovered device with the 6-digit pairing code the user reads off the screen plus the broker URL, PSK hex, and any optional config. On success the device persists to NVS and reboots; if `broker_url + psk_hex` are supplied this tool also registers/queues the device in the local registry. |

## Per-device control plane

Per-device state lives under `~/.config/claude-wall-monitor/devices/`,
one `<device_id>.toml` per device. Reads and writes are flock-serialised
so leader and follower processes can both operate safely.

Schema (truncated example):

```toml
schema_version = 1
device_id = "ab12cd34"

[active]
version = 7
broker_url = "http://192.168.1.10:8765"
psk_hex = "0011…"        # 64 hex
city = "Madrid"
br_day = 80
br_night = 20
vol = 60
last_seen = 2026-05-22T09:14:00Z

[active.providers]
claude = true
codex = false
gemini = false

# Present only while a change is in flight:
[pending]
version = 8
psk_hex = "ab34…"        # rotation in progress
city = "Barcelona"
created_at = 2026-05-22T09:13:00Z
```

The broker serves `GET /device/<id>/sync`. The pending payload is
**AES-CTR encrypted with the device's currently-active PSK**, so a
passive attacker who never broke the active key cannot learn the
rotated key from a captured response. The wire shape:

```json
{
  "active_version": 7,
  "pending": {
    "version": 8,
    "nonce_b64": "…(16 random bytes, base64)…",
    "payload_b64": "…(AES-CTR ciphertext of the pending TOML, base64)…"
  }
}
```

Promotion (the broker drops the old PSK / commits the new active) only
fires when the device's next request signs with the **pending** PSK
AND reports `X-Cwm-Config-Version == pending.version`. Both conditions
together are the device's "I have applied it" confirmation; either
alone isn't enough.

## Initial provisioning via mDNS (BOOT_NEEDS_CONFIG)

Devices that finished WiFi association but don't yet have a broker URL
+ PSK sit in **BOOT_NEEDS_CONFIG**: they advertise themselves on
`_cwm._tcp.local.` (TXT record `device_id`, `state=needs_config`, `fw`)
and serve HTTP on port 80:

- `GET /info` — public probe, returns `{device_id, fw_version, state,
  capabilities}`. Safe to call from anywhere on the LAN. **Never**
  returns the pairing code.
- `POST /provision` — accepts the initial config. Body shape:

  ```json
  {
    "pairing_code": "123456",
    "broker_url":   "http://192.168.1.10:8765",
    "psk_hex":      "0011…",
    "city":         "Madrid",
    "br_day":       80,
    "br_night":     20,
    "vol":          60,
    "providers":    { "claude": true, "codex": false, "gemini": false }
  }
  ```

  All fields except `pairing_code` are optional; only the ones supplied
  get persisted. The 6-digit `pairing_code` is generated fresh on every
  boot, shown only on the device's screen, and compared in constant
  time. A wrong code returns `401`; a successful provision returns
  `{"ok":true,"device_id":"…","next":"rebooting"}` and the device
  reboots into BOOT_READY after a short delay.

The `/wall-monitor:configure` Claude Code skill drives this end-to-end
via `wall_monitor_discover_devices` + `wall_monitor_provision`.

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
- [x] MCP stdio JSON-RPC surface via
      [`mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go), with
      four tools (see below)

## License

Apache-2.0. See [LICENSE](LICENSE).
