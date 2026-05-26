// Package config loads cwm-mcp's TOML configuration, derives the PSK from
// either a passphrase (preferred) or a raw 64-hex key, and exposes the
// resulting bytes to the rest of the binary.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultPath is the canonical location of the config file. If it does not
// exist, Load() falls back to LegacyPath for users still on the older
// service-go installation.
const (
	DefaultPath = "~/.config/claude-wall-monitor/cwm.toml"
	LegacyPath  = "~/.config/claude-wall-monitor/service.toml"
	DevicesDir  = "~/.config/claude-wall-monitor/devices"
	// FirmwareDir holds binaries served by GET /firmware/<name>. The
	// publish_firmware MCP tool copies the .bin here and the device
	// downloads from there after a pending OTA promotion.
	FirmwareDir = "~/.config/claude-wall-monitor/firmware"
)

// DevicesPath returns the absolute path to the per-device registry
// directory. Exposed so main() can hand it to registry.New.
func DevicesPath() string { return expandUser(DevicesDir) }

// FirmwarePath returns the absolute path to the firmware artifact
// directory. Exposed so main() can hand it to broker.NewMux.
func FirmwarePath() string { return expandUser(FirmwareDir) }

type Config struct {
	Server      Server      `toml:"server"`
	Auth        Auth        `toml:"auth"`
	Credentials Credentials `toml:"credentials"`
	Codex       Codex       `toml:"codex"`
	Gemini      Gemini      `toml:"gemini"`
	Usage       Usage       `toml:"usage"`
	Security    Security    `toml:"security"`
	Logging     Logging     `toml:"logging"`
	Serial      Serial      `toml:"serial"`
	pskBytes    []byte
}

type Server struct {
	Bind string `toml:"bind"`
	Port int    `toml:"port"`
}

type Auth struct {
	Passphrase string `toml:"psk_passphrase"`
	PSKHex     string `toml:"psk_hex"`
}

type Credentials struct {
	OAuthPath string `toml:"oauth_path"`
}

type Codex struct {
	Enabled  bool   `toml:"enabled"`
	AuthPath string `toml:"auth_path"`
}

// Gemini configures the loadCodeAssist usage probe. CredsPath points at
// the Gemini CLI's oauth_creds.json; ProjectsPath at its projects.json
// (used to derive a cloudaicompanionProject — any of the user's projects
// works). Both are optional; loadCodeAssist accepts an empty project.
//
// Models is the ordered list of Gemini model IDs the broker surfaces in
// the `slots` array on /usage/gemini. Max 3 entries — the firmware only
// renders that many cards. Empty falls back to DefaultGeminiModels.
type Gemini struct {
	Enabled      bool     `toml:"enabled"`
	CredsPath    string   `toml:"creds_path"`
	ProjectsPath string   `toml:"projects_path"`
	Models       []string `toml:"models"`
}

// DefaultGeminiModels is what the broker exposes when [gemini].models is
// empty. Pro is the headline model users care most about; Flash is the
// high-volume bucket that burns the fastest.
var DefaultGeminiModels = []string{"gemini-2.5-pro", "gemini-2.5-flash"}

// MaxGeminiModels caps the number of model slots the broker emits — the
// firmware dashboard has 3 fixed card slots (large/large/small) and
// ignores anything past index 2.
const MaxGeminiModels = 3

// GeminiModels returns the configured list, clamped to MaxGeminiModels.
// An empty config returns DefaultGeminiModels.
func (c *Config) GeminiModels() []string {
	src := c.Gemini.Models
	if len(src) == 0 {
		src = DefaultGeminiModels
	}
	if len(src) > MaxGeminiModels {
		src = src[:MaxGeminiModels]
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// Usage controls the cache TTL for /usage/{provider}. A device polling
// every 60 s with default TTL hits each upstream at most once per minute.
type Usage struct {
	CacheTTLSeconds int `toml:"cache_ttl_seconds"`
}

type Security struct {
	MaxTimestampSkewSeconds int `toml:"max_timestamp_skew_seconds"`
	NonceCacheTTLSeconds    int `toml:"nonce_cache_ttl_seconds"`
}

type Logging struct {
	Level string `toml:"level"`
}

// Serial is the USB-CDC tail for the device's ESP-IDF logs. When Device is
// empty the tailer is disabled — leaving idf.py monitor free to own the
// port. When set, only the leader process opens it; followers read via
// the broker's HTTP /firmware-logs endpoint.
type Serial struct {
	Device string `toml:"device"`
	Baud   int    `toml:"baud"`
	Lines  int    `toml:"lines"`
}

func (c *Config) PSK() []byte { return c.pskBytes }

func (c *Config) OAuthPath() string {
	return expandUser(c.Credentials.OAuthPath)
}

func (c *Config) CodexAuthPath() string {
	return expandUser(c.Codex.AuthPath)
}

func (c *Config) GeminiCredsPath() string {
	return expandUser(c.Gemini.CredsPath)
}

func (c *Config) GeminiProjectsPath() string {
	return expandUser(c.Gemini.ProjectsPath)
}

func expandUser(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// Load reads the config from `path` (or the default location if empty). If
// `path` is the default and missing, it transparently tries the legacy
// service.toml so existing service-go users don't have to migrate.
func Load(path string) (*Config, error) {
	explicit := path != ""
	if path == "" {
		path = DefaultPath
	}
	resolved := expandUser(path)

	raw, err := os.ReadFile(resolved)
	if err != nil && !explicit && errors.Is(err, os.ErrNotExist) {
		legacy := expandUser(LegacyPath)
		legacyRaw, legacyErr := os.ReadFile(legacy)
		if legacyErr == nil {
			raw = legacyRaw
			resolved = legacy
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", resolved, err)
	}

	cfg := defaults()
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", resolved, err)
	}

	switch {
	case cfg.Auth.Passphrase != "":
		if len(cfg.Auth.Passphrase) < 8 {
			return nil, errors.New("auth.psk_passphrase must be at least 8 characters")
		}
		sum := sha256.Sum256([]byte(cfg.Auth.Passphrase))
		cfg.pskBytes = sum[:]
	case cfg.Auth.PSKHex != "":
		if len(cfg.Auth.PSKHex) != 64 {
			return nil, errors.New("auth.psk_hex must be exactly 64 hex characters")
		}
		psk, err := hex.DecodeString(cfg.Auth.PSKHex)
		if err != nil {
			return nil, fmt.Errorf("auth.psk_hex is not valid hex: %w", err)
		}
		cfg.pskBytes = psk
		cfg.Auth.PSKHex = strings.ToLower(cfg.Auth.PSKHex)
	default:
		return nil, errors.New("auth: either psk_passphrase or psk_hex is required")
	}
	cfg.Logging.Level = strings.ToUpper(cfg.Logging.Level)
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: Server{Bind: "127.0.0.1", Port: 8765},
		Credentials: Credentials{
			OAuthPath: "~/.claude/.credentials.json",
		},
		Codex: Codex{
			Enabled:  false,
			AuthPath: "~/.codex/auth.json",
		},
		Gemini: Gemini{
			Enabled:      false,
			CredsPath:    "~/.gemini/oauth_creds.json",
			ProjectsPath: "~/.gemini/projects.json",
			// Models left nil so GeminiModels() returns the default —
			// keeps the zero value useful for tests that don't load TOML.
		},
		Usage: Usage{
			CacheTTLSeconds: 30,
		},
		Security: Security{
			MaxTimestampSkewSeconds: 60,
			NonceCacheTTLSeconds:    300,
		},
		Logging: Logging{Level: "INFO"},
		Serial:  Serial{Device: "", Baud: 115200, Lines: 2000},
	}
}

// SampleTOML is a self-documenting template suitable for `cwm-mcp --print-config`.
const SampleTOML = `[server]
# 0.0.0.0 to accept connections from the ESP32 over the LAN.
bind = "0.0.0.0"
port = 8765

[auth]
# A passphrase (8+ chars) shared with the device. Both sides SHA-256 it to
# derive the HMAC key, so you only need to type something memorable.
psk_passphrase = "change-me-please"
# Alternative: set psk_hex (64 hex chars from 'openssl rand -hex 32').
# psk_hex = ""

[credentials]
oauth_path = "~/.claude/.credentials.json"

[codex]
# Enable if you also use the Codex CLI. auth.json contains the ChatGPT
# bearer token plus account_id required by /backend-api/wham/usage.
enabled = false
auth_path = "~/.codex/auth.json"

[gemini]
# Enable if you also use the Gemini CLI. The broker reads the OAuth creds
# the CLI writes, refreshes the access token in memory when needed (never
# writing back to avoid racing the CLI), and asks cloudcode-pa for the
# tier. Free tier returns no usage signal; paid tier returns credits.
enabled = false
creds_path = "~/.gemini/oauth_creds.json"
projects_path = "~/.gemini/projects.json"
# Models exposed as dashboard cards (max 3). Default is Pro + Flash.
# Each entry is a Gemini model ID; prefix matches are tolerated so
# "gemini-2.5-flash" also resolves "gemini-2.5-flash-002" if Google
# rotates suffixes. Per-device overrides live in the registry under
# gemini_models (pushed through /device/<id>/sync).
# models = ["gemini-2.5-pro", "gemini-2.5-flash"]

[usage]
# How long the broker caches each provider's /usage payload before
# re-fetching upstream. A device polling every 60 s with TTL 30 s hits
# each upstream once per minute at most.
cache_ttl_seconds = 30

[security]
max_timestamp_skew_seconds = 60
nonce_cache_ttl_seconds = 300

[logging]
level = "INFO"

[serial]
# USB-CDC device that streams ESP-IDF logs. Leave empty (default) to keep
# idf.py monitor as the sole owner of the port. When set, the leader
# cwm-mcp process opens it and exposes the tail via:
#   - MCP tool wall_monitor_firmware_logs
#   - HTTP GET /firmware-logs (HMAC-signed)
# device = "/dev/esp32s3"
# baud is meaningless for true USB-CDC; the kernel ignores it. Set to
# whatever you'd pass idf.py — it's just for documentation.
baud = 115200
# Ring buffer size in lines.
lines = 2000
`
