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
)

type Config struct {
	Server      Server      `toml:"server"`
	Auth        Auth        `toml:"auth"`
	Credentials Credentials `toml:"credentials"`
	Security    Security    `toml:"security"`
	Logging     Logging     `toml:"logging"`
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

type Security struct {
	MaxTimestampSkewSeconds int `toml:"max_timestamp_skew_seconds"`
	NonceCacheTTLSeconds    int `toml:"nonce_cache_ttl_seconds"`
}

type Logging struct {
	Level string `toml:"level"`
}

func (c *Config) PSK() []byte { return c.pskBytes }

func (c *Config) OAuthPath() string {
	return expandUser(c.Credentials.OAuthPath)
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
		Security: Security{
			MaxTimestampSkewSeconds: 60,
			NonceCacheTTLSeconds:    300,
		},
		Logging: Logging{Level: "INFO"},
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

[security]
max_timestamp_skew_seconds = 60
nonce_cache_ttl_seconds = 300

[logging]
level = "INFO"
`
