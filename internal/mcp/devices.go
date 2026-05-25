package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/registry"
)

// deviceSummary is the trimmed view exposed by wall_monitor_list_devices.
// Anything secret (PSK bytes/hex) stays out — callers see whether a
// rotation is queued without learning the keys themselves.
type deviceSummary struct {
	DeviceID         string    `json:"device_id"`
	ActiveVersion    uint32    `json:"active_version"`
	ActiveBrokerURL  string    `json:"active_broker_url,omitempty"`
	ActiveCity       string    `json:"active_city,omitempty"`
	ActiveProviders  []string  `json:"active_providers,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	HasPending       bool      `json:"has_pending"`
	PendingVersion   uint32    `json:"pending_version,omitempty"`
	PendingChanges   []string  `json:"pending_changes,omitempty"`
	PendingCreatedAt time.Time `json:"pending_created_at,omitempty"`
}

// providerNames flattens a ProviderSet into the slice of enabled names so
// the JSON stays compact and human-readable.
func providerNames(p *registry.ProviderSet) []string {
	if p == nil {
		return nil
	}
	var out []string
	if p.Claude {
		out = append(out, "claude")
	}
	if p.Codex {
		out = append(out, "codex")
	}
	if p.Gemini {
		out = append(out, "gemini")
	}
	return out
}

// pendingChanges enumerates which fields the pending payload would alter
// relative to active. Useful so the operator sees "rotating PSK + city"
// instead of having to diff two opaque blobs in their head.
func pendingChanges(active, pending registry.ConfigPayload) []string {
	var diffs []string
	if pending.BrokerURL != "" && pending.BrokerURL != active.BrokerURL {
		diffs = append(diffs, "broker_url")
	}
	if pending.PSKHex != "" && pending.PSKHex != active.PSKHex {
		diffs = append(diffs, "psk_hex (key rotation)")
	}
	if pending.City != "" && pending.City != active.City {
		diffs = append(diffs, "city")
	}
	if pending.BrDay != nil && (active.BrDay == nil || *pending.BrDay != *active.BrDay) {
		diffs = append(diffs, "br_day")
	}
	if pending.BrNight != nil && (active.BrNight == nil || *pending.BrNight != *active.BrNight) {
		diffs = append(diffs, "br_night")
	}
	if pending.Vol != nil && (active.Vol == nil || *pending.Vol != *active.Vol) {
		diffs = append(diffs, "vol")
	}
	if pending.Providers != nil &&
		(active.Providers == nil || *pending.Providers != *active.Providers) {
		diffs = append(diffs, "providers")
	}
	if pending.AutorotateEnabled != nil {
		if active.AutorotateEnabled == nil || *active.AutorotateEnabled != *pending.AutorotateEnabled {
			diffs = append(diffs, "autorotate_enabled")
		}
	}
	if pending.AutorotateIntervalS != nil {
		if active.AutorotateIntervalS == nil || *active.AutorotateIntervalS != *pending.AutorotateIntervalS {
			diffs = append(diffs, "autorotate_interval_s")
		}
	}
	if pending.ThemeMode != "" && pending.ThemeMode != active.ThemeMode {
		diffs = append(diffs, "theme_mode")
	}
	if pending.GeminiModels != nil && !stringSliceEqual(active.GeminiModels, pending.GeminiModels) {
		diffs = append(diffs, "gemini_models")
	}
	return diffs
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func summarise(dev *registry.Device) deviceSummary {
	s := deviceSummary{
		DeviceID:        dev.DeviceID,
		ActiveVersion:   dev.Active.Version,
		ActiveBrokerURL: dev.Active.BrokerURL,
		ActiveCity:      dev.Active.City,
		ActiveProviders: providerNames(dev.Active.Providers),
		LastSeen:        dev.Active.LastSeen,
	}
	if dev.Pending != nil {
		s.HasPending = true
		s.PendingVersion = dev.Pending.Version
		s.PendingChanges = pendingChanges(dev.Active.ConfigPayload, dev.Pending.ConfigPayload)
		s.PendingCreatedAt = dev.Pending.CreatedAt
	}
	return s
}

func registryUnavailable() *mcp.CallToolResult {
	return mcp.NewToolResultErrorFromErr(
		"registry disabled",
		errors.New("device registry is not configured on this cwm-mcp install; configure ~/.config/claude-wall-monitor/devices/ and retry"),
	)
}

func handleListDevices(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		devs, err := d.Registry.List()
		if err != nil {
			return mcp.NewToolResultErrorFromErr("list", err), nil
		}
		out := make([]deviceSummary, 0, len(devs))
		for _, dev := range devs {
			out = append(out, summarise(dev))
		}
		return mcp.NewToolResultJSON(struct {
			Count   int             `json:"count"`
			Devices []deviceSummary `json:"devices"`
		}{Count: len(out), Devices: out})
	}
}

func handleRegisterDevice(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
		pskHex := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", "")))

		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		if brokerURL == "" {
			return mcp.NewToolResultError("broker_url required"), nil
		}
		if len(pskHex) != 64 {
			return mcp.NewToolResultError("psk_hex must be exactly 64 hex chars"), nil
		}
		if _, err := hex.DecodeString(pskHex); err != nil {
			return mcp.NewToolResultError("psk_hex is not valid hex"), nil
		}

		payload := registry.ConfigPayload{
			BrokerURL: brokerURL,
			PSKHex:    pskHex,
		}
		payload.City = strings.TrimSpace(req.GetString("city", ""))
		if v := req.GetFloat("br_day", 0); v > 0 {
			u8 := clamp8(uint8(v), 10, 100)
			payload.BrDay = &u8
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			u8 := clamp8(uint8(v), 5, 100)
			payload.BrNight = &u8
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			u8 := clamp8(uint8(v), 0, 100)
			payload.Vol = &u8
		}

		dev, err := d.Registry.Register(deviceID, payload)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("register", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK     bool          `json:"ok"`
			Device deviceSummary `json:"device"`
		}{OK: true, Device: summarise(dev)})
	}
}

func handleSetDevicePending(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}

		var update registry.ConfigPayload
		if v := strings.TrimSpace(req.GetString("broker_url", "")); v != "" {
			update.BrokerURL = v
		}
		if v := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", ""))); v != "" {
			if len(v) != 64 {
				return mcp.NewToolResultError("psk_hex must be exactly 64 hex chars"), nil
			}
			if _, err := hex.DecodeString(v); err != nil {
				return mcp.NewToolResultError("psk_hex is not valid hex"), nil
			}
			update.PSKHex = v
		}
		if v := strings.TrimSpace(req.GetString("city", "")); v != "" {
			update.City = v
		}
		if v := req.GetFloat("br_day", 0); v > 0 {
			u8 := clamp8(uint8(v), 10, 100)
			update.BrDay = &u8
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			u8 := clamp8(uint8(v), 5, 100)
			update.BrNight = &u8
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			u8 := clamp8(uint8(v), 0, 100)
			update.Vol = &u8
		}

		// Providers: only build the struct if any of the three flags
		// was supplied. We need *all three* in NVS to be deterministic,
		// so we read existing values from the device's current view
		// (active or pending) and override only what changed.
		anyProv := req.GetArguments()
		_, hasClaude := anyProv["provider_claude"]
		_, hasCodex := anyProv["provider_codex"]
		_, hasGemini := anyProv["provider_gemini"]
		if hasClaude || hasCodex || hasGemini {
			cur, err := d.Registry.Load(deviceID)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("load", err), nil
			}
			base := registry.ProviderSet{Claude: true} // sensible default for legacy
			if cur.Pending != nil && cur.Pending.Providers != nil {
				base = *cur.Pending.Providers
			} else if cur.Active.Providers != nil {
				base = *cur.Active.Providers
			}
			if hasClaude {
				base.Claude = req.GetBool("provider_claude", base.Claude)
			}
			if hasCodex {
				base.Codex = req.GetBool("provider_codex", base.Codex)
			}
			if hasGemini {
				base.Gemini = req.GetBool("provider_gemini", base.Gemini)
			}
			update.Providers = &base
		}

		if _, ok := anyProv["autorotate_enabled"]; ok {
			v := req.GetBool("autorotate_enabled", false)
			update.AutorotateEnabled = &v
		}
		if _, ok := anyProv["autorotate_interval_s"]; ok {
			v := uint16(req.GetFloat("autorotate_interval_s", 30))
			if v < 10 {
				v = 10
			}
			if v > 300 {
				v = 300
			}
			update.AutorotateIntervalS = &v
		}

		if v := strings.TrimSpace(req.GetString("theme_mode", "")); v != "" {
			tm := strings.ToLower(v)
			if tm != "day" && tm != "night" && tm != "auto" {
				return mcp.NewToolResultError("theme_mode must be one of: day, night, auto"), nil
			}
			update.ThemeMode = tm
		}

		// gemini_models: comma-separated list. Empty string clears the
		// override (signalled by an empty-but-non-nil slice; mergePayload
		// then replaces the stored list).
		if raw, ok := req.GetArguments()["gemini_models"]; ok {
			models := parseGeminiModels(fmt.Sprint(raw))
			if len(models) > 3 {
				return mcp.NewToolResultError("gemini_models must list at most 3 entries"), nil
			}
			if models == nil {
				models = []string{}
			}
			update.GeminiModels = models
		}

		dev, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call wall_monitor_register_device first", deviceID)), nil
			}
			return mcp.NewToolResultErrorFromErr("set_pending", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK     bool          `json:"ok"`
			Device deviceSummary `json:"device"`
		}{OK: true, Device: summarise(dev)})
	}
}

// parseGeminiModels splits a comma-separated list of model IDs and
// trims whitespace. Returns an empty slice (not nil) when the input is
// empty after trimming, so callers can distinguish "clear the override"
// (empty slice) from "field not provided" (nil).
func parseGeminiModels(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func clamp8(v, lo, hi uint8) uint8 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
