package mcp

// MCP tools for the Phase-2 discovery flow:
//
//   wall_monitor_discover_devices  — scan the LAN for `_cwm._tcp.local.`
//                                    advertisements and report devices in
//                                    BOOT_NEEDS_CONFIG.
//   wall_monitor_provision         — POST /provision against a discovered
//                                    device with the pairing code the user
//                                    just read off its screen.
//
// Both tools live on the laptop, alongside the broker, and need no signed
// HMAC: discovery is multicast and /provision is gated by a 6-digit code
// printed on the device's display (physical-presence proof). The PSK is
// generated server-side: if the caller does not pass psk_hex, we draw 32
// random bytes with crypto/rand and use that. The result is pushed over
// plain HTTP on the LAN once (within the brief pairing window) and stored
// in the registry; the device then reboots into BOOT_READY and signs
// every subsequent request with it. The user never sees the key.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/registry"
)

const (
	mdnsService = "_cwm._tcp"
	mdnsDomain  = "local."
)

// discoveredDevice is the public shape returned by the discover tool. We
// expose every TXT key we know about plus the parsed IPs so the caller
// can both display the device and point /provision straight at it.
type discoveredDevice struct {
	DeviceID   string   `json:"device_id"`
	State      string   `json:"state,omitempty"`
	FW         string   `json:"fw,omitempty"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	IPv4       []string `json:"ipv4,omitempty"`
	ProvisionURL string `json:"provision_url"`
	InfoURL      string `json:"info_url"`
}

func registerDiscoveryTools(s *server.MCPServer, d Deps) {
	s.AddTool(
		mcp.NewTool("wall_monitor_discover_devices",
			mcp.WithDescription("Scan the local network via mDNS for Claude Wall Monitor devices that have just connected to WiFi and are waiting for an initial config (`_cwm._tcp.local.`). Returns one entry per device with its device_id, firmware version, hostname, IPv4 address(es) and the URL to POST a /provision payload to. The pairing code is NOT returned — the user must read it from the device's screen. Default scan window is 4 seconds."),
			mcp.WithNumber("timeout_seconds",
				mcp.Description("Browse window in seconds (1..15). Defaults to 4."),
			),
		),
		handleDiscoverDevices(d),
	)

	s.AddTool(
		mcp.NewTool("wall_monitor_provision",
			mcp.WithDescription("Send the initial config to a device that is currently in BOOT_NEEDS_CONFIG. Requires the 6-digit pairing code the user reads off the device's screen, plus the broker URL and PSK hex you want the device to start using. On success the device persists the config to NVS and reboots into BOOT_READY. If broker_url + psk_hex are supplied, this tool also registers the device in the local cwm-mcp registry so subsequent control-plane polls (/device/<id>/sync) are recognised."),
			mcp.WithString("device_id", mcp.Required(),
				mcp.Description("8 lowercase hex chars from the device screen or wall_monitor_discover_devices output.")),
			mcp.WithString("provision_url", mcp.Required(),
				mcp.Description("The full http://HOST:80/provision URL from wall_monitor_discover_devices.")),
			mcp.WithString("pairing_code", mcp.Required(),
				mcp.Description("6-digit code shown on the device's screen.")),
			mcp.WithString("broker_url",
				mcp.Description("HTTP(S) URL of the cwm-mcp broker the device should poll. Run wall_monitor_provision_hint to learn the laptop's reachable URL on this LAN; do not assume a specific IP. If omitted, only the optional fields below are pushed.")),
			mcp.WithString("psk_hex",
				mcp.Description("Optional 64-hex PSK the device should sign requests with. If omitted (recommended), the broker generates a fresh 32-byte random PSK with crypto/rand and stores it in the registry — the user never has to think of or remember one. Supplying psk_hex is only needed when reproducing an existing PSK (e.g. migrating a device between brokers).")),
			mcp.WithString("city", mcp.Description("Optional city for ambient weather.")),
			mcp.WithNumber("br_day",   mcp.Description("Daytime brightness 10..100.")),
			mcp.WithNumber("br_night", mcp.Description("Nighttime brightness 5..100.")),
			mcp.WithNumber("vol",      mcp.Description("Alert volume 0..100.")),
			mcp.WithBoolean("provider_claude", mcp.Description("Enable Claude provider.")),
			mcp.WithBoolean("provider_codex",  mcp.Description("Enable Codex provider.")),
			mcp.WithBoolean("provider_gemini", mcp.Description("Enable Gemini provider.")),
		),
		handleProvision(d),
	)
}

// parseTXT lifts the txt key/value pairs into a map. zeroconf returns them
// as a []string of "key=value" entries.
func parseTXT(txt []string) map[string]string {
	out := make(map[string]string, len(txt))
	for _, kv := range txt {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			out[strings.ToLower(kv[:i])] = kv[i+1:]
		}
	}
	return out
}

func handleDiscoverDevices(_ Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		timeout := 4 * time.Second
		if v := req.GetFloat("timeout_seconds", 0); v > 0 {
			if v < 1 {
				v = 1
			}
			if v > 15 {
				v = 15
			}
			timeout = time.Duration(v * float64(time.Second))
		}

		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("zeroconf resolver", err), nil
		}

		entries := make(chan *zeroconf.ServiceEntry, 16)
		browseCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := resolver.Browse(browseCtx, mdnsService, mdnsDomain, entries); err != nil {
			return mcp.NewToolResultErrorFromErr("zeroconf browse", err), nil
		}

		// Collect entries until the browse context expires. zeroconf will
		// close the channel for us.
		var devices []discoveredDevice
		seen := map[string]bool{}
		for e := range entries {
			txt := parseTXT(e.Text)
			id := strings.ToLower(strings.TrimSpace(txt["device_id"]))
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true

			var ips []string
			for _, ip := range e.AddrIPv4 {
				ips = append(ips, ip.String())
			}
			// Prefer the first IPv4 for the URLs — most users want one
			// clickable address, not a hostname that may not resolve via
			// .local outside macOS.
			host := e.HostName
			if len(ips) > 0 {
				host = ips[0]
			}
			port := e.Port
			if port == 0 {
				port = 80
			}
			base := fmt.Sprintf("http://%s:%d", host, port)
			devices = append(devices, discoveredDevice{
				DeviceID:     id,
				State:        txt["state"],
				FW:           txt["fw"],
				Host:         e.HostName,
				Port:         port,
				IPv4:         ips,
				ProvisionURL: base + "/provision",
				InfoURL:      base + "/info",
			})
		}

		return mcp.NewToolResultJSON(struct {
			Count   int                `json:"count"`
			Devices []discoveredDevice `json:"devices"`
		}{Count: len(devices), Devices: devices})
	}
}

// provisionPayload is the JSON envelope POSTed to /provision. Pointer
// fields stay nil when unset so the device's persist_provision treats
// them as "no change".
type provisionPayload struct {
	PairingCode string                 `json:"pairing_code"`
	BrokerURL   string                 `json:"broker_url,omitempty"`
	PSKHex      string                 `json:"psk_hex,omitempty"`
	City        string                 `json:"city,omitempty"`
	BrDay       *uint8                 `json:"br_day,omitempty"`
	BrNight     *uint8                 `json:"br_night,omitempty"`
	Vol         *uint8                 `json:"vol,omitempty"`
	Providers   map[string]bool        `json:"providers,omitempty"`
}

func handleProvision(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		provisionURL := strings.TrimSpace(req.GetString("provision_url", ""))
		code := strings.TrimSpace(req.GetString("pairing_code", ""))

		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		if provisionURL == "" || !strings.HasSuffix(provisionURL, "/provision") {
			return mcp.NewToolResultError("provision_url must end in /provision (use wall_monitor_discover_devices to get it)"), nil
		}
		if len(code) != 6 {
			return mcp.NewToolResultError("pairing_code must be 6 digits"), nil
		}

		brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
		pskHex := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", "")))
		pskGenerated := false
		if pskHex != "" {
			if len(pskHex) != 64 {
				return mcp.NewToolResultError("psk_hex must be 64 hex chars"), nil
			}
			if _, err := hex.DecodeString(pskHex); err != nil {
				return mcp.NewToolResultError("psk_hex is not valid hex"), nil
			}
		} else if brokerURL != "" {
			// No PSK supplied for a full provision — generate one. The
			// user never has to memorise a passphrase or pick a key:
			// pairing-code physical-presence proof + a fresh 32-byte
			// random PSK is strictly stronger than the old
			// SHA-256(passphrase) derivation, and the secret stays
			// machine-only (broker registry + device NVS).
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return mcp.NewToolResultErrorFromErr("psk gen", err), nil
			}
			pskHex = hex.EncodeToString(b)
			pskGenerated = true
		}

		payload := provisionPayload{
			PairingCode: code,
			BrokerURL:   brokerURL,
			PSKHex:      pskHex,
			City:        strings.TrimSpace(req.GetString("city", "")),
		}
		if v := req.GetFloat("br_day", 0); v > 0 {
			b := clamp8(uint8(v), 10, 100)
			payload.BrDay = &b
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			b := clamp8(uint8(v), 5, 100)
			payload.BrNight = &b
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			b := clamp8(uint8(v), 0, 100)
			payload.Vol = &b
		}

		args := req.GetArguments()
		_, hasClaude := args["provider_claude"]
		_, hasCodex := args["provider_codex"]
		_, hasGemini := args["provider_gemini"]
		if hasClaude || hasCodex || hasGemini {
			p := map[string]bool{}
			if hasClaude {
				p["claude"] = req.GetBool("provider_claude", false)
			}
			if hasCodex {
				p["codex"] = req.GetBool("provider_codex", false)
			}
			if hasGemini {
				p["gemini"] = req.GetBool("provider_gemini", false)
			}
			payload.Providers = p
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("encode", err), nil
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", provisionURL, bytes.NewReader(body))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("request", err), nil
		}
		httpReq.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			},
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("POST /provision", err), nil
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return mcp.NewToolResultJSON(struct {
				OK         bool   `json:"ok"`
				HTTPStatus int    `json:"http_status"`
				Body       string `json:"body"`
			}{OK: false, HTTPStatus: resp.StatusCode, Body: string(respBody)})
		}

		// Mirror the freshly-provisioned config into the local registry
		// so /device/<id>/sync recognises the device on first poll. We
		// only do this when the caller actually sent broker_url + psk_hex;
		// a partial provision (e.g. only city) is meant for an already
		// registered device.
		var registryErr error
		var registered, reregistered bool
		if d.Registry != nil && brokerURL != "" && pskHex != "" {
			reg := registry.ConfigPayload{
				BrokerURL: brokerURL,
				PSKHex:    pskHex,
				City:      payload.City,
			}
			if payload.BrDay != nil {
				v := *payload.BrDay
				reg.BrDay = &v
			}
			if payload.BrNight != nil {
				v := *payload.BrNight
				reg.BrNight = &v
			}
			if payload.Vol != nil {
				v := *payload.Vol
				reg.Vol = &v
			}
			if payload.Providers != nil {
				reg.Providers = &registry.ProviderSet{
					Claude: payload.Providers["claude"],
					Codex:  payload.Providers["codex"],
					Gemini: payload.Providers["gemini"],
				}
			}
			_, err := d.Registry.Register(deviceID, reg)
			switch {
			case err == nil:
				registered = true
			case strings.Contains(err.Error(), "already exists"):
				// Device was re-provisioned (e.g. user wiped NVS and started
				// over). Queue a pending update so the new PSK/URL flows
				// through the rotation safety net instead of silently
				// stomping the existing record.
				if _, perr := d.Registry.SetPending(deviceID, reg); perr != nil {
					registryErr = fmt.Errorf("re-register failed: %w", perr)
				} else {
					reregistered = true
				}
			default:
				registryErr = err
			}
		}

		out := struct {
			OK           bool   `json:"ok"`
			DeviceID     string `json:"device_id"`
			Registered   bool   `json:"registered"`
			Reregistered bool   `json:"reregistered,omitempty"`
			PSKGenerated bool   `json:"psk_generated,omitempty"`
			Note         string `json:"note,omitempty"`
			DeviceResp   any    `json:"device_response,omitempty"`
		}{
			OK:           true,
			DeviceID:     deviceID,
			Registered:   registered,
			Reregistered: reregistered,
			PSKGenerated: pskGenerated,
		}
		if registryErr != nil {
			out.Note = "device provisioned but registry write failed: " + registryErr.Error()
		}
		var parsed map[string]any
		if json.Unmarshal(respBody, &parsed) == nil {
			out.DeviceResp = parsed
		} else {
			out.DeviceResp = string(respBody)
		}
		return mcp.NewToolResultJSON(out)
	}
}
