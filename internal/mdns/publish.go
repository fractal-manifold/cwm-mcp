// Package mdns advertises the cwm-mcp broker on the local network so
// firmware devices can locate it when their cached broker URL stops
// working (DHCP renew, broker host change). The service type is
// `_cwm-broker._tcp` and the TXT record carries:
//
//	v=1
//	runtime=go|python|js
//	devs=<id1>,<id2>,...     (registered device_ids, lowercase 8 hex)
//
// device_id is public — it travels in the X-Cwm-Device HTTP header on
// every poll — so listing them in TXT only lets devices filter "is my
// broker on this LAN?" without leaking secrets. Authentication is still
// HMAC against the per-device PSK held by the registry.
//
// When bind is loopback (127.0.0.1 / ::1) we skip publication entirely:
// the device can't reach the broker anyway, and pretending otherwise
// would just generate spurious hits in the discovery scan.
package mdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// ServiceType is the mDNS service the firmware queries for.
const ServiceType = "_cwm-broker._tcp"

// virtualIfacePrefixes mirrors the list in internal/mcp/server.go. We
// must skip them on mDNS publication too: a device on the WiFi LAN can't
// reach a Docker bridge / VPN tunnel address, but if we announce on that
// interface zeroconf advertises every interface's IP — including the
// unreachable ones — and the firmware's discovery code picks the first
// match by device_id, which lands on the wrong IP.
var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "vnet", "tun", "tap",
	"vmnet", "tailscale", "wg", "zt",
}

func isVirtualIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// physicalMulticastIfaces returns the multicast-capable, non-loopback,
// non-virtual interfaces zeroconf should advertise on. Returning nil
// would make zeroconf fall back to ALL multicast interfaces, which is
// what we are explicitly trying to avoid.
func physicalMulticastIfaces() []net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, iface := range all {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		if isVirtualIface(iface.Name) {
			continue
		}
		out = append(out, iface)
	}
	return out
}

// Runtime is the value used in the TXT `runtime=` field. The Python and
// JS impls publish the same record format with their own runtime tag so
// a single TXT can disambiguate which binary won the bind race.
const Runtime = "go"

// devIDLister is the slice of the registry the publisher needs. Kept
// minimal so tests can inject a fake without dragging the whole package.
type devIDLister interface {
	ListDeviceIDs() ([]string, error)
}

// Publisher owns the zeroconf server and a goroutine that re-announces
// the TXT record whenever the device list changes. Construct via Start;
// stop with Close (or by cancelling the context passed to Start).
type Publisher struct {
	server *zeroconf.Server
	mu     sync.Mutex
	lastTxt string
}

// hostShort derives a 6-hex tag from the OS hostname so two laptops on
// the same LAN don't collide on `cwm-broker.local`. Falling back to
// "anon" rather than randomising — a stable name across reboots is
// friendlier to the device's cached resolution.
func hostShort() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "anon00"
	}
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:3])
}

// isLoopback returns true when bind targets only the loopback interface.
// "" / "0.0.0.0" / "::" are treated as "all interfaces" — publishable.
func isLoopback(bind string) bool {
	if bind == "" || bind == "0.0.0.0" || bind == "::" {
		return false
	}
	ip := net.ParseIP(bind)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// buildTXT renders the TXT record body. Length cap: a single TXT chunk
// is bounded at 255 bytes by the DNS RR encoding; we trim the devs list
// from the right when we exceed that so the most-recently-discovered
// devices stay visible (alphabetical order means lowest IDs win, which
// is fine for the small home/lab fleets we target).
func buildTXT(devs []string) []string {
	out := []string{"v=1", "runtime=" + Runtime}
	if len(devs) == 0 {
		out = append(out, "devs=")
		return out
	}
	sort.Strings(devs)
	const maxLen = 255 - len("devs=")
	joined := strings.Join(devs, ",")
	if len(joined) > maxLen {
		// Walk back until we fit. Each id is 8 chars + 1 comma = 9.
		// This is a worst-case truncation; we don't expect to hit it.
		joined = joined[:maxLen]
		if cut := strings.LastIndex(joined, ","); cut > 0 {
			joined = joined[:cut]
		}
	}
	out = append(out, "devs="+joined)
	return out
}

// Start advertises the broker and keeps the TXT record fresh. Returns
// nil + a no-op publisher when the bind is loopback (publication
// suppressed by design). Errors during initial Register are returned;
// later refresh failures are logged, not propagated, since the broker
// keeps serving regardless.
func Start(ctx context.Context, bind string, port int, lister devIDLister, logger *log.Logger) (*Publisher, error) {
	if isLoopback(bind) {
		if logger != nil {
			logger.Printf("mdns: bind=%s is loopback, skipping broker advertisement", bind)
		}
		return &Publisher{}, nil
	}
	if lister == nil {
		return nil, fmt.Errorf("mdns: nil registry")
	}

	devs, err := lister.ListDeviceIDs()
	if err != nil {
		// Non-fatal: empty list still lets the device discover by
		// runtime tag, and the next refresh tick will retry.
		if logger != nil {
			logger.Printf("mdns: initial device list: %v", err)
		}
		devs = nil
	}
	txt := buildTXT(devs)

	instance := "cwm-broker-" + hostShort()
	ifaces := physicalMulticastIfaces()
	srv, err := zeroconf.Register(instance, ServiceType, "local.", port, txt, ifaces)
	if err != nil {
		return nil, fmt.Errorf("mdns register: %w", err)
	}
	if logger != nil {
		names := make([]string, 0, len(ifaces))
		for _, i := range ifaces {
			names = append(names, i.Name)
		}
		logger.Printf("mdns: published %s.%s.local. port=%d devs=%d ifaces=%v",
			instance, ServiceType, port, len(devs), names)
	}

	p := &Publisher{server: srv, lastTxt: strings.Join(txt, ";")}

	go p.refreshLoop(ctx, lister, logger)
	return p, nil
}

// refreshLoop polls the registry every 30s and pushes an updated TXT if
// the device list changed. Cheap (a single readdir) and bounded — we
// don't watch the filesystem to avoid bringing in inotify just for this.
func (p *Publisher) refreshLoop(ctx context.Context, lister devIDLister, logger *log.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Close()
			return
		case <-t.C:
		}
		devs, err := lister.ListDeviceIDs()
		if err != nil {
			if logger != nil {
				logger.Printf("mdns: refresh device list: %v", err)
			}
			continue
		}
		txt := buildTXT(devs)
		joined := strings.Join(txt, ";")
		p.mu.Lock()
		changed := joined != p.lastTxt
		if changed {
			p.lastTxt = joined
		}
		srv := p.server
		p.mu.Unlock()
		if changed && srv != nil {
			srv.SetText(txt)
			if logger != nil {
				logger.Printf("mdns: TXT updated, devs=%d", len(devs))
			}
		}
	}
}

// Close releases the zeroconf server (idempotent). Safe to call after
// Start returned the loopback no-op publisher.
func (p *Publisher) Close() {
	p.mu.Lock()
	srv := p.server
	p.server = nil
	p.mu.Unlock()
	if srv != nil {
		srv.Shutdown()
	}
}
