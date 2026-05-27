// Package registry persists per-device configuration for the cwm-mcp
// control plane. Each device gets one TOML file under devicesDir; reads
// and writes are serialised with flock so leader/follower processes
// can't race each other. The store is the source of truth for which
// PSK and broker URL a given device is supposed to be running, and
// holds an optional `pending` config used to roll changes out safely:
//
//   - active = what the device is believed to be running right now
//   - pending = what we want it to switch to next
//
// Promotion (pending → active) only happens once the device has proved
// it is actually running the pending version: it must sign a request
// with the pending PSK and report config_version == pending.version. A
// stale or failed pending never overwrites the known-good active, and
// the firmware does its own candidate/rollback dance on top of this so
// a bad URL can't brick anything.
package registry

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"
)

// SchemaVersion identifies the on-disk TOML layout. Bump when fields move
// or get renamed so callers can refuse incompatible files instead of
// silently producing junk.
//
// v2 adds: device.serial_number, device.hw_sku (factory identity),
//          pending.firmware_manifest_b64 / firmware_manifest_sig_b64
//          (signed OTA manifest delivered alongside the .bin URL),
//          active.min_secure_version (anti-rollback floor mirrored
//          from the device's cwm_min_sv NVS key).
// v1 files load with empty serial / hw_sku / manifest fields and are
// re-serialised as v2 on the next save (migration in loadLocked).
const SchemaVersion = 2

// ProviderSet mirrors the firmware's per-provider NVS toggles (NVS keys
// prov_claude, prov_codex, prov_gemini). Stored as plain bools so an
// omitted field unambiguously means "no change requested" when used in
// a partial update (see SetPending).
type ProviderSet struct {
	Claude bool `toml:"claude"`
	Codex  bool `toml:"codex"`
	Gemini bool `toml:"gemini"`
}

// ConfigPayload is the set of values a config_sync delivery can carry.
// All non-Version fields are optional in pending payloads; an empty
// value means "don't touch on the device". Active payloads, by
// contrast, are the snapshot of the last fully-applied config and
// therefore have every field populated.
type ConfigPayload struct {
	Version              uint32       `toml:"version"`
	BrokerURL            string       `toml:"broker_url,omitempty"`
	PSKHex               string       `toml:"psk_hex,omitempty"`
	City                 string       `toml:"city,omitempty"`
	BrDay                *uint8       `toml:"br_day,omitempty"`
	BrNight              *uint8       `toml:"br_night,omitempty"`
	Vol                  *uint8       `toml:"vol,omitempty"`
	Providers            *ProviderSet `toml:"providers,omitempty"`
	AutorotateEnabled    *bool        `toml:"autorotate_enabled,omitempty"`
	AutorotateIntervalS  *uint16      `toml:"autorotate_interval_s,omitempty"`
	// ThemeMode is the on-device palette mode: "day", "night", or "auto"
	// (the latter follows sunrise/sunset). Empty string means "no
	// opinion" / "don't touch on the device" for partial pending updates;
	// see compat/tool-schemas.json for the enum.
	ThemeMode            string       `toml:"theme_mode,omitempty"`
	// GeminiModels overrides service.toml [gemini].models for this
	// device. The broker honours this list when serving /usage/gemini
	// for the device. Empty means "use the global default". Max 3 entries;
	// excess is silently clamped on the broker side.
	GeminiModels         []string     `toml:"gemini_models,omitempty"`
	// FirmwareURL / FirmwareSHA256 / FirmwareVersion carry a staged OTA
	// update through the same pending envelope as a config change. All
	// three must be present in the pending payload for the firmware's
	// config_sync to arm the on-device cwm_ota_* NVS keys (see
	// firmware/components/ota/src/cwm_ota.c). The URL must be HTTPS so
	// the device's CA bundle applies; the SHA-256 is the integrity
	// anchor since the .bin itself is not signed; the version string
	// must match the esp_app_desc baked into the binary so the device
	// can refuse to re-install or downgrade.
	FirmwareURL          string       `toml:"firmware_url,omitempty"`
	FirmwareSHA256       string       `toml:"firmware_sha256,omitempty"`
	FirmwareVersion      string       `toml:"firmware_version,omitempty"`
	// FirmwareManifestB64 is the base64 of the canonical-JSON Ed25519
	// manifest produced by `firmware/components/ota/scripts/manifest.py
	// sign`. FirmwareManifestSigB64 is the base64 of the 64-byte raw
	// signature over those exact bytes. Both fields travel inside the
	// AES-CTR-encrypted pending blob; the firmware verifies the
	// signature with one of the pubkeys in cwm_ota_pubkey_{current,next}
	// BEFORE downloading the .bin. See firmware/components/ota/include/
	// cwm_manifest.h for the canonical key order.
	FirmwareManifestB64    string `toml:"firmware_manifest_b64,omitempty"`
	FirmwareManifestSigB64 string `toml:"firmware_manifest_sig_b64,omitempty"`
	// MinSecureVersion mirrors the device's cwm_min_sv NVS key (packed
	// 8.8.16 = major.minor.patch). Pending payloads must satisfy
	// manifest.min_secure_version >= active.MinSecureVersion or the
	// firmware refuses to apply. Tracked here so revert-via-MCP can
	// surface "this rollback would violate anti-rollback" before it
	// touches the device.
	MinSecureVersion       uint32 `toml:"min_secure_version,omitempty"`
}

type Active struct {
	ConfigPayload
	LastSeen time.Time `toml:"last_seen,omitempty"`
}

type Pending struct {
	ConfigPayload
	CreatedAt time.Time `toml:"created_at"`
}

// Device is the full per-device record.
type Device struct {
	SchemaVersion int    `toml:"schema_version"`
	DeviceID      string `toml:"device_id"`
	// SerialNumber is the human-readable factory serial baked in the
	// device's eFuse BLOCK_USR_DATA (or the NVS dev override). Format:
	// "CWM-<SKU2>-<FAC3>-<YYWW4>-<SEQ6>-<C1>" — 24 chars. Empty on
	// devices that haven't yet sent the X-Cwm-Serial header (legacy /
	// pre-rev-2 firmware). Persisted but never authoritative — we
	// always trust the device's eFuse over what the broker remembers.
	SerialNumber string `toml:"serial_number,omitempty"`
	// HWSku is the 2-char SKU code parsed out of SerialNumber (or "DEV"
	// for non-factory units). Stored separately so MCP queries don't
	// have to re-parse the serial. The broker NEVER promotes a pending
	// whose firmware_manifest_b64.sku conflicts with this — the
	// firmware would reject it anyway, this just spares the round trip.
	HWSku   string   `toml:"hw_sku,omitempty"`
	Active  Active   `toml:"active"`
	Pending *Pending `toml:"pending,omitempty"`
}

// Registry owns the on-disk store under devicesDir. Construct via New.
type Registry struct {
	dir string
}

func New(devicesDir string) (*Registry, error) {
	if devicesDir == "" {
		return nil, errors.New("registry: empty directory")
	}
	if err := os.MkdirAll(devicesDir, 0o755); err != nil {
		return nil, fmt.Errorf("registry: mkdir %s: %w", devicesDir, err)
	}
	return &Registry{dir: devicesDir}, nil
}

// Dir exposes the backing directory (useful for diagnostics).
func (r *Registry) Dir() string { return r.dir }

var deviceIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// ValidDeviceID enforces the 8-lowercase-hex shape derived from the
// ESP32 MAC. Centralised so HTTP handlers, MCP tools and the on-disk
// store all reject the same way.
func ValidDeviceID(id string) bool { return deviceIDRe.MatchString(id) }

func (r *Registry) path(deviceID string) string {
	return filepath.Join(r.dir, deviceID+".toml")
}

// ErrNotFound is returned when no record exists for a device. Callers
// distinguish first-poll-by-unknown-device (legacy mode) from
// configuration errors using this sentinel.
var ErrNotFound = errors.New("registry: device not found")

// withLock opens the device file (creating it if `create`) and holds an
// exclusive flock for the duration of fn. The lock is on a sibling
// `.lock` file rather than the data file itself so we can rename(2) the
// data file atomically without invalidating the lock.
func (r *Registry) withLock(deviceID string, fn func(dataPath string) error) error {
	lockPath := r.path(deviceID) + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("registry: open lock %s: %w", lockPath, err)
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("registry: flock %s: %w", lockPath, err)
	}
	defer unix.Flock(int(lf.Fd()), unix.LOCK_UN)
	return fn(r.path(deviceID))
}

// loadLocked reads the device file from disk. Caller must already hold
// the lock for deviceID. Returns ErrNotFound if the file is missing.
func (r *Registry) loadLocked(dataPath string) (*Device, error) {
	raw, err := os.ReadFile(dataPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("registry: read %s: %w", dataPath, err)
	}
	var dev Device
	if err := toml.Unmarshal(raw, &dev); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", dataPath, err)
	}
	switch dev.SchemaVersion {
	case 0, 1, SchemaVersion:
		// v0 = freshly-decoded zero value (no field set). v1 is the
		// pre-serial schema — migrated transparently: serial_number /
		// hw_sku stay empty until the next /sync round populates them
		// from the X-Cwm-Serial header, and the next save bumps the
		// stored schema_version to SchemaVersion.
	default:
		return nil, fmt.Errorf("registry: %s schema %d, expected %d", dataPath, dev.SchemaVersion, SchemaVersion)
	}
	return &dev, nil
}

// saveLocked persists dev atomically: write to a tmp sibling, fsync,
// rename over the target. Caller must hold the lock.
func (r *Registry) saveLocked(dev *Device, dataPath string) error {
	if !ValidDeviceID(dev.DeviceID) {
		return fmt.Errorf("registry: invalid device_id %q", dev.DeviceID)
	}
	dev.SchemaVersion = SchemaVersion
	tmp := dataPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("registry: create %s: %w", tmp, err)
	}
	enc := toml.NewEncoder(f)
	if err := enc.Encode(dev); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("registry: encode %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("registry: fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("registry: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dataPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("registry: rename %s: %w", dataPath, err)
	}
	return nil
}

// Load returns the device record. Returns ErrNotFound for unknown IDs.
func (r *Registry) Load(deviceID string) (*Device, error) {
	if !ValidDeviceID(deviceID) {
		return nil, fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	var out *Device
	err := r.withLock(deviceID, func(p string) error {
		d, err := r.loadLocked(p)
		out = d
		return err
	})
	return out, err
}

// Register creates a new device record with `active` populated from the
// supplied payload (version forced to 1). Fails if the device already
// exists — callers that want to overwrite must use SetActive explicitly.
func (r *Registry) Register(deviceID string, active ConfigPayload) (*Device, error) {
	if !ValidDeviceID(deviceID) {
		return nil, fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	if active.PSKHex == "" || active.BrokerURL == "" {
		return nil, errors.New("registry: register requires psk_hex and broker_url")
	}
	if _, err := hex.DecodeString(active.PSKHex); err != nil || len(active.PSKHex) != 64 {
		return nil, errors.New("registry: psk_hex must be 64 lowercase hex chars")
	}
	active.PSKHex = strings.ToLower(active.PSKHex)
	active.Version = 1

	var out *Device
	err := r.withLock(deviceID, func(p string) error {
		if _, err := r.loadLocked(p); err == nil {
			return fmt.Errorf("registry: device %s already exists", deviceID)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		dev := &Device{
			DeviceID: deviceID,
			Active:   Active{ConfigPayload: active},
		}
		if err := r.saveLocked(dev, p); err != nil {
			return err
		}
		out = dev
		return nil
	})
	return out, err
}

// SetPending stages a partial update. Behaviour:
//
//   - Build the new pending payload by mergingg `update` on top of the
//     current pending (if present) or active (if not). This way callers
//     can call SetPending repeatedly and each call just amends what's
//     already queued instead of dropping prior edits.
//   - version = max(active.Version, prior pending.Version) + 1, so the
//     device always sees a strictly newer number than what it last knew.
//   - If the resulting pending is identical to active (no real change),
//     drop pending instead of writing a no-op.
//
// Returns the device record after the update for the caller to inspect.
func (r *Registry) SetPending(deviceID string, update ConfigPayload) (*Device, error) {
	if !ValidDeviceID(deviceID) {
		return nil, fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	if update.PSKHex != "" {
		if _, err := hex.DecodeString(update.PSKHex); err != nil || len(update.PSKHex) != 64 {
			return nil, errors.New("registry: psk_hex must be 64 lowercase hex chars")
		}
		update.PSKHex = strings.ToLower(update.PSKHex)
	}

	var out *Device
	err := r.withLock(deviceID, func(p string) error {
		dev, err := r.loadLocked(p)
		if err != nil {
			return err
		}

		var base ConfigPayload
		if dev.Pending != nil {
			base = dev.Pending.ConfigPayload
		} else {
			base = dev.Active.ConfigPayload
		}
		merged := mergePayload(base, update)

		nextVersion := dev.Active.Version + 1
		if dev.Pending != nil && dev.Pending.Version >= nextVersion {
			nextVersion = dev.Pending.Version + 1
		}
		merged.Version = nextVersion

		if payloadEquivalent(merged, dev.Active.ConfigPayload) {
			dev.Pending = nil
		} else {
			dev.Pending = &Pending{
				ConfigPayload: merged,
				CreatedAt:     time.Now().UTC(),
			}
		}
		if err := r.saveLocked(dev, p); err != nil {
			return err
		}
		out = dev
		return nil
	})
	return out, err
}

// MaybePromote moves pending → active when the device proves it has
// applied the candidate. Promotion happens when observedVersion
// matches pending.Version AND either:
//
//  1. usedPendingPSK == true — the device signed with the pending PSK,
//     which proves the new key works (mandatory for key rotations); or
//  2. the pending payload does NOT rotate the PSK (active.PSKHex ==
//     pending.PSKHex) — there is no new key to prove, so the version
//     header on a valid signature with the active PSK is sufficient.
//
// The second branch closes a footgun where city-only / brightness-only
// / theme-only pending updates would never be promoted because the
// device never gets a chance to sign with a "pending" PSK distinct
// from the active one.
//
// Returns promoted=true when the registry was updated. When pending is
// absent, returns (false, nil) regardless of the other arguments.
func (r *Registry) MaybePromote(deviceID string, observedVersion uint32, usedPendingPSK bool) (bool, error) {
	if !ValidDeviceID(deviceID) {
		return false, fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	promoted := false
	err := r.withLock(deviceID, func(p string) error {
		dev, err := r.loadLocked(p)
		if err != nil {
			return err
		}
		if dev.Pending == nil {
			return nil
		}
		if observedVersion != dev.Pending.Version {
			return nil
		}
		// Allow promotion without a pending-PSK signature only when the
		// rotation does not actually change the PSK.
		if !usedPendingPSK && dev.Pending.PSKHex != dev.Active.PSKHex {
			return nil
		}
		dev.Active = Active{
			ConfigPayload: dev.Pending.ConfigPayload,
			LastSeen:      time.Now().UTC(),
		}
		dev.Pending = nil
		promoted = true
		return r.saveLocked(dev, p)
	})
	return promoted, err
}

// Touch updates active.LastSeen without changing any config. Called
// after every successful HMAC verification so list_devices can show
// freshness. Silently no-ops on ErrNotFound — a legacy device polling
// without X-Cwm-Device shouldn't be auto-registered.
func (r *Registry) Touch(deviceID string) error {
	if !ValidDeviceID(deviceID) {
		return fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	return r.withLock(deviceID, func(p string) error {
		dev, err := r.loadLocked(p)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		dev.Active.LastSeen = time.Now().UTC()
		return r.saveLocked(dev, p)
	})
}

// SetSerial persists the X-Cwm-Serial / X-Cwm-Sku headers reported by
// the device on /sync. Non-destructive: if either string is empty the
// existing value is kept (a v2 broker can rendezvous with a v1
// firmware that doesn't send the header without losing the serial it
// already knew). Returns silently for unknown devices — the headers
// arrived together with an authenticated request, so unknown-device
// means a race with a fresh registration, not a header forgery.
func (r *Registry) SetSerial(deviceID, serial, sku string) error {
	if !ValidDeviceID(deviceID) {
		return fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	return r.withLock(deviceID, func(p string) error {
		dev, err := r.loadLocked(p)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		changed := false
		if serial != "" && serial != dev.SerialNumber {
			dev.SerialNumber = serial
			changed = true
		}
		if sku != "" && sku != dev.HWSku {
			dev.HWSku = sku
			changed = true
		}
		if !changed {
			return nil
		}
		return r.saveLocked(dev, p)
	})
}

// BumpMinSV records that the device acknowledged installing a firmware
// with at least `sv` packed semver. Monotonic — never lowers the
// floor. Used by revert-via-MCP to reject downgrade pendings before
// they reach the device.
func (r *Registry) BumpMinSV(deviceID string, sv uint32) error {
	if !ValidDeviceID(deviceID) {
		return fmt.Errorf("registry: invalid device_id %q", deviceID)
	}
	return r.withLock(deviceID, func(p string) error {
		dev, err := r.loadLocked(p)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		if sv <= dev.Active.MinSecureVersion {
			return nil
		}
		dev.Active.MinSecureVersion = sv
		return r.saveLocked(dev, p)
	})
}

// PSKsFor returns the active PSK and, when a pending config carries a
// PSK change, the pending PSK too. Either may be nil if the
// corresponding hex is unset (pending often has no PSK change). The
// caller fed both to auth.VerifyMulti.
func (r *Registry) PSKsFor(deviceID string) (active, pending []byte, err error) {
	dev, err := r.Load(deviceID)
	if err != nil {
		return nil, nil, err
	}
	if dev.Active.PSKHex != "" {
		active, err = hex.DecodeString(dev.Active.PSKHex)
		if err != nil {
			return nil, nil, fmt.Errorf("registry: decode active psk: %w", err)
		}
	}
	// Only surface pending PSK when it actually differs from active —
	// SetPending merges fields from active into pending for convenience,
	// so pending.PSKHex is non-empty even on pure city/brightness changes.
	// Returning it would waste a verifier round-trip and, worse, hide a
	// MaybePromote that triggered for the wrong reason.
	if dev.Pending != nil && dev.Pending.PSKHex != "" && dev.Pending.PSKHex != dev.Active.PSKHex {
		pending, err = hex.DecodeString(dev.Pending.PSKHex)
		if err != nil {
			return nil, nil, fmt.Errorf("registry: decode pending psk: %w", err)
		}
	}
	return active, pending, nil
}

// ListDeviceIDs returns just the device_id slugs found on disk, sorted
// ascending. Cheaper than List for callers that only need IDs (e.g. the
// mDNS advertiser populating the TXT `devs=` record). Parse failures
// don't abort the scan — the file might still belong to a valid device
// the next time around, and a partial list is more useful than none.
func (r *Registry) ListDeviceIDs() ([]string, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("registry: readdir %s: %w", r.dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".toml") {
			continue
		}
		id := strings.TrimSuffix(name, ".toml")
		if !ValidDeviceID(id) {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// List returns all device records, sorted by device_id ascending. Skips
// files that fail to parse but surfaces the first error encountered so
// the caller can log it.
func (r *Registry) List() ([]*Device, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("registry: readdir %s: %w", r.dir, err)
	}
	out := make([]*Device, 0, len(entries))
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".toml") {
			continue
		}
		id := strings.TrimSuffix(name, ".toml")
		if !ValidDeviceID(id) {
			continue
		}
		dev, err := r.Load(id)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, firstErr
}

// mergePayload copies fields from `upd` onto `base` only when `upd`
// holds a non-zero value, except for Providers and the Autorotate
// pointers which are merged when non-nil. This is what makes partial
// updates idempotent: "no opinion" stays as "no opinion".
func mergePayload(base, upd ConfigPayload) ConfigPayload {
	out := base
	if upd.BrokerURL != "" {
		out.BrokerURL = upd.BrokerURL
	}
	if upd.PSKHex != "" {
		out.PSKHex = upd.PSKHex
	}
	if upd.City != "" {
		out.City = upd.City
	}
	if upd.BrDay != nil {
		v := *upd.BrDay
		out.BrDay = &v
	}
	if upd.BrNight != nil {
		v := *upd.BrNight
		out.BrNight = &v
	}
	if upd.Vol != nil {
		v := *upd.Vol
		out.Vol = &v
	}
	if upd.Providers != nil {
		ps := *upd.Providers
		out.Providers = &ps
	}
	if upd.AutorotateEnabled != nil {
		v := *upd.AutorotateEnabled
		out.AutorotateEnabled = &v
	}
	if upd.AutorotateIntervalS != nil {
		v := *upd.AutorotateIntervalS
		out.AutorotateIntervalS = &v
	}
	if upd.ThemeMode != "" {
		out.ThemeMode = upd.ThemeMode
	}
	if upd.GeminiModels != nil {
		// Copy so callers can't mutate the stored slice afterwards.
		m := make([]string, len(upd.GeminiModels))
		copy(m, upd.GeminiModels)
		out.GeminiModels = m
	}
	if upd.FirmwareURL != "" {
		out.FirmwareURL = upd.FirmwareURL
	}
	if upd.FirmwareSHA256 != "" {
		out.FirmwareSHA256 = upd.FirmwareSHA256
	}
	if upd.FirmwareVersion != "" {
		out.FirmwareVersion = upd.FirmwareVersion
	}
	// Manifest pair and anti-rollback floor — same partial-update rule
	// as the rest: a missing field means "no opinion", an empty
	// explicit override falls back to the default zero value. We
	// merge both b64 fields independently rather than treating them
	// as a unit so a follow-up rotation can drop the sig in isolation
	// while keeping the manifest text for audit. The device's
	// `gate_manifest` is what enforces the pair-or-fail rule.
	if upd.FirmwareManifestB64 != "" {
		out.FirmwareManifestB64 = upd.FirmwareManifestB64
	}
	if upd.FirmwareManifestSigB64 != "" {
		out.FirmwareManifestSigB64 = upd.FirmwareManifestSigB64
	}
	// Anti-rollback is monotonic: a merge can only raise the floor,
	// never lower it. This matches the firmware-side invariant on
	// cwm_min_sv (refuses any decrease).
	if upd.MinSecureVersion > out.MinSecureVersion {
		out.MinSecureVersion = upd.MinSecureVersion
	}
	return out
}

func payloadEquivalent(a, b ConfigPayload) bool {
	if a.BrokerURL != b.BrokerURL ||
		a.PSKHex != b.PSKHex ||
		a.City != b.City ||
		a.ThemeMode != b.ThemeMode ||
		a.FirmwareURL != b.FirmwareURL ||
		a.FirmwareSHA256 != b.FirmwareSHA256 ||
		a.FirmwareVersion != b.FirmwareVersion ||
		a.FirmwareManifestB64 != b.FirmwareManifestB64 ||
		a.FirmwareManifestSigB64 != b.FirmwareManifestSigB64 ||
		a.MinSecureVersion != b.MinSecureVersion {
		return false
	}
	if !ptrU8Equal(a.BrDay, b.BrDay) {
		return false
	}
	if !ptrU8Equal(a.BrNight, b.BrNight) {
		return false
	}
	if !ptrU8Equal(a.Vol, b.Vol) {
		return false
	}
	if (a.Providers == nil) != (b.Providers == nil) {
		return false
	}
	if a.Providers != nil && *a.Providers != *b.Providers {
		return false
	}
	if !ptrBoolEqual(a.AutorotateEnabled, b.AutorotateEnabled) {
		return false
	}
	if !ptrU16Equal(a.AutorotateIntervalS, b.AutorotateIntervalS) {
		return false
	}
	if !strSliceEqual(a.GeminiModels, b.GeminiModels) {
		return false
	}
	return true
}

func strSliceEqual(a, b []string) bool {
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

func ptrBoolEqual(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func ptrU8Equal(a, b *uint8) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func ptrU16Equal(a, b *uint16) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}
