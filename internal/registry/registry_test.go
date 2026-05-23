package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testID  = "ab12cd34"
	testPSK = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	newPSK  = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
)

func newReg(t *testing.T) *Registry {
	t.Helper()
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func u8ptr(v uint8) *uint8 { return &v }

func TestValidDeviceID(t *testing.T) {
	cases := map[string]bool{
		"ab12cd34": true,
		"00000000": true,
		"AB12CD34": false, // uppercase rejected
		"ab12cd":   false, // too short
		"ab12cd345": false,
		"zzzzzzzz": false,
		"":         false,
	}
	for id, want := range cases {
		if got := ValidDeviceID(id); got != want {
			t.Errorf("ValidDeviceID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestRegister_RequiresPSKAndURL(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{BrokerURL: "x"}); err == nil {
		t.Fatal("expected error without psk")
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK}); err == nil {
		t.Fatal("expected error without broker_url")
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: "short", BrokerURL: "x"}); err == nil {
		t.Fatal("expected error on bad psk length")
	}
}

func TestRegister_DuplicateRejected(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestLoad_NotFound(t *testing.T) {
	r := newReg(t)
	_, err := r.Load(testID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRegister_ForcesVersion1(t *testing.T) {
	r := newReg(t)
	dev, err := r.Register(testID, ConfigPayload{
		PSKHex:    testPSK,
		BrokerURL: "http://x",
		Version:   99, // should be overridden
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if dev.Active.Version != 1 {
		t.Errorf("Active.Version = %d, want 1", dev.Active.Version)
	}
	if dev.Pending != nil {
		t.Errorf("Pending = %+v, want nil", dev.Pending)
	}
}

func TestSetPending_BumpsVersionAndMerges(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid", BrDay: u8ptr(80), BrNight: u8ptr(20), Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Partial update: just City.
	dev, err := r.SetPending(testID, ConfigPayload{City: "Barcelona"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after change")
	}
	if dev.Pending.Version != 2 {
		t.Errorf("Pending.Version = %d, want 2", dev.Pending.Version)
	}
	if dev.Pending.City != "Barcelona" {
		t.Errorf("Pending.City = %q, want Barcelona", dev.Pending.City)
	}
	// Untouched fields come from active.
	if dev.Pending.BrokerURL != "http://a" {
		t.Errorf("Pending.BrokerURL = %q, want http://a", dev.Pending.BrokerURL)
	}
	if *dev.Pending.BrDay != 80 || *dev.Pending.BrNight != 20 || *dev.Pending.Vol != 60 {
		t.Errorf("Pending non-changed fields not preserved: %+v", dev.Pending.ConfigPayload)
	}

	// Second partial: change PSK on top of pending. Version becomes 3, City stays.
	dev, err = r.SetPending(testID, ConfigPayload{PSKHex: newPSK})
	if err != nil {
		t.Fatalf("SetPending #2: %v", err)
	}
	if dev.Pending.Version != 3 {
		t.Errorf("Pending.Version = %d, want 3", dev.Pending.Version)
	}
	if dev.Pending.City != "Barcelona" {
		t.Errorf("City lost across SetPending calls: %q", dev.Pending.City)
	}
	if dev.Pending.PSKHex != newPSK {
		t.Errorf("PSK not applied: %q", dev.Pending.PSKHex)
	}
}

func TestSetPending_NoOpDropsPending(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid", BrDay: u8ptr(80), BrNight: u8ptr(20), Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Update that matches active exactly = no-op = no pending written.
	dev, err := r.SetPending(testID, ConfigPayload{City: "Madrid"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("expected no pending after no-op update, got %+v", dev.Pending)
	}
}

func TestMaybePromote_RequiresPendingPSKAndExactVersion(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK, City: "Tokyo"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}

	// Wrong: signed with active.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || promoted {
		t.Fatalf("promote with active PSK: promoted=%v err=%v", promoted, err)
	}
	// Wrong: signed with pending but version off.
	promoted, err = r.MaybePromote(testID, 1, true)
	if err != nil || promoted {
		t.Fatalf("promote with wrong version: promoted=%v err=%v", promoted, err)
	}
	// Right: signed with pending AND version matches.
	promoted, err = r.MaybePromote(testID, 2, true)
	if err != nil || !promoted {
		t.Fatalf("legit promote rejected: promoted=%v err=%v", promoted, err)
	}

	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load post-promote: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("Pending still present after promote: %+v", dev.Pending)
	}
	if dev.Active.Version != 2 || dev.Active.PSKHex != newPSK || dev.Active.City != "Tokyo" {
		t.Errorf("Active not updated: %+v", dev.Active)
	}
	if dev.Active.LastSeen.IsZero() {
		t.Errorf("Active.LastSeen not set on promote")
	}
}


func TestMaybePromote_ThemeOnlyPromotesWithActivePSK(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", ThemeMode: "day",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{ThemeMode: "night"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	// Active PSK signature (usedPendingPSK=false) MUST promote because
	// the rotation does not change the PSK.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || !promoted {
		t.Fatalf("theme-only promote with active PSK: promoted=%v err=%v", promoted, err)
	}
	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("Pending still set after theme-only promote: %+v", dev.Pending)
	}
	if dev.Active.ThemeMode != "night" {
		t.Errorf("Active.ThemeMode = %q, want night", dev.Active.ThemeMode)
	}
}

func TestMaybePromote_RotationStillRequiresPendingPSK(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	// Active-PSK signature against a rotation pending must NOT promote.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || promoted {
		t.Fatalf("PSK-rotation promote with active sig: promoted=%v err=%v", promoted, err)
	}
}

func TestMaybePromote_NoPending(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	promoted, err := r.MaybePromote(testID, 1, true)
	if err != nil || promoted {
		t.Fatalf("no-pending promote: promoted=%v err=%v", promoted, err)
	}
}

func TestPSKsFor(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	active, pending, err := r.PSKsFor(testID)
	if err != nil {
		t.Fatalf("PSKsFor: %v", err)
	}
	if len(active) != 32 || pending != nil {
		t.Errorf("active=%d pending=%v", len(active), pending)
	}

	// Pending without PSK change => still only active PSK exposed.
	if _, err := r.SetPending(testID, ConfigPayload{City: "X"}); err != nil {
		t.Fatalf("SetPending city: %v", err)
	}
	active, pending, err = r.PSKsFor(testID)
	if err != nil || len(active) != 32 || pending != nil {
		t.Errorf("after city-only pending: active=%d pending=%v err=%v", len(active), pending, err)
	}

	// Pending with PSK change => both surface.
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK}); err != nil {
		t.Fatalf("SetPending psk: %v", err)
	}
	active, pending, err = r.PSKsFor(testID)
	if err != nil || len(active) != 32 || len(pending) != 32 {
		t.Errorf("after psk pending: active=%d pending=%d err=%v", len(active), len(pending), err)
	}
}

func TestTouch_NoOpsForUnknown(t *testing.T) {
	r := newReg(t)
	if err := r.Touch(testID); err != nil {
		t.Errorf("Touch unknown should be nil, got %v", err)
	}
}

func TestList_SortedAndIgnoresJunk(t *testing.T) {
	r := newReg(t)
	for _, id := range []string{"bb000000", "aa000000", "cc000000"} {
		if _, err := r.Register(id, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}
	// junk files that List must skip
	for _, name := range []string{"junk.toml", "ZZ000000.toml", "ab.toml", "notes.txt"} {
		if err := writeFile(r.Dir(), name, "garbage"); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	out, err := r.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[0].DeviceID != "aa000000" || out[2].DeviceID != "cc000000" {
		t.Errorf("not sorted: %s, %s, %s", out[0].DeviceID, out[1].DeviceID, out[2].DeviceID)
	}
}

func TestSetPending_ThemeModeOnlyBumpsVersion(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", ThemeMode: "day",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	dev, err := r.SetPending(testID, ConfigPayload{ThemeMode: "night"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after theme-only change")
	}
	if dev.Pending.Version != 2 {
		t.Errorf("Pending.Version = %d, want 2", dev.Pending.Version)
	}
	if dev.Pending.ThemeMode != "night" {
		t.Errorf("Pending.ThemeMode = %q, want night", dev.Pending.ThemeMode)
	}
	// No-op when pending matches active.
	if _, err := r.Register("cc000000", ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://b", ThemeMode: "auto",
	}); err != nil {
		t.Fatalf("Register cc: %v", err)
	}
	dev2, err := r.SetPending("cc000000", ConfigPayload{ThemeMode: "auto"})
	if err != nil {
		t.Fatalf("SetPending cc: %v", err)
	}
	if dev2.Pending != nil {
		t.Errorf("Pending should be nil for theme no-op, got %+v", dev2.Pending)
	}
}

func TestConcurrentSetPending_VersionsMonotonic(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	const N = 20
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine writes a distinct city so SetPending never decides "no-op".
			city := "City" + strings.Repeat("X", i+1)
			if _, err := r.SetPending(testID, ConfigPayload{City: city}); err != nil {
				t.Errorf("SetPending %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after concurrent updates")
	}
	// Active = 1, so pending must be > 1 and ≤ N+1.
	if dev.Pending.Version <= 1 || dev.Pending.Version > N+1 {
		t.Errorf("Pending.Version = %d, want between 2 and %d", dev.Pending.Version, N+1)
	}
}

func TestSetPending_VolZero(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Update Vol to 0.
	dev, err := r.SetPending(testID, ConfigPayload{Vol: u8ptr(0)})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after Vol change to 0")
	}
	if dev.Pending.Vol == nil || *dev.Pending.Vol != 0 {
		t.Errorf("Pending.Vol = %v, want 0", dev.Pending.Vol)
	}

	// Another partial update (City) should preserve Vol=0.
	dev, err = r.SetPending(testID, ConfigPayload{City: "Berlin"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending.Vol == nil || *dev.Pending.Vol != 0 {
		t.Errorf("Pending.Vol = %v after partial update, want 0", dev.Pending.Vol)
	}
}

func writeFile(dir, name, body string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
}
