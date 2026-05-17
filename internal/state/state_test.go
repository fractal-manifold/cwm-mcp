package state

import (
	"testing"
	"time"
)

func TestNew_StartsUnknown(t *testing.T) {
	s := New()
	if got := s.Snapshot().Role; got != "unknown" {
		t.Errorf("role = %q, want unknown", got)
	}
}

func TestSetRole_TracksTransitions(t *testing.T) {
	s := New()
	initial := s.Snapshot().RoleSince

	time.Sleep(2 * time.Millisecond)
	s.SetRole(RoleLeader)
	if got := s.Snapshot().Role; got != "leader" {
		t.Fatalf("role = %q, want leader", got)
	}
	afterLeader := s.Snapshot().RoleSince
	if !afterLeader.After(initial) {
		t.Error("RoleSince did not advance on transition")
	}

	// Setting the same role should not bump RoleSince.
	time.Sleep(2 * time.Millisecond)
	s.SetRole(RoleLeader)
	if got := s.Snapshot().RoleSince; !got.Equal(afterLeader) {
		t.Error("RoleSince advanced on no-op SetRole")
	}
}

func TestRecordRequest(t *testing.T) {
	s := New()
	now := time.Unix(1700000000, 0)
	s.RecordRequest("192.168.1.99:54321", 200, now)
	snap := s.Snapshot()
	if snap.LastRequestAt != now {
		t.Errorf("LastRequestAt = %v, want %v", snap.LastRequestAt, now)
	}
	if snap.LastRequestRemote != "192.168.1.99:54321" {
		t.Errorf("LastRequestRemote = %q", snap.LastRequestRemote)
	}
	if snap.LastRequestStatus != 200 {
		t.Errorf("LastRequestStatus = %d", snap.LastRequestStatus)
	}
	if snap.RequestsTotal != 1 {
		t.Errorf("RequestsTotal = %d, want 1", snap.RequestsTotal)
	}

	s.RecordRequest("x", 401, now.Add(time.Second))
	if snap := s.Snapshot(); snap.RequestsTotal != 2 {
		t.Errorf("RequestsTotal after 2 records = %d", snap.RequestsTotal)
	}
}
