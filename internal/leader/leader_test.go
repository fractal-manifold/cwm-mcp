package leader

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pickPort grabs an OS-assigned free port and immediately releases it. The
// race window between release and re-bind is acceptable for tests; if it
// flakes we'll switch to passing the listener directly.
func pickPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestAcquire_HappyPath(t *testing.T) {
	addr := pickPort(t)
	ln, leader, err := Acquire(addr)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !leader {
		t.Fatal("expected leader=true")
	}
	if ln == nil {
		t.Fatal("expected non-nil listener")
	}
	ln.Close()
}

func TestAcquire_Busy(t *testing.T) {
	// First bind takes the port; second sees EADDRINUSE.
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	addr := first.Addr().String()

	ln, leader, err := Acquire(addr)
	if err != nil {
		t.Fatalf("expected leader=false err=nil, got err=%v", err)
	}
	if leader {
		ln.Close()
		t.Fatal("expected leader=false (port busy)")
	}
	if ln != nil {
		t.Fatal("expected nil listener when busy")
	}
}

func TestRun_PromotesAfterPeerExits(t *testing.T) {
	addr := pickPort(t)

	// Pre-bind so Run starts as follower.
	held, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	logger := log.New(io.Discard, "", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*RetryInterval+2*time.Second)
	defer cancel()

	var promoted atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, addr, nil, logger, func(ctx context.Context, ln net.Listener) error {
			promoted.Store(true)
			ln.Close()
			return nil
		})
	}()

	// Give the follower one probe cycle, then release the port.
	time.Sleep(RetryInterval / 2)
	if promoted.Load() {
		held.Close()
		t.Fatal("promoted before peer released the port")
	}
	held.Close()

	// Wait up to two retry intervals for the follower to detect the free
	// port and promote itself.
	deadline := time.Now().Add(2*RetryInterval + time.Second)
	for time.Now().Before(deadline) {
		if promoted.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !promoted.Load() {
		cancel()
		<-done
		t.Fatal("Run never promoted to leader after peer exited")
	}

	cancel()
	err = <-done
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
}

func TestRun_RespectsContextCancel(t *testing.T) {
	addr := pickPort(t)
	held, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	logger := log.New(io.Discard, "", 0)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, addr, nil, logger, func(context.Context, net.Listener) error {
			return nil
		})
	}()

	// Let it become follower, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(RetryInterval + 2*time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
