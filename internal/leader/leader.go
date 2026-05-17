// Package leader implements bind-based single-leader election.
//
// Several cwm-mcp processes can run at once (one per Claude Code session
// plus a possible standalone --daemon). They all compete for the same
// TCP port; the kernel guarantees exactly one bind succeeds. The loser
// goes into a probe loop, retrying every RetryInterval until either the
// port is freed (then it promotes itself) or its own context is
// cancelled (then it just exits).
//
// This trivially supports the "old service-go daemon still installed"
// case from the README: the followers never get promoted because the
// daemon never releases the port — and that's exactly what we want.
package leader

import (
	"context"
	"errors"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/state"
)

// RetryInterval controls how often a follower retries the bind. 5 s was
// chosen as a balance between fast handover (≤ 5 s after the leader exits)
// and not flooding logs while a long-lived daemon holds the port.
const RetryInterval = 5 * time.Second

// Acquire tries to bind addr once. It returns the listener on success,
// (nil, false, nil) if the address is busy, or (nil, false, err) on any
// other failure (which the caller likely wants to treat as fatal).
func Acquire(addr string) (net.Listener, bool, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, true, nil
	}
	if isAddrInUse(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// OnAcquired is invoked with the bound listener once leadership is gained.
// It owns the listener and must Close it before returning. When it returns,
// Run re-enters the probe loop (so a crash in the handler doesn't leave the
// process zombified).
type OnAcquired func(context.Context, net.Listener) error

// Run keeps trying to become the leader for addr until ctx is cancelled.
// It logs the first follower-fall and each promotion but stays quiet on
// subsequent retries to keep the log readable.
//
// `st` (may be nil) is updated on every role transition so the MCP tools
// can report current state.
func Run(ctx context.Context, addr string, st *state.State, logger *log.Logger, onAcquired OnAcquired) error {
	announcedFollower := false
	for {
		ln, gained, err := Acquire(addr)
		switch {
		case err != nil:
			logger.Printf("leader: listen %s: %v (will retry in %s)", addr, err, RetryInterval)
		case gained:
			announcedFollower = false
			if st != nil {
				st.SetRole(state.RoleLeader)
			}
			logger.Printf("leader: bound %s", addr)
			runErr := onAcquired(ctx, ln)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if runErr != nil {
				logger.Printf("leader: handler exited with: %v", runErr)
			}
		default:
			if !announcedFollower {
				logger.Printf("leader: %s busy, running as follower (probing every %s)", addr, RetryInterval)
				announcedFollower = true
			}
			if st != nil {
				st.SetRole(state.RoleFollower)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(RetryInterval):
		}
	}
}
