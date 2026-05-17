// Package logbuf is a tiny ring buffer of log lines that doubles as an
// io.Writer. We tee the broker's logger through it so the
// `wall_monitor_recent_logs` MCP tool has something to return without
// having to follow stderr from disk.
//
// One line is one element in the ring. Partial writes are buffered until
// a '\n' arrives, mirroring how log.Logger flushes a single line per
// Output() call.
package logbuf

import (
	"bytes"
	"sync"
)

type Buffer struct {
	mu      sync.Mutex
	lines   []string
	max     int
	partial []byte
}

// New returns a buffer that keeps at most `max` lines (oldest evicted).
func New(max int) *Buffer {
	if max <= 0 {
		max = 200
	}
	return &Buffer{max: max}
}

// Write implements io.Writer. Each newline-terminated chunk becomes one
// line in the ring. The trailing partial line (no '\n' yet) is kept
// pending and folded into the next Write.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.partial = append(b.partial, p...)
	for {
		i := bytes.IndexByte(b.partial, '\n')
		if i < 0 {
			break
		}
		line := string(b.partial[:i])
		b.partial = b.partial[i+1:]
		b.lines = append(b.lines, line)
		if len(b.lines) > b.max {
			b.lines = b.lines[len(b.lines)-b.max:]
		}
	}
	return len(p), nil
}

// Tail returns the most recent up-to-n lines (newest last). A copy is
// returned so callers can't see future mutations through the slice.
func (b *Buffer) Tail(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n >= len(b.lines) {
		return append([]string(nil), b.lines...)
	}
	return append([]string(nil), b.lines[len(b.lines)-n:]...)
}

// Len returns the current number of complete lines retained.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.lines)
}
