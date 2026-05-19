// Package serial owns the USB-CDC port that streams ESP-IDF logs from the
// Wall Monitor device. The tailer is started by the leader cwm-mcp process
// only — there's a single /dev/ttyACMx and exactly one process can read it
// at a time. Followers (and any tool that wants the logs) go through the
// broker's HTTP /firmware-logs endpoint instead.
//
// We deliberately avoid pulling in a serial-port library: USB-CDC ignores
// baud/parity/stop-bits, so all we need is to open the tty in raw,
// non-canonical mode and read bytes. Doing that with a couple of unix
// syscalls is cheaper than a dependency.
package serial

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Strip ANSI CSI sequences (color, cursor moves) that ESP-IDF emits when
// logs are colored. The MCP consumer doesn't render escapes.
var ansiCSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Tailer is a long-lived reader of one serial port. Run blocks until ctx
// is cancelled, reconnecting on errors so an unplugged device doesn't
// kill the goroutine.
type Tailer struct {
	Device string
	Writer io.Writer
	Logger *log.Logger

	connected atomic.Bool
}

// Connected reports whether the tailer currently has the device open. The
// MCP /firmware-logs handler surfaces this so callers can distinguish
// "device unplugged" from "no logs yet".
func (t *Tailer) Connected() bool { return t.connected.Load() }

// Run owns the reconnect loop. Each open attempt either succeeds (we read
// lines until EOF or ctx) or fails (we wait with capped backoff). Logs go
// to t.Logger; nothing returns to the caller.
func (t *Tailer) Run(ctx context.Context) {
	if t.Device == "" {
		return
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := t.tailOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && t.Logger != nil {
			t.Logger.Printf("serial: %s: %v (retry in %s)", t.Device, err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (t *Tailer) tailOnce(ctx context.Context) error {
	// O_NOCTTY prevents the tty from becoming our controlling terminal.
	// O_NONBLOCK lets Open return immediately even if the port's modem
	// status isn't asserted; we clear it right after via fcntl so reads
	// block normally.
	f, err := os.OpenFile(t.Device, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	fd := int(f.Fd())
	if err := setRaw(fd); err != nil {
		return err
	}
	// Drop O_NONBLOCK so subsequent reads are blocking again — saves a
	// busy-loop on the bufio reader.
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}

	t.connected.Store(true)
	defer t.connected.Store(false)
	if t.Logger != nil {
		t.Logger.Printf("serial: tailing %s", t.Device)
	}

	// Close the fd when ctx is cancelled so the blocking read unblocks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = f.Close()
		case <-done:
		}
	}()

	br := bufio.NewReader(f)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			t.writeLine(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return err
			}
			return err
		}
	}
}

func (t *Tailer) writeLine(raw string) {
	// Strip CRLF and ANSI escapes; add a single trailing '\n' so logbuf
	// stores one entry per line.
	clean := ansiCSI.ReplaceAllString(raw, "")
	clean = strings.TrimRight(clean, "\r\n")
	if clean == "" {
		return
	}
	_, _ = io.WriteString(t.Writer, clean+"\n")
}

// setRaw puts the tty in non-canonical, no-echo mode. We don't touch baud
// because USB-CDC ignores it anyway.
func setRaw(fd int) error {
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	// cfmakeraw equivalent.
	tio.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	tio.Oflag &^= unix.OPOST
	tio.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	tio.Cflag &^= unix.CSIZE | unix.PARENB
	tio.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	// VMIN=1, VTIME=0 — block until at least one byte arrives.
	tio.Cc[unix.VMIN] = 1
	tio.Cc[unix.VTIME] = 0
	return unix.IoctlSetTermios(fd, unix.TCSETS, tio)
}
