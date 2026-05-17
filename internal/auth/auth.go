// Package auth implements the HMAC-SHA256 request signing scheme shared
// between the cwm broker and the ESP32 firmware, plus a small TTL nonce
// cache used to reject replays.
//
// Signature input is canonicalised as:
//
//	HMAC-SHA256(psk, "<METHOD>\n<PATH>\n<TIMESTAMP>\n<NONCE>")
//
// emitted as lowercase hex. The firmware computes the same string before
// every poll, so any drift in this file must be mirrored there.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NonceCache tracks nonces seen within the TTL window. Reaping is lazy on each
// insertion. Concurrent callers (one per HTTP request) are serialised by the
// mutex — the TTL window is short and the cache stays tiny.
type NonceCache struct {
	ttl  time.Duration
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, seen: make(map[string]time.Time)}
}

// CheckAndAdd records `nonce`. Returns true on first sight, false on replay.
func (c *NonceCache) CheckAndAdd(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reap(now)
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = now
	return true
}

func (c *NonceCache) reap(now time.Time) {
	cutoff := now.Add(-c.ttl)
	for n, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, n)
		}
	}
}

// ComputeSignature reproduces the canonical request signature returned as
// lowercase hex.
func ComputeSignature(psk []byte, method, path, ts, nonce string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

var (
	ErrMissingHeaders = errors.New("missing headers")
	ErrBadTimestamp   = errors.New("bad timestamp")
	ErrTimestampSkew  = errors.New("timestamp skew")
	ErrBadNonceFormat = errors.New("bad nonce format")
	ErrBadSignature   = errors.New("bad signature")
	ErrNonceReplay    = errors.New("nonce replay")
)

// Verify checks an incoming request's auth headers against the shared PSK.
// All non-nil error returns are reasons to reject with 401; never surface them
// to the client — log internally instead.
func Verify(
	psk []byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader string,
	cache *NonceCache,
	maxSkew time.Duration,
	now time.Time,
) error {
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return ErrMissingHeaders
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return ErrTimestampSkew
	}
	if !isHex32(nonceHeader) {
		return ErrBadNonceFormat
	}
	nonceLC := strings.ToLower(nonceHeader)
	expected := ComputeSignature(psk, method, path, strconv.FormatInt(ts, 10), nonceLC)
	if !hmac.Equal([]byte(strings.ToLower(sigHeader)), []byte(expected)) {
		return ErrBadSignature
	}
	if !cache.CheckAndAdd(nonceLC, now) {
		return ErrNonceReplay
	}
	return nil
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
