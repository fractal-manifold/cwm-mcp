// Package auth implements the HMAC-SHA256 request signing scheme shared
// between the cwm broker and the ESP32 firmware, plus a small TTL nonce
// cache used to reject replays.
//
// Signature input is canonicalised (v2) as:
//
//	HMAC-SHA256(psk,
//	  "<METHOD>\n<PATH>\n<TIMESTAMP>\n<NONCE>\n<DEVICE>\n<VERSION>")
//
// emitted as lowercase hex. DEVICE and VERSION are the X-Cwm-Device and
// X-Cwm-Config-Version header values verbatim, or the empty string when
// the header is absent. The firmware computes the same string before
// every poll, so any drift in this file must be mirrored there.
//
// See compat/HMAC_CANONICAL.md for the contract and
// compat/vectors/hmac.json for the test vectors every implementation
// must reproduce byte-for-byte.
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
// lowercase hex. Pass the empty string for `device` and/or `configVersion`
// when the corresponding header is not sent — empty strings still
// contribute their trailing "\n" separators, so the result is distinct
// from the deprecated v1 form.
func ComputeSignature(psk []byte, method, path, ts, nonce, device, configVersion string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nonce))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(device))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(configVersion))
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
// to the client — log internally instead. Pass deviceHeader/configVersionHeader
// from r.Header.Get(...) verbatim — empty string when absent.
func Verify(
	psk []byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader string,
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
	expected := ComputeSignature(psk, method, path, tsHeader, nonceLC, deviceHeader, configVersionHeader)
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

// VerifyResult tells the caller which PSK satisfied the signature.
// PSKIndex is the position in the slice passed to VerifyMulti; the
// broker uses it to spot a "device signed with pending PSK" event and
// trigger registry.MaybePromote.
type VerifyResult struct {
	PSKIndex int
}

// VerifyMulti tries each PSK in order and returns the first one whose
// signature matches. Shape checks (timestamp present and parseable,
// nonce hex32, skew within window) run once; the per-PSK loop only
// retries the HMAC comparison. The replay nonce is consumed only after
// a PSK matched, so probing the wrong PSK does not burn the slot for
// the eventual right one. If every PSK is rejected, returns
// ErrBadSignature. A nil or empty `psks` slice returns ErrBadSignature.
func VerifyMulti(
	psks [][]byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader string,
	cache *NonceCache,
	maxSkew time.Duration,
	now time.Time,
) (VerifyResult, error) {
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return VerifyResult{}, ErrMissingHeaders
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return VerifyResult{}, ErrBadTimestamp
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return VerifyResult{}, ErrTimestampSkew
	}
	if !isHex32(nonceHeader) {
		return VerifyResult{}, ErrBadNonceFormat
	}
	nonceLC := strings.ToLower(nonceHeader)
	sigLC := strings.ToLower(sigHeader)

	matchedIdx := -1
	for i, psk := range psks {
		if len(psk) == 0 {
			continue
		}
		expected := ComputeSignature(psk, method, path, tsHeader, nonceLC, deviceHeader, configVersionHeader)
		if hmac.Equal([]byte(sigLC), []byte(expected)) {
			matchedIdx = i
			break
		}
	}
	if matchedIdx < 0 {
		return VerifyResult{}, ErrBadSignature
	}
	if !cache.CheckAndAdd(nonceLC, now) {
		return VerifyResult{}, ErrNonceReplay
	}
	return VerifyResult{PSKIndex: matchedIdx}, nil
}
