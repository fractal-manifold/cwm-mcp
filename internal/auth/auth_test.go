package auth

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func mustPSK() []byte {
	return []byte("psk-32-bytes-of-secret-material!")
}

func TestVerify_HappyPath(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce)

	if err := Verify(psk, "GET", "/credentials", ts, nonce, sig, cache, time.Minute, now); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerify_MissingHeaders(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Now()
	err := Verify(mustPSK(), "GET", "/credentials", "", "abc", "def", cache, time.Minute, now)
	if !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("expected ErrMissingHeaders, got %v", err)
	}
}

func TestVerify_BadTimestamp(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	err := Verify(mustPSK(), "GET", "/credentials", "not-a-number",
		"0123456789abcdef0123456789abcdef", "deadbeef",
		cache, time.Minute, time.Now())
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("expected ErrBadTimestamp, got %v", err)
	}
}

func TestVerify_TimestampSkew(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	oldTS := strconv.FormatInt(now.Unix()-120, 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(mustPSK(), "GET", "/credentials", oldTS, nonce)

	err := Verify(mustPSK(), "GET", "/credentials", oldTS, nonce, sig, cache, time.Minute, now)
	if !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew, got %v", err)
	}
}

func TestVerify_BadNonceFormat(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	err := Verify(mustPSK(), "GET", "/credentials", ts, "not-hex", "anything",
		cache, time.Minute, now)
	if !errors.Is(err, ErrBadNonceFormat) {
		t.Fatalf("expected ErrBadNonceFormat, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	wrongSig := "deadbeef"
	err := Verify(mustPSK(), "GET", "/credentials", ts, nonce, wrongSig,
		cache, time.Minute, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_NonceReplay(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce)

	if err := Verify(psk, "GET", "/credentials", ts, nonce, sig, cache, time.Minute, now); err != nil {
		t.Fatalf("first call: %v", err)
	}
	err := Verify(psk, "GET", "/credentials", ts, nonce, sig, cache, time.Minute, now)
	if !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("expected ErrNonceReplay on second call, got %v", err)
	}
}

func TestNonceCache_ReapAfterTTL(t *testing.T) {
	cache := NewNonceCache(30 * time.Second)
	t0 := time.Unix(1700000000, 0)
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !cache.CheckAndAdd(nonce, t0) {
		t.Fatal("first insert should succeed")
	}
	if !cache.CheckAndAdd(nonce, t0.Add(31*time.Second)) {
		t.Fatal("expected reuse after TTL, got replay")
	}
}

func TestComputeSignature_KnownVector(t *testing.T) {
	// Hand-computed reference, kept identical to service-go for interop.
	// $ printf 'GET\n/credentials\n100\nN' | openssl dgst -sha256 -hmac 'key' -hex
	psk := []byte("key")
	got := ComputeSignature(psk, "GET", "/credentials", "100", "N")
	want := "f85423c8d31953c2683b223abf28df18c7019b63b7a1dd684a6afacf7f3704e0"
	if got != want {
		t.Fatalf("signature mismatch:\n  got  %s\n  want %s", got, want)
	}
}
