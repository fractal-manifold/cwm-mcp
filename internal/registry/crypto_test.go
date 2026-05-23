package registry

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptPending_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	plaintext := []byte(`{"version":8,"city":"Tokyo","psk_hex":"abcd..."}`)

	nonce, ct, err := EncryptPending(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptPending: %v", err)
	}
	if len(nonce) != PendingNonceLen {
		t.Errorf("nonce length = %d, want %d", len(nonce), PendingNonceLen)
	}
	if bytes.Equal(ct, plaintext) {
		t.Error("ciphertext equals plaintext")
	}

	got, err := DecryptPending(key, nonce, ct)
	if err != nil {
		t.Fatalf("DecryptPending: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted mismatch:\n got=%q\nwant=%q", got, plaintext)
	}
}

func TestEncryptPending_FreshNonceEachCall(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	pt := []byte("same plaintext every time")

	n1, c1, err := EncryptPending(key, pt)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	n2, c2, err := EncryptPending(key, pt)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Error("nonces collided — AES-CTR with the same key+nonce on different plaintexts leaks XOR")
	}
	if bytes.Equal(c1, c2) {
		t.Error("ciphertexts identical despite different nonces")
	}
}

func TestDecryptPending_WrongKeyReturnsGarbage(t *testing.T) {
	key := make([]byte, 32)
	wrong := make([]byte, 32)
	rand.Read(key)
	rand.Read(wrong)
	pt := []byte("the real payload, plenty of entropy here 0123456789")

	nonce, ct, err := EncryptPending(key, pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptPending(wrong, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt should still succeed mechanically: %v", err)
	}
	if bytes.Equal(got, pt) {
		t.Error("wrong key produced the right plaintext (entropy ~0)")
	}
}

func TestEncryptPending_KeyLengthEnforced(t *testing.T) {
	if _, _, err := EncryptPending(make([]byte, 16), []byte("x")); err == nil {
		t.Error("expected error for short key")
	}
	if _, err := DecryptPending(make([]byte, 16), make([]byte, PendingNonceLen), []byte("x")); err == nil {
		t.Error("expected error for short key")
	}
	if _, err := DecryptPending(make([]byte, 32), make([]byte, 8), []byte("x")); err == nil {
		t.Error("expected error for short nonce")
	}
}
