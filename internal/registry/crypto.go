package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// PendingNonceLen is the size of the random nonce that prefixes every
// encrypted pending payload. AES-CTR needs an IV the size of the block
// (16 bytes); a fresh one per encryption call guarantees that
// re-encrypting the same payload after a registry edit produces a
// different ciphertext, eliminating the catastrophic AES-CTR
// nonce-reuse failure mode.
const PendingNonceLen = aes.BlockSize

// EncryptPending encrypts `plaintext` with AES-CTR using `key` (must be
// 32 bytes — the device's active PSK). Returns the random nonce and the
// ciphertext separately so the broker can serialise them as distinct
// JSON fields. The plaintext is never logged; callers should treat it
// as secret.
func EncryptPending(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	nonce = make([]byte, PendingNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("registry/crypto: rand: %w", err)
	}
	ciphertext = make([]byte, len(plaintext))
	cipher.NewCTR(block, nonce).XORKeyStream(ciphertext, plaintext)
	return nonce, ciphertext, nil
}

// DecryptPending reverses EncryptPending. AES-CTR is malleable on its
// own (no auth tag); callers MUST rely on the HMAC of the surrounding
// HTTP response — not on this function — to detect tampering.
func DecryptPending(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != PendingNonceLen {
		return nil, fmt.Errorf("registry/crypto: nonce must be %d bytes, got %d", PendingNonceLen, len(nonce))
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("registry/crypto: empty ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCTR(block, nonce).XORKeyStream(out, ciphertext)
	return out, nil
}
