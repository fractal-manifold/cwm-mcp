package creds

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Happy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(p,
		[]byte(`{"claudeAiOauth":{"accessToken":"tok","expiresAt":1700000000000}}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "tok" {
		t.Errorf("token: %q", c.AccessToken)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Errorf("expires_at: %d", c.ExpiresAtUnixMS)
	}
}

func TestLoad_Missing(t *testing.T) {
	_, err := Load("/nonexistent/path/credentials.json")
	if !errors.Is(err, ErrFileMissing) {
		t.Fatalf("expected ErrFileMissing, got %v", err)
	}
}

func TestLoad_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte("not json"), 0600)
	_, err := Load(p)
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}

func TestLoad_MissingFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte(`{"claudeAiOauth":{}}`), 0600)
	_, err := Load(p)
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}

func TestStored_IsExpired(t *testing.T) {
	c := Stored{ExpiresAtUnixMS: 1000}
	if !c.IsExpired(time.UnixMilli(2000)) {
		t.Error("expected expired at 2000ms")
	}
	if c.IsExpired(time.UnixMilli(500)) {
		t.Error("not yet expired at 500ms")
	}
}

func TestLoadCodex_HappyNested(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(p,
		[]byte(`{"tokens":{"access_token":"tok","account_id":"acct"},"expires_at":"2026-01-02T03:04:05Z"}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "tok" || c.AccountID != "acct" {
		t.Fatalf("codex creds = %+v", c)
	}
	if c.ExpiresAtISO() != "2026-01-02T03:04:05.000Z" {
		t.Fatalf("expires = %s", c.ExpiresAtISO())
	}
}

func TestLoadCodex_HappyFlatEpochSeconds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(p,
		[]byte(`{"access_token":"tok","account_id":"acct","expires_at":1700000000}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Fatalf("expires ms = %d", c.ExpiresAtUnixMS)
	}
}

func TestLoadCodex_ExpiresFromJWT(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1700000000}`))
	jwt := header + "." + payload + ".sig"
	body := `{"tokens":{"access_token":"` + jwt + `","account_id":"acct"}}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Fatalf("expires ms = %d", c.ExpiresAtUnixMS)
	}
}

func TestLoadCodex_MissingAccount(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	os.WriteFile(p, []byte(`{"access_token":"tok","expires_at":1700000000}`), 0600)
	_, err := LoadCodex(p)
	if !errors.Is(err, ErrParse) || !errors.Is(err, ErrCodexNoAccount) {
		t.Fatalf("expected ErrParse wrapping ErrCodexNoAccount, got %v", err)
	}
}
