package creds

import (
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
