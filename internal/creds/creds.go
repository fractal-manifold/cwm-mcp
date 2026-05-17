// Package creds reads the OAuth credentials file written by the Claude CLI
// (`~/.claude/.credentials.json` by default) and exposes the bits the broker
// needs to hand to the device.
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	ErrFileMissing = errors.New("credentials file missing")
	ErrParse       = errors.New("credentials parse error")
)

// Stored is the subset of the on-disk credentials we hand to the device.
type Stored struct {
	AccessToken     string
	ExpiresAtUnixMS int64
}

func (s Stored) ExpiresAtISO() string {
	t := time.UnixMilli(s.ExpiresAtUnixMS).UTC()
	return t.Format("2006-01-02T15:04:05.000Z")
}

func (s Stored) IsExpired(now time.Time) bool {
	return now.UnixMilli() >= s.ExpiresAtUnixMS
}

// Load parses the on-disk JSON written by the Claude CLI:
//
//	{"claudeAiOauth": {"accessToken": "...", "expiresAt": <ms>, ...}}
func Load(path string) (*Stored, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrFileMissing, path)
		}
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	var doc struct {
		ClaudeAIOauth struct {
			AccessToken string `json:"accessToken"`
			ExpiresAt   int64  `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	if doc.ClaudeAIOauth.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing or invalid 'accessToken'", ErrParse)
	}
	if doc.ClaudeAIOauth.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: missing or invalid 'expiresAt'", ErrParse)
	}
	return &Stored{
		AccessToken:     doc.ClaudeAIOauth.AccessToken,
		ExpiresAtUnixMS: doc.ClaudeAIOauth.ExpiresAt,
	}, nil
}
