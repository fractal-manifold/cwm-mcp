package creds

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var ErrCodexNoAccount = errors.New("codex auth.json missing account_id")

// CodexStored is the subset of ~/.codex/auth.json the firmware needs for
// ChatGPT's wham/usage endpoint: Bearer token plus ChatGPT-Account-Id.
type CodexStored struct {
	AccessToken     string
	AccountID       string
	ExpiresAtUnixMS int64
}

func (s CodexStored) ExpiresAtISO() string {
	t := time.UnixMilli(s.ExpiresAtUnixMS).UTC()
	return t.Format("2006-01-02T15:04:05.000Z")
}

func (s CodexStored) IsExpired(now time.Time) bool {
	return now.UnixMilli() >= s.ExpiresAtUnixMS
}

type codexAuthDoc struct {
	Tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		AccountID   string `json:"account_id"`
	} `json:"tokens"`

	AccessTokenFlat string          `json:"access_token"`
	IDTokenFlat     string          `json:"id_token"`
	AccountIDFlat   string          `json:"account_id"`
	ExpiresAtRaw    json.RawMessage `json:"expires_at"`
}

// LoadCodex accepts the two auth.json shapes seen from the Codex CLI:
// newer builds nest token/id under "tokens"; older builds place them at
// the root. expires_at may be ISO-8601, epoch seconds, or epoch ms.
func LoadCodex(path string) (*CodexStored, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrFileMissing, path)
		}
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	var doc codexAuthDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	tok := doc.Tokens.AccessToken
	if tok == "" {
		tok = doc.AccessTokenFlat
	}
	if tok == "" {
		return nil, fmt.Errorf("%w: missing access_token", ErrParse)
	}
	aid := doc.Tokens.AccountID
	if aid == "" {
		aid = doc.AccountIDFlat
	}
	if aid == "" {
		return nil, fmt.Errorf("%w: %w", ErrParse, ErrCodexNoAccount)
	}
	expMS, err := parseExpiresAt(doc.ExpiresAtRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at: %v", ErrParse, err)
	}
	if expMS == 0 {
		expMS = jwtExpiresAtMS(tok)
	}
	if expMS == 0 {
		idTok := doc.Tokens.IDToken
		if idTok == "" {
			idTok = doc.IDTokenFlat
		}
		expMS = jwtExpiresAtMS(idTok)
	}
	if expMS == 0 {
		return nil, fmt.Errorf("%w: missing expires_at or JWT exp", ErrParse)
	}
	return &CodexStored{
		AccessToken:     tok,
		AccountID:       aid,
		ExpiresAtUnixMS: expMS,
	}, nil
}

func parseExpiresAt(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, err
		}
		if s == "" {
			return 0, nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t, err = time.Parse(time.RFC3339, s)
			if err != nil {
				return 0, err
			}
		}
		return t.UTC().UnixMilli(), nil
	}

	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil {
			return 0, err
		}
		v = int64(f)
	}
	if v < 1_000_000_000_000 {
		v *= 1000
	}
	return v, nil
}

func jwtExpiresAtMS(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var doc struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil || doc.Exp == "" {
		return 0
	}
	v, err := strconv.ParseInt(string(doc.Exp), 10, 64)
	if err != nil {
		f, ferr := doc.Exp.Float64()
		if ferr != nil {
			return 0
		}
		v = int64(f)
	}
	if v < 1_000_000_000_000 {
		v *= 1000
	}
	return v
}
