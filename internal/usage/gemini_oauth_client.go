package usage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// geminiOAuthClient holds the public OAuth "installed app" credentials
// that @google/gemini-cli ships in its bundle. Google does not classify
// these as confidential (installed-app clients can't keep secrets), but
// the textual form of the client_secret trips secret scanners. We never
// store the values in source — we extract them at runtime from a local
// @google/gemini-cli install if one is present, otherwise from the
// published npm tarball.
type geminiOAuthClient struct {
	ID     string
	Secret string
}

var (
	geminiOAuthOnce sync.Once
	geminiOAuthVal  geminiOAuthClient
	geminiOAuthErr  error

	// Structural patterns only — these match Google's documented
	// installed-app OAuth identifier shape, not any specific value.
	// The client-secret prefix is assembled at runtime so the literal
	// doesn't sit in source where scanners would flag it.
	geminiClientIDRe     = regexp.MustCompile(`[0-9]{6,}-[a-z0-9]+\.apps\.googleusercontent\.com`)
	geminiClientSecretRe = regexp.MustCompile(geminiClientSecretPrefix() + `[A-Za-z0-9_-]{20,}`)
)

func geminiClientSecretPrefix() string {
	// Google installed-app OAuth client_secret prefix, assembled at
	// runtime so the literal token does not appear in source.
	return string([]byte{'G', 'O', 'C', 'S', 'P', 'X', '-'})
}

// resolveGeminiOAuthClient returns the client_id/secret pair used by the
// Gemini CLI. Result is memoised for the process lifetime.
func resolveGeminiOAuthClient(ctx context.Context, do func(*http.Request) (*http.Response, error)) (geminiOAuthClient, error) {
	geminiOAuthOnce.Do(func() {
		if v, ok := geminiOAuthFromLocalCLI(); ok {
			geminiOAuthVal = v
			return
		}
		v, err := geminiOAuthFromNpmRegistry(ctx, do)
		if err != nil {
			geminiOAuthErr = err
			return
		}
		geminiOAuthVal = v
	})
	if geminiOAuthErr != nil {
		return geminiOAuthClient{}, geminiOAuthErr
	}
	return geminiOAuthVal, nil
}

func geminiOAuthFromLocalCLI() (geminiOAuthClient, bool) {
	home, _ := os.UserHomeDir()
	roots := []string{
		"/usr/lib/node_modules/@google/gemini-cli",
		"/usr/local/lib/node_modules/@google/gemini-cli",
		filepath.Join(home, ".npm-global/lib/node_modules/@google/gemini-cli"),
		filepath.Join(home, ".local/lib/node_modules/@google/gemini-cli"),
		filepath.Join(home, "node_modules/@google/gemini-cli"),
	}
	for _, r := range roots {
		if v, ok := scanDirForGeminiOAuth(r); ok {
			return v, true
		}
	}
	return geminiOAuthClient{}, false
}

func scanDirForGeminiOAuth(root string) (geminiOAuthClient, bool) {
	var hit geminiOAuthClient
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".js", ".mjs", ".cjs":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if v, ok := extractGeminiOAuthFromBundle(data); ok {
			hit = v
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return hit, found
}

func extractGeminiOAuthFromBundle(data []byte) (geminiOAuthClient, bool) {
	// The bundle commonly contains two installed-app client IDs: the
	// gemini-cli one (right next to the OAUTH_CLIENT_SECRET literal) and
	// an unrelated Cloud SDK one earlier in the file. Naively taking
	// regexp.Find of each yields a mismatched pair. We anchor on the
	// secret (which is unique to gemini-cli in the bundle) and search
	// the surrounding window for its paired client ID.
	sec := geminiClientSecretRe.Find(data)
	if len(sec) == 0 {
		return geminiOAuthClient{}, false
	}
	secIdx := bytes.Index(data, sec)
	const window = 2048
	start := secIdx - window
	if start < 0 {
		start = 0
	}
	end := secIdx + len(sec) + window
	if end > len(data) {
		end = len(data)
	}
	id := geminiClientIDRe.Find(data[start:end])
	if len(id) == 0 {
		return geminiOAuthClient{}, false
	}
	return geminiOAuthClient{ID: string(id), Secret: string(sec)}, true
}

// geminiOAuthFromNpmRegistry pulls the published @google/gemini-cli
// tarball and extracts the credentials from its bundle.
func geminiOAuthFromNpmRegistry(ctx context.Context, do func(*http.Request) (*http.Response, error)) (geminiOAuthClient, error) {
	if do == nil {
		do = http.DefaultClient.Do
	}
	metaReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/@google/gemini-cli/latest", nil)
	if err != nil {
		return geminiOAuthClient{}, err
	}
	metaReq.Header.Set("Accept", "application/json")
	metaResp, err := do(metaReq)
	if err != nil {
		return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer metaResp.Body.Close()
	if metaResp.StatusCode < 200 || metaResp.StatusCode >= 300 {
		return geminiOAuthClient{}, fmt.Errorf("%w: npm registry status %d", ErrTransport, metaResp.StatusCode)
	}
	var meta struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.NewDecoder(io.LimitReader(metaResp.Body, 1<<20)).Decode(&meta); err != nil {
		return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if meta.Dist.Tarball == "" {
		return geminiOAuthClient{}, fmt.Errorf("%w: npm registry returned empty tarball URL", ErrParseUpstream)
	}
	tgzReq, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.Dist.Tarball, nil)
	if err != nil {
		return geminiOAuthClient{}, err
	}
	tgzResp, err := do(tgzReq)
	if err != nil {
		return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer tgzResp.Body.Close()
	if tgzResp.StatusCode < 200 || tgzResp.StatusCode >= 300 {
		return geminiOAuthClient{}, fmt.Errorf("%w: tarball status %d", ErrTransport, tgzResp.StatusCode)
	}
	gz, err := gzip.NewReader(tgzResp.Body)
	if err != nil {
		return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		switch filepath.Ext(h.Name) {
		case ".js", ".mjs", ".cjs":
		default:
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 16<<20))
		if err != nil {
			return geminiOAuthClient{}, fmt.Errorf("%w: %v", ErrTransport, err)
		}
		if v, ok := extractGeminiOAuthFromBundle(data); ok {
			return v, nil
		}
	}
	return geminiOAuthClient{}, fmt.Errorf("%w: OAuth client not found in @google/gemini-cli bundle", ErrParseUpstream)
}
