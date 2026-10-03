// Package vault is a client for the APS Vault machine API (service tokens).
// Standard library only, Go 1.20+.
//
//	v, err := vault.New("https://vault.example.com", os.Getenv("VAULT_TOKEN"))
//	pw, err := v.Get(ctx, "db-password")
//
// Values are cached for TTL (default 5 min); when the vault is unreachable a stale cached
// value is returned (FailOpenCache), so a vault restart does not take the service down.
// Retries 429/5xx/network errors with 1s/2s/4s back-off. Nothing is logged.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "0.11.0"

// Secret is the machine-API response for one secret.
type Secret struct {
	Name      string  `json:"name"`
	Value     string  `json:"value"`
	Login     string  `json:"login,omitempty"`
	Notes     string  `json:"notes,omitempty"`
	TOTP      *string `json:"totp,omitempty"`
	UpdatedAt string  `json:"updated_at"`
}

// Error is an HTTP-level error from the vault.
type Error struct {
	Status int
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("vault: HTTP %d %s", e.Status, e.Detail) }

// Options tune the client; zero values mean defaults.
type Options struct {
	CacheTTL      time.Duration // default 5m; negative disables
	Timeout       time.Duration // default 5s
	MaxRetries    int           // default 3
	FailOpenCache *bool         // default true
	HTTPClient    *http.Client
}

type entry struct {
	sec Secret
	exp time.Time
}

// Client talks to one vault with one service token.
type Client struct {
	base, token string
	ttl         time.Duration
	retries     int
	failOpen    bool
	http        *http.Client
	mu          sync.Mutex
	cache       map[string]entry
}

// New validates the token shape and returns a client.
func New(baseURL, token string, opts ...Options) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("vault: base URL required")
	}
	if !strings.HasPrefix(token, "vlt_") {
		return nil, errors.New("vault: a service token (vlt_…) is required, not a master password")
	}
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	c := &Client{base: strings.TrimRight(baseURL, "/"), token: token, ttl: 5 * time.Minute,
		retries: 3, failOpen: true, cache: map[string]entry{}}
	if o.CacheTTL != 0 {
		c.ttl = o.CacheTTL
	}
	if o.MaxRetries != 0 {
		c.retries = o.MaxRetries
	}
	if o.FailOpenCache != nil {
		c.failOpen = *o.FailOpenCache
	}
	timeout := 5 * time.Second
	if o.Timeout != 0 {
		timeout = o.Timeout
	}
	c.http = o.HTTPClient
	if c.http == nil {
		c.http = &http.Client{Timeout: timeout}
	}
	return c, nil
}

// FromEnv reads VAULT_URL and VAULT_TOKEN (or VAULT_TOKEN_FILE).
func FromEnv(opts ...Options) (*Client, error) {
	tok := os.Getenv("VAULT_TOKEN")
	if tok == "" {
		if f := os.Getenv("VAULT_TOKEN_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			tok = strings.TrimSpace(string(b))
		}
	}
	return New(os.Getenv("VAULT_URL"), tok, opts...)
}

// Get returns the secret value.
func (c *Client) Get(ctx context.Context, name string) (string, error) {
	s, err := c.GetFull(ctx, name)
	if err != nil {
		return "", err
	}
	return s.Value, nil
}

// GetVersion returns an older value by its version number (e.g. the previous encryption key
// while files encrypted with it are still being re-wrapped). version 0 = current.
func (c *Client) GetVersion(ctx context.Context, name string, version int) (string, error) {
	s, err := c.GetFullVersion(ctx, name, version)
	if err != nil {
		return "", err
	}
	return s.Value, nil
}

// GetFull returns the whole record (login/notes/totp depend on token grants).
func (c *Client) GetFull(ctx context.Context, name string) (Secret, error) { return c.GetFullVersion(ctx, name, 0) }

// GetFullVersion is GetFull for a specific version (0 = current).
func (c *Client) GetFullVersion(ctx context.Context, name string, version int) (Secret, error) {
	if name == "" {
		return Secret{}, errors.New("vault: name required")
	}
	key := name
	path := "/api/v1/m/secret/" + url.PathEscape(name)
	if version > 0 {
		key = fmt.Sprintf("%s@%d", name, version)
		path += fmt.Sprintf("?version=%d", version)
	}
	c.mu.Lock()
	hit, ok := c.cache[key]
	c.mu.Unlock()
	if ok && time.Now().Before(hit.exp) {
		return hit.sec, nil
	}
	var s Secret
	err := c.do(ctx, http.MethodGet, path, nil, &s)
	if err != nil {
		var he *Error
		transient := !errors.As(err, &he) || he.Status == 429 || he.Status >= 500
		if ok && c.failOpen && transient {
			return hit.sec, nil
		}
		return Secret{}, err
	}
	if c.ttl > 0 {
		c.mu.Lock()
		c.cache[key] = entry{s, time.Now().Add(c.ttl)}
		c.mu.Unlock()
	}
	return s, nil
}

// Put creates or updates a secret in the token's folder (token needs can_write).
func (c *Client) Put(ctx context.Context, name, value string, login, tags, link string) error {
	body := map[string]string{"value": value, "login": login, "tags": tags, "url": link}
	err := c.do(ctx, http.MethodPost, "/api/v1/m/secret/"+url.PathEscape(name), body, nil)
	c.mu.Lock()
	delete(c.cache, name)
	c.mu.Unlock()
	return err
}

// List returns names and metadata of secrets in scope (no values).
func (c *Client) List(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.do(ctx, http.MethodGet, "/api/v1/m/secrets", nil, &out)
}

// Health checks the token and reports its scope.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/api/v1/m/health", nil, &out)
}

// ClearCache drops cached values (call after a known rotation).
func (c *Client) ClearCache() {
	c.mu.Lock()
	c.cache = map[string]entry{}
	c.mu.Unlock()
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	var last error
	for attempt := 0; attempt <= c.retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "aps-vault-go/"+Version)
		resp, err := c.http.Do(req)
		if err != nil {
			last = err
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode/100 == 2 {
					if out != nil {
						last = json.NewDecoder(resp.Body).Decode(out)
					} else {
						last = nil
					}
					return
				}
				var d struct {
					Detail any `json:"detail"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&d)
				last = &Error{Status: resp.StatusCode, Detail: fmt.Sprint(d.Detail)}
			}()
			var he *Error
			if last == nil || (errors.As(last, &he) && he.Status != 429 && he.Status < 500) {
				return last
			}
		}
		if attempt < c.retries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
	}
	return fmt.Errorf("vault: request failed after %d attempts: %w", c.retries+1, last)
}
