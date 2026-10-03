// Package vault is a client for the APS Vault machine API (service tokens).
// Standard library only, Go 1.20+.
//
//	v, err := vault.New("https://vault.example.com", os.Getenv("VAULT_TOKEN"))
//	pw, err := v.Get(ctx, "db-password")
//
// Values are cached for TTL (default 5 min); when the vault is unreachable a stale cached
// value is returned (FailOpenCache), so a vault restart does not take the service down.
// Retries 429/5xx/network errors with 1s/2s/4s back-off. Nothing is logged.
//
// Sealed delivery (0.17): a token bound to this application's X25519 public key gets values
// encrypted to that key; set Options.ClientPrivateKey (base64 raw 32 bytes, or VAULT_CLIENT_KEY)
// and the client decrypts in-process. GenerateKeyPair makes the pair.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

const Version = "0.17.1"

// SealedAlg is the only envelope algorithm the vault emits (sealed.py).
const SealedAlg = "X25519-HKDF-SHA256-AES256GCM"

var sealedInfo = []byte("aps-vault/sealed/v1")

// SealedEnvelope is the `sealed` object of GET /api/v1/m/secret/{name} for a key-bound token.
type SealedEnvelope struct {
	Alg   string `json:"alg"`
	V     int    `json:"v"`
	EPK   string `json:"epk"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// Secret is the machine-API response for one secret. Sealed is nil after a successful
// decryption (the fields hold the payload) and is never returned non-nil by Get*.
type Secret struct {
	Name      string          `json:"name"`
	Value     string          `json:"value"`
	Login     string          `json:"login,omitempty"`
	Notes     string          `json:"notes,omitempty"`
	TOTP      *string         `json:"totp,omitempty"`
	Version   int             `json:"version,omitempty"`
	UpdatedAt string          `json:"updated_at"`
	Sealed    *SealedEnvelope `json:"sealed,omitempty"`
}

// GenerateKeyPair returns (privateB64, publicB64): raw 32-byte X25519 keys in standard base64.
// Give the public half to the vault administrator (token field client_public_key); keep the
// private half with the token.
func GenerateKeyPair() (string, string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// hkdfSHA256 is RFC 5869 with an all-zero salt (what the vault uses), expanded to n bytes.
func hkdfSHA256(ikm, info []byte, n int) []byte {
	ext := hmac.New(sha256.New, make([]byte, sha256.Size))
	ext.Write(ikm)
	prk := ext.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// Unseal opens a sealed envelope with the application's private key; name is the secret's name
// (the envelope's AAD). Returns the payload: value, login, notes, totp as granted.
func Unseal(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
	if env.Alg != SealedAlg || env.V != 1 {
		return nil, fmt.Errorf("vault: unsupported sealed envelope %q v%d", env.Alg, env.V)
	}
	skb, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("vault: client private key is not base64: %w", err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(skb)
	if err != nil {
		return nil, fmt.Errorf("vault: client private key: %w", err)
	}
	epkb, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	epk, err := ecdh.X25519().NewPublicKey(epkb)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	shared, err := sk.ECDH(epk)
	if err != nil {
		return nil, err
	}
	info := append(append(append([]byte{}, sealedInfo...), epkb...), sk.PublicKey().Bytes()...)
	block, err := aes.NewCipher(hkdfSHA256(shared, info, 32))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope ct: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, errors.New("vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)")
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
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
	// ClientPrivateKey opens sealed values (base64 raw X25519 private key); default VAULT_CLIENT_KEY.
	ClientPrivateKey string
}

type entry struct {
	sec Secret
	exp time.Time
}

// Client talks to one vault with one service token.
type Client struct {
	base, token string
	clientKey   string
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
		retries: 3, failOpen: true, cache: map[string]entry{}, clientKey: o.ClientPrivateKey}
	if c.clientKey == "" {
		c.clientKey = os.Getenv("VAULT_CLIENT_KEY")
	}
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
func (c *Client) GetFull(ctx context.Context, name string) (Secret, error) {
	return c.GetFullVersion(ctx, name, 0)
}

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
	if s.Sealed != nil {
		if c.clientKey == "" {
			return Secret{}, errors.New("vault: this token delivers sealed values — set Options.ClientPrivateKey (or VAULT_CLIENT_KEY)")
		}
		n := s.Name
		if n == "" {
			n = name
		}
		m, err := Unseal(*s.Sealed, c.clientKey, n)
		if err != nil {
			return Secret{}, err
		}
		s.Sealed = nil
		s.Value, _ = m["value"].(string)
		s.Login, _ = m["login"].(string)
		s.Notes, _ = m["notes"].(string)
		if t, ok := m["totp"].(string); ok {
			s.TOTP = &t
		}
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
