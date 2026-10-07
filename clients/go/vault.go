// Package vault is a client for the APS Vault machine API (service tokens).
// Standard library only, Go 1.24+ (crypto/mlkem).
//
//	v, err := vault.New("https://vault.example.com", os.Getenv("VAULT_TOKEN"))
//	pw, err := v.Get(ctx, "db-password")
//
// Values are cached for TTL (default 5 min); when the vault is unreachable a stale cached
// value is returned (FailOpenCache), so a vault restart does not take the service down — but only
// within MaxStale (default 24h, 0.41.6) of when it was fetched, so an outage cannot keep a revoked
// or rotated value alive forever.
// Retries 429/5xx/network errors with 1s/2s/4s back-off. Nothing is logged.
//
// Sealed delivery (0.17): a token bound to this application's X25519 public key gets values
// encrypted to that key; set Options.ClientPrivateKey (base64 raw 32 bytes, or VAULT_CLIENT_KEY)
// and the client decrypts in-process. GenerateKeyPair makes the pair. Since 0.19 the key may
// instead be a GOST R 34.10-2012 pair (GenerateGostKeyPair): the vault then seals with
// VKO → KDF_TREE → Kuznyechik-MGM (gost.go, clients/GOST-PORTING.md). Since 0.27 the key may be a
// post-quantum hybrid pair (GeneratePqcKeyPair): X25519 + ML-KEM-768 (FIPS 203); the vault seals with
// an ephemeral X25519 exchange AND an ML-KEM encapsulation, HKDF-SHA256 over both shared secrets,
// AES-256-GCM — an attacker has to break both primitives.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
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

const Version = "0.41.6"

// SealedAlg is the X25519 envelope algorithm (sealed.py); SealedAlgGOST (gost.go) is the other one.
const SealedAlg = "X25519-HKDF-SHA256-AES256GCM"
const SealedAlgP256 = "P256-HKDF-SHA256-AES256GCM" // 0.22: NIST P-256 — for keys that live in a TPM or a PKCS#11 token

var sealedInfoP256 = []byte("aps-vault/sealed-p256/v1")

// SealedAlgPQC (0.27) is the post-quantum hybrid envelope: X25519 + ML-KEM-768 (FIPS 203), HKDF-SHA256
// over both shared secrets, AES-256-GCM. Private key = X25519 sk (32) ‖ ML-KEM-768 seed d‖z (64) = 96
// bytes; public key = X25519 pk (32) ‖ ML-KEM-768 encapsulation key (1184) = 1216 bytes.
const SealedAlgPQC = "X25519MLKEM768-HKDF-SHA256-AES256GCM"

var sealedInfoPQC = []byte("aps-vault/sealed-pqc/v1")

const (
	pqcPrivateKeyLen    = 32 + mlkem.SeedSize                // 96
	pqcPublicKeyLen     = 32 + mlkem.EncapsulationKeySize768 // 1216
	pqcKEMCiphertextLen = mlkem.CiphertextSize768            // 1088
)

// GeneratePqcKeyPair returns (privateB64, publicB64) for the hybrid envelope: a fresh X25519 pair and a
// fresh ML-KEM-768 pair; the ML-KEM half is stored as its 64-byte seed, from which every client library
// (Python, Node, Java, Go) derives the same encapsulation key.
func GeneratePqcKeyPair() (string, string, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", "", err
	}
	priv := append(append([]byte{}, x.Bytes()...), dk.Bytes()...)
	pub := append(append([]byte{}, x.PublicKey().Bytes()...), dk.EncapsulationKey().Bytes()...)
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// parsePqcPrivate splits the 96-byte hybrid private key into its X25519 and ML-KEM-768 halves.
func parsePqcPrivate(privateKeyB64 string) (*ecdh.PrivateKey, *mlkem.DecapsulationKey768, error) {
	skb, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: client private key is not base64: %w", err)
	}
	if len(skb) != pqcPrivateKeyLen {
		return nil, nil, fmt.Errorf("vault: hybrid private key must be %d bytes (X25519 sk ‖ ML-KEM-768 seed), got %d", pqcPrivateKeyLen, len(skb))
	}
	x, err := ecdh.X25519().NewPrivateKey(skb[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("vault: client private key (X25519 half): %w", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(skb[32:])
	if err != nil {
		return nil, nil, fmt.Errorf("vault: client private key (ML-KEM-768 seed): %w", err)
	}
	return x, dk, nil
}

// PqcPublicFromPrivate returns the 1216-byte public key (base64) that belongs to a 96-byte hybrid
// private key — what the vault administrator enters as client_public_key.
func PqcPublicFromPrivate(privateKeyB64 string) (string, error) {
	x, dk, err := parsePqcPrivate(privateKeyB64)
	if err != nil {
		return "", err
	}
	pub := append(append([]byte{}, x.PublicKey().Bytes()...), dk.EncapsulationKey().Bytes()...)
	return base64.StdEncoding.EncodeToString(pub), nil
}

// unsealPqc opens the hybrid envelope: ss_x = X25519(sk, epk), ss_kem = ML-KEM-768.Decaps(dk, kem),
// key = HKDF-SHA256(ss_x ‖ ss_kem, info = label ‖ epk ‖ kem) — note: unlike the X25519 envelope the
// info does NOT include our public key — then AES-256-GCM with the secret name as AAD.
func unsealPqc(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
	x, dk, err := parsePqcPrivate(privateKeyB64)
	if err != nil {
		return nil, err
	}
	epkb, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	epk, err := ecdh.X25519().NewPublicKey(epkb)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	kem, err := base64.StdEncoding.DecodeString(env.KEM)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope kem: %w", err)
	}
	if len(kem) != pqcKEMCiphertextLen {
		return nil, fmt.Errorf("vault: sealed envelope kem: ML-KEM-768 ciphertext must be %d bytes, got %d", pqcKEMCiphertextLen, len(kem))
	}
	ssX, err := x.ECDH(epk)
	if err != nil {
		return nil, errSealedWrongKey
	}
	// ML-KEM uses implicit rejection: a tampered ciphertext yields a different secret, not an error,
	// so the mismatch surfaces at the GCM tag check below.
	ssKem, err := dk.Decapsulate(kem)
	if err != nil {
		return nil, errSealedWrongKey
	}
	ikm := append(append([]byte{}, ssX...), ssKem...)
	info := append(append(append([]byte{}, sealedInfoPQC...), epkb...), kem...)
	block, err := aes.NewCipher(hkdfSHA256(ikm, info, 32))
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
	if len(nonce) != gcm.NonceSize() {
		return nil, errSealedWrongKey
	}
	pt, err := gcm.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, errSealedWrongKey
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// KeyProvider is a private key the client does not hold itself (0.22): a TPM / HSM behind PKCS#11, a
// cloud KMS. PublicKey returns the uncompressed P-256 point (65 bytes); ECDH performs one derivation
// with the vault's ephemeral point. Set Options.KeyProvider instead of ClientPrivateKey.
type KeyProvider interface {
	PublicKey() []byte
	ECDH(peerPoint []byte) ([]byte, error)
}

// GenerateP256KeyPair returns (privateB64, publicB64): a 32-byte scalar and the 65-byte uncompressed point.
func GenerateP256KeyPair() (string, string, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// unsealP256 opens the P-256 envelope with a software scalar or a KeyProvider.
func unsealP256(env SealedEnvelope, privateKeyB64 string, kp KeyProvider, name string) (map[string]any, error) {
	epk, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	var our, shared []byte
	if kp != nil {
		our = kp.PublicKey()
		if shared, err = kp.ECDH(epk); err != nil {
			return nil, err
		}
	} else {
		skb, err := base64.StdEncoding.DecodeString(privateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("vault: client private key is not base64: %w", err)
		}
		sk, err := ecdh.P256().NewPrivateKey(skb)
		if err != nil {
			return nil, errSealedWrongKey
		}
		peer, err := ecdh.P256().NewPublicKey(epk)
		if err != nil {
			return nil, errSealedWrongKey
		}
		our = sk.PublicKey().Bytes()
		if shared, err = sk.ECDH(peer); err != nil {
			return nil, errSealedWrongKey
		}
	}
	info := append(append(append([]byte{}, sealedInfoP256...), epk...), our...)
	block, err := aes.NewCipher(hkdfSHA256(shared, info, 32))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, _ := base64.StdEncoding.DecodeString(env.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(env.CT)
	pt, err := gcm.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, errSealedWrongKey
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

var sealedInfo = []byte("aps-vault/sealed/v1")

// SealedEnvelope is the `sealed` object of GET /api/v1/m/secret/{name} for a key-bound token.
type SealedEnvelope struct {
	Alg   string `json:"alg"`
	V     int    `json:"v"`
	EPK   string `json:"epk"`
	UKM   string `json:"ukm,omitempty"` // GOST envelope only: 8-byte VKO UKM
	KEM   string `json:"kem,omitempty"` // the two hybrid envelopes only: 1088-byte ML-KEM-768 ciphertext
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
// (the envelope's AAD). Returns the payload: value, login, notes, totp as granted. Dispatches on
// env.Alg: X25519-HKDF-SHA256-AES256GCM (32-byte X25519 key), the P-256 envelope (SealedAlgP256,
// 32-byte scalar), the GOST envelope (SealedAlgGOST, 32-byte GOST R 34.10-2012 scalar) or the
// post-quantum hybrid (SealedAlgPQC, 96-byte X25519 sk ‖ ML-KEM-768 seed) or the GOST hybrid
// (SealedAlgGOSTPQC, 96-byte GOST scalar ‖ ML-KEM-768 seed).
func Unseal(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
	if env.V != 1 {
		return nil, fmt.Errorf("vault: unsupported sealed envelope %q v%d", env.Alg, env.V)
	}
	switch env.Alg {
	case SealedAlg:
		return unsealX25519(env, privateKeyB64, name)
	case SealedAlgP256:
		return unsealP256(env, privateKeyB64, nil, name)
	case SealedAlgGOST:
		return unsealGost(env, privateKeyB64, name)
	case SealedAlgPQC:
		return unsealPqc(env, privateKeyB64, name)
	case SealedAlgGOSTPQC:
		return unsealGostPqc(env, privateKeyB64, name)
	default:
		return nil, fmt.Errorf("vault: unsupported sealed envelope %q v%d", env.Alg, env.V)
	}
}

func unsealX25519(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
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
		return nil, errSealedWrongKey
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
	MaxStale      time.Duration // how long after the fetch a stale value may be served in an outage; default 24h, negative = no limit
	HTTPClient    *http.Client
	// ClientPrivateKey opens sealed values (base64 private key: raw X25519, GOST R 34.10-2012 scalar,
	// P-256 scalar or the 96-byte X25519+ML-KEM-768 hybrid — whatever kind the token carries); default VAULT_CLIENT_KEY.
	ClientPrivateKey string
	// KeyProvider opens the P-256 envelope with a key held elsewhere (TPM, HSM, 0.22); takes precedence over ClientPrivateKey.
	KeyProvider KeyProvider
}

type entry struct {
	sec     Secret
	exp     time.Time
	fetched time.Time
}

// Client talks to one vault with one service token.
type Client struct {
	base, token string
	clientKey   string
	keyProvider KeyProvider
	ttl         time.Duration
	retries     int
	failOpen    bool
	maxStale    time.Duration // <0: no limit
	http        *http.Client
	mu          sync.Mutex
	cache       map[string]entry
}

// Enrollment is what Enroll returns: keep Token and PrivateKey with mode 0600 (VAULT_TOKEN /
// VAULT_CLIENT_KEY); the token alone opens nothing.
type Enrollment struct {
	Token, PrivateKey, PublicKey, TokenName, FolderName, VaultURL string
}

// Enroll (0.21) makes this machine's key pair (X25519, or GOST when gost is true), redeems the
// one-time code and receives a token sealed to the new key. name defaults to the host name.
func Enroll(ctx context.Context, baseURL, code, name string, gost bool) (Enrollment, error) {
	kind := "x25519"
	if gost {
		kind = "gost"
	}
	return EnrollWith(ctx, baseURL, code, name, kind, nil)
}

// EnrollWith (0.22) is Enroll with a key kind — "x25519", "gost", "p256", "pqc" (0.27: X25519+ML-KEM-768
// hybrid), "gost-pqc" (0.32: GOST+ML-KEM-768 hybrid) — or a KeyProvider whose key lives in hardware (the private key stays there;
// Enrollment.PrivateKey comes back empty).
func EnrollWith(ctx context.Context, baseURL, code, name, kind string, kp KeyProvider) (Enrollment, error) {
	var priv, pub string
	var err error
	switch {
	case kp != nil:
		pub = base64.StdEncoding.EncodeToString(kp.PublicKey())
	case kind == "gost":
		priv, pub, err = GenerateGostKeyPair()
	case kind == "p256":
		priv, pub, err = GenerateP256KeyPair()
	case kind == "pqc":
		priv, pub, err = GeneratePqcKeyPair()
	case kind == "gost-pqc":
		priv, pub, err = GenerateGostPqcKeyPair()
	default:
		priv, pub, err = GenerateKeyPair()
	}
	if err != nil {
		return Enrollment{}, err
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	body, _ := json.Marshal(map[string]string{"code": code, "public_key": pub, "name": name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return Enrollment{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aps-vault-go/"+Version)
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return Enrollment{}, err
	}
	defer res.Body.Close()
	var out struct {
		RawToken   string `json:"raw_token"`
		TokenName  string `json:"token_name"`
		FolderName string `json:"folder_name"`
		VaultURL   string `json:"vault_url"`
		Detail     string `json:"detail"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode/100 != 2 {
		return Enrollment{}, &Error{Status: res.StatusCode, Detail: "enrol: " + out.Detail}
	}
	if out.VaultURL == "" {
		out.VaultURL = baseURL
	}
	return Enrollment{Token: out.RawToken, PrivateKey: priv, PublicKey: pub, TokenName: out.TokenName, FolderName: out.FolderName, VaultURL: out.VaultURL}, nil
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
		retries: 3, failOpen: true, maxStale: 24 * time.Hour, cache: map[string]entry{}, clientKey: o.ClientPrivateKey, keyProvider: o.KeyProvider}
	if c.clientKey == "" {
		c.clientKey = os.Getenv("VAULT_CLIENT_KEY")
	}
	if o.CacheTTL != 0 {
		c.ttl = o.CacheTTL
	}
	if o.MaxRetries != 0 {
		c.retries = o.MaxRetries
	}
	if o.MaxStale != 0 {
		c.maxStale = o.MaxStale
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
		freshEnough := c.maxStale < 0 || time.Since(hit.fetched) <= c.maxStale
		if ok && freshEnough && c.failOpen && transient {
			return hit.sec, nil
		}
		return Secret{}, err
	}
	if s.Sealed == nil && (c.clientKey != "" || c.keyProvider != nil) {
		// 0.37: a key is configured, so a plaintext answer is refused (a tampering proxy could have dropped the envelope)
		return Secret{}, errors.New("vault: a client key is configured but the response is not sealed — refusing (a proxy may have replaced it)")
	}
	if s.Sealed != nil {
		if c.clientKey == "" && c.keyProvider == nil {
			return Secret{}, errors.New("vault: this token delivers sealed values — set Options.ClientPrivateKey (or VAULT_CLIENT_KEY) or Options.KeyProvider")
		}
		n := name // 0.37: the AAD is the requested name — a swapped envelope of another secret does not open
		var m map[string]any
		var err error
		if c.keyProvider != nil {
			if s.Sealed.Alg != SealedAlgP256 || s.Sealed.V != 1 {
				return Secret{}, fmt.Errorf("vault: a hardware key opens only the P-256 envelope, the token sent %q", s.Sealed.Alg)
			}
			m, err = unsealP256(*s.Sealed, "", c.keyProvider, n)
		} else {
			m, err = Unseal(*s.Sealed, c.clientKey, n)
		}
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
		now := time.Now()
		c.cache[key] = entry{s, now.Add(c.ttl), now}
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

// Delete removes a secret from the token's folder (token needs can_write; vault 0.30.1+). A missing
// secret is a *Error with Status 404.
func (c *Client) Delete(ctx context.Context, name string) error {
	err := c.do(ctx, http.MethodDelete, "/api/v1/m/secret/"+url.PathEscape(name), nil, nil)
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
