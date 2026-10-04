package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fake machine API: one secret, counts hits, can be switched to failing.
func fakeVault(t *testing.T, failing *atomic.Bool, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vlt_test_token" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid token"})
			return
		}
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		hits.Add(1)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/m/secret/db-password":
			_ = json.NewEncoder(w).Encode(Secret{Name: "db-password", Value: "s3cr3t", Login: "app", UpdatedAt: "2026-10-02T00:00:00"})
		case r.Method == "POST" && r.URL.Path == "/api/v1/m/secret/new":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["value"] != "v" || b["login"] != "u" {
				t.Errorf("bad put body: %v", b)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "name": "new", "created": true})
		case r.Method == "GET" && r.URL.Path == "/api/v1/m/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "scope_folder": "f"})
		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "not found"})
		}
	}))
}

func TestRejectsNonServiceToken(t *testing.T) {
	if _, err := New("http://x", "my master password"); err == nil {
		t.Fatal("master password must be rejected")
	}
}

func TestGetCachesAndFailsOpen(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, err := New(srv.URL, "vlt_test_token", Options{MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := c.Get(ctx, "db-password")
	if err != nil || v != "s3cr3t" {
		t.Fatalf("get: %v %q", err, v)
	}
	if _, err := c.Get(ctx, "db-password"); err != nil || hits.Load() != 1 {
		t.Fatalf("second get must be served from cache, hits=%d", hits.Load())
	}
	// vault down + cache expired → stale value is still returned (fail-open)
	c.ttl = time.Nanosecond
	time.Sleep(time.Millisecond)
	failing.Store(true)
	if v, err := c.Get(ctx, "db-password"); err != nil || v != "s3cr3t" {
		t.Fatalf("fail-open: %v %q", err, v)
	}
	// but an unknown name with the vault down is an error
	if _, err := c.Get(ctx, "never-seen"); err == nil {
		t.Fatal("expected error for uncached secret while vault is down")
	}
}

func TestNotFoundIsNotRetriedAndCarriesStatus(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token")
	_, err := c.Get(context.Background(), "missing")
	var he *Error
	if !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("want 404 Error, got %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("404 must not be retried, hits=%d", hits.Load())
	}
}

func TestPutAndHealth(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token")
	if err := c.Put(context.Background(), "new", "v", "u", "", ""); err != nil {
		t.Fatal(err)
	}
	h, err := c.Health(context.Background())
	if err != nil || h["status"] != "ok" {
		t.Fatalf("health: %v %v", err, h)
	}
}

func TestBadTokenIs401(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_wrong")
	_, err := c.Get(context.Background(), "db-password")
	var he *Error
	if !errors.As(err, &he) || he.Status != 401 {
		t.Fatalf("want 401, got %v", err)
	}
}

// Fixture produced by the server (backend/sealed.py) for the private key 0x01..0x20: proves the
// Go implementation opens what Python seals — HKDF salt handling, info layout, AAD included.
const fixtureSK = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

var fixtureEnv = SealedEnvelope{Alg: SealedAlg, V: 1, EPK: "qId7VmcoFhnApxHZznkoaKFl/wIl/z2HauZI+GMVI1Q=", Nonce: "qTsci1J2iUT0nr58",
	CT: "DmXYnxSzPc9d6MIdODi2I9bd2nw4yi3mBUWcxVHLDVlX/ax+BH5DcqBh2PBcBt8E7eTZouxd0SyW+fzJ4dlXL+F4SL2HrSY="}

func TestUnsealServerFixture(t *testing.T) {
	m, err := Unseal(fixtureEnv, fixtureSK, "core-db")
	if err != nil || m["value"] != "pg-pass-2026" || m["login"] != "core" || m["totp"] != "123456" {
		t.Fatalf("fixture: %v %v", err, m)
	}
	if _, err := Unseal(fixtureEnv, fixtureSK, "other-name"); err == nil {
		t.Fatal("AAD: another name must not open the envelope")
	}
	_, otherPK, _ := GenerateKeyPair()
	_ = otherPK
	otherSK, _, _ := GenerateKeyPair()
	if _, err := Unseal(fixtureEnv, otherSK, "core-db"); err == nil {
		t.Fatal("another private key must not open the envelope")
	}
	bad := fixtureEnv
	bad.Alg = "RSA"
	if _, err := Unseal(bad, fixtureSK, "core-db"); err == nil {
		t.Fatal("unsupported alg must be refused")
	}
}

func TestSealedThroughClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Secret{Name: "core-db", Version: 1, UpdatedAt: "x", Sealed: &fixtureEnv})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: fixtureSK})
	s, err := c.GetFull(context.Background(), "core-db")
	if err != nil || s.Value != "pg-pass-2026" || s.Login != "core" || s.TOTP == nil || *s.TOTP != "123456" || s.Sealed != nil {
		t.Fatalf("sealed via client: %v %+v", err, s)
	}
	t.Setenv("VAULT_CLIENT_KEY", "")
	noKey, _ := New(srv.URL, "vlt_test_token")
	if _, err := noKey.Get(context.Background(), "core-db"); err == nil || !strings.Contains(err.Error(), "sealed values") {
		t.Fatalf("without a key the client must refuse, got %v", err)
	}
}

// ── GOST envelope (0.19): every entry of clients/fixtures/gost-sealed.json ─────

type gostFixture struct {
	Streebog struct {
		M1, M1256, M1512, M2, M2256, M2512, Empty256 string
	}
	HMAC  struct{ Key, Data, Mac string }
	KDF   struct{ Key, Label, Seed, Out string }
	Kuz   struct{ Key, PT, CT string }
	MGM   struct{ Key, Nonce, AAD, PT, CT, Tag string }
	Curve struct {
		P, A, B, Q, GX, GY string
	}
	Keypair struct{ PrivateB64, PublicB64, XHex, YHex string }
	VKO     struct{ PrivateB64, PeerPublicB64, UKMHex, KEKHex string }
	Env     struct {
		Name    string
		Payload map[string]any
		Sealed  SealedEnvelope
	}
}

func loadGostFixture(t *testing.T) gostFixture {
	t.Helper()
	raw, err := os.ReadFile("../fixtures/gost-sealed.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var j struct {
		Streebog map[string]string `json:"streebog"`
		HMAC     map[string]string `json:"hmac_streebog256"`
		KDF      map[string]string `json:"kdf_tree_256"`
		Kuz      map[string]string `json:"kuznyechik"`
		MGM      map[string]string `json:"mgm_rfc9058"`
		Curve    map[string]string `json:"curve"`
		Keypair  map[string]string `json:"keypair"`
		VKO      map[string]string `json:"vko"`
		Env      struct {
			Name    string         `json:"name"`
			Payload map[string]any `json:"payload"`
			Sealed  SealedEnvelope `json:"sealed"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	var f gostFixture
	f.Streebog.M1, f.Streebog.M1256, f.Streebog.M1512 = j.Streebog["M1"], j.Streebog["M1_256"], j.Streebog["M1_512"]
	f.Streebog.M2, f.Streebog.M2256, f.Streebog.M2512 = j.Streebog["M2"], j.Streebog["M2_256"], j.Streebog["M2_512"]
	f.Streebog.Empty256 = j.Streebog["empty_256"]
	f.HMAC.Key, f.HMAC.Data, f.HMAC.Mac = j.HMAC["key"], j.HMAC["data"], j.HMAC["mac"]
	f.KDF.Key, f.KDF.Label, f.KDF.Seed, f.KDF.Out = j.KDF["key"], j.KDF["label"], j.KDF["seed"], j.KDF["out"]
	f.Kuz.Key, f.Kuz.PT, f.Kuz.CT = j.Kuz["key"], j.Kuz["pt"], j.Kuz["ct"]
	f.MGM.Key, f.MGM.Nonce, f.MGM.AAD, f.MGM.PT, f.MGM.CT, f.MGM.Tag = j.MGM["key"], j.MGM["nonce"], j.MGM["aad"], j.MGM["pt"], j.MGM["ct"], j.MGM["tag"]
	f.Curve.P, f.Curve.A, f.Curve.B, f.Curve.Q, f.Curve.GX, f.Curve.GY = j.Curve["p"], j.Curve["a"], j.Curve["b"], j.Curve["q"], j.Curve["gx"], j.Curve["gy"]
	f.Keypair.PrivateB64, f.Keypair.PublicB64 = j.Keypair["private_b64"], j.Keypair["public_b64"]
	f.Keypair.XHex, f.Keypair.YHex = j.Keypair["public_x_hex_be"], j.Keypair["public_y_hex_be"]
	f.VKO.PrivateB64, f.VKO.PeerPublicB64, f.VKO.UKMHex, f.VKO.KEKHex = j.VKO["private_b64"], j.VKO["peer_public_b64"], j.VKO["ukm_hex"], j.VKO["kek_hex"]
	f.Env.Name, f.Env.Payload, f.Env.Sealed = j.Env.Name, j.Env.Payload, j.Env.Sealed
	return f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

func TestStreebogVectors(t *testing.T) {
	f := loadGostFixture(t)
	m1, m2 := unhex(t, f.Streebog.M1), unhex(t, f.Streebog.M2)
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"M1-256", Streebog256(m1), f.Streebog.M1256},
		{"M1-512", Streebog512(m1), f.Streebog.M1512},
		{"M2-256", Streebog256(m2), f.Streebog.M2256},
		{"M2-512", Streebog512(m2), f.Streebog.M2512},
		{"empty-256", Streebog256(nil), f.Streebog.Empty256},
	}
	for _, c := range cases {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s: got %x want %s", c.name, c.got, c.want)
		}
	}
	// a 64-byte message (one full block, empty padding block) and a 65-byte one exercise the
	// block loop; they must agree with the incremental definition (cross-checked against Python).
	if len(m1) != 63 || len(m2) != 72 {
		t.Fatalf("fixture lengths changed: %d %d", len(m1), len(m2))
	}
}

func TestHMACAndKDFTreeVectors(t *testing.T) {
	f := loadGostFixture(t)
	if got := hmacStreebog256(unhex(t, f.HMAC.Key), unhex(t, f.HMAC.Data)); hex.EncodeToString(got) != f.HMAC.Mac {
		t.Errorf("hmac: got %x want %s", got, f.HMAC.Mac)
	}
	if got := kdfTree256(unhex(t, f.KDF.Key), unhex(t, f.KDF.Label), unhex(t, f.KDF.Seed)); hex.EncodeToString(got) != f.KDF.Out {
		t.Errorf("kdf_tree: got %x want %s", got, f.KDF.Out)
	}
	// keys longer than the 64-byte block are hashed first (RFC 2104) — must equal HMAC with the hash
	long := bytes.Repeat([]byte{0xAB}, 83)
	if !bytes.Equal(hmacStreebog256(long, []byte("x")), hmacStreebog256(Streebog256(long), []byte("x"))) {
		t.Error("hmac: long key must be hashed first")
	}
}

func TestKuznyechikVector(t *testing.T) {
	f := loadGostFixture(t)
	c, err := newKuznyechik(unhex(t, f.Kuz.Key))
	if err != nil {
		t.Fatal(err)
	}
	pt, ct := unhex(t, f.Kuz.PT), unhex(t, f.Kuz.CT)
	if got := c.EncryptBlock(pt); !bytes.Equal(got, ct) {
		t.Errorf("encrypt: got %x want %x", got, ct)
	}
	if got := c.DecryptBlock(ct); !bytes.Equal(got, pt) {
		t.Errorf("decrypt: got %x want %x", got, pt)
	}
	if _, err := newKuznyechik(make([]byte, 16)); err == nil {
		t.Error("16-byte key must be refused")
	}
}

func TestMGMRFC9058(t *testing.T) {
	f := loadGostFixture(t)
	c, _ := newKuznyechik(unhex(t, f.MGM.Key))
	nonce, aad, pt := unhex(t, f.MGM.Nonce), unhex(t, f.MGM.AAD), unhex(t, f.MGM.PT)
	// RFC 9058 Appendix A.1 (Kuznyechik example): the fixture holds the RFC's plaintext, ct and tag.
	if !bytes.HasPrefix(pt, unhex(t, "1122334455667700ffeeddccbbaa9988")) {
		t.Fatalf("fixture mgm_rfc9058.pt is not the RFC 9058 A.1 plaintext: %x", pt[:16])
	}
	want := append(unhex(t, f.MGM.CT), unhex(t, f.MGM.Tag)...)
	got, err := mgmSeal(c, nonce, pt, aad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("seal: %v\n got %x\nwant %x", err, got, want)
	}
	back, err := mgmOpen(c, nonce, want, aad)
	if err != nil || !bytes.Equal(back, pt) {
		t.Fatalf("open: %v %x", err, back)
	}
	// tampering: ciphertext byte, tag byte, AAD, nonce — all refused
	for _, tamper := range []struct {
		name string
		mod  func() ([]byte, []byte, []byte)
	}{
		{"ct", func() ([]byte, []byte, []byte) { b := append([]byte{}, want...); b[3] ^= 1; return nonce, b, aad }},
		{"tag", func() ([]byte, []byte, []byte) {
			b := append([]byte{}, want...)
			b[len(b)-1] ^= 1
			return nonce, b, aad
		}},
		{"aad", func() ([]byte, []byte, []byte) { a := append([]byte{}, aad...); a[0] ^= 1; return nonce, want, a }},
		{"nonce", func() ([]byte, []byte, []byte) { n := append([]byte{}, nonce...); n[5] ^= 1; return n, want, aad }},
	} {
		n, ct, a := tamper.mod()
		if _, err := mgmOpen(c, n, ct, a); err == nil {
			t.Errorf("tampered %s must be refused", tamper.name)
		}
	}
	if _, err := mgmOpen(c, nonce, want[:10], aad); err == nil {
		t.Error("short ciphertext must be refused")
	}
	bad := append([]byte{}, nonce...)
	bad[0] |= 0x80
	if _, err := mgmSeal(c, bad, pt, aad); err == nil {
		t.Error("nonce with the top bit set must be refused")
	}
}

func TestGostCurveConstantsMatchFixture(t *testing.T) {
	f := loadGostFixture(t)
	c := gostParams()
	for _, p := range []struct {
		name string
		got  *big.Int
		want string
	}{{"p", c.p, f.Curve.P}, {"a", c.a, f.Curve.A}, {"b", c.b, f.Curve.B}, {"q", c.q, f.Curve.Q}, {"gx", c.gx, f.Curve.GX}, {"gy", c.gy, f.Curve.GY}} {
		if "0x"+got(p.got) != p.want {
			t.Errorf("curve %s: got 0x%s want %s", p.name, got(p.got), p.want)
		}
	}
	if !c.onCurve(c.generator()) {
		t.Error("generator must be on the curve")
	}
	if c.mul(c.q, c.generator()) != nil {
		t.Error("q·G must be the point at infinity")
	}
}

func got(n *big.Int) string { return n.Text(16) }

func TestGostKeypairVector(t *testing.T) {
	f := loadGostFixture(t)
	c := gostParams()
	d, err := c.parseGostPrivate(f.Keypair.PrivateB64)
	if err != nil {
		t.Fatal(err)
	}
	pub := c.publicFromPrivate(d)
	if "0x"+pub.x.Text(16) != f.Keypair.XHex || "0x"+pub.y.Text(16) != f.Keypair.YHex {
		t.Errorf("public: x=0x%s y=0x%s want %s %s", pub.x.Text(16), pub.y.Text(16), f.Keypair.XHex, f.Keypair.YHex)
	}
	if got := base64.StdEncoding.EncodeToString(encodePoint(pub)); got != f.Keypair.PublicB64 {
		t.Errorf("encoded public: got %s want %s", got, f.Keypair.PublicB64)
	}
	// decode round-trips and validates
	back, err := c.decodePoint(unb64(t, f.Keypair.PublicB64))
	if err != nil || back.x.Cmp(pub.x) != 0 || back.y.Cmp(pub.y) != 0 {
		t.Fatalf("decode: %v", err)
	}
	// off-curve point refused: flip one byte of Y
	raw := unb64(t, f.Keypair.PublicB64)
	raw[40] ^= 0x01
	if _, err := c.decodePoint(raw); err == nil {
		t.Error("off-curve point must be refused")
	}
	if _, err := c.decodePoint(raw[:63]); err == nil {
		t.Error("63-byte point must be refused")
	}
	// private key range
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := c.parseGostPrivate(zero); err == nil {
		t.Error("d = 0 must be refused")
	}
	var qb [32]byte
	c.q.FillBytes(qb[:])
	if _, err := c.parseGostPrivate(base64.StdEncoding.EncodeToString(qb[:])); err == nil {
		t.Error("d = q must be refused")
	}
	// fresh pair: shapes and consistency
	skB64, pkB64, err := GenerateGostKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk, pk := unb64(t, skB64), unb64(t, pkB64)
	if len(sk) != 32 || len(pk) != 64 {
		t.Fatalf("key sizes %d %d", len(sk), len(pk))
	}
	d2, err := c.parseGostPrivate(skB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodePoint(c.publicFromPrivate(d2)), pk) {
		t.Error("generated public key does not match d·G")
	}
}

func TestGostVKOVector(t *testing.T) {
	f := loadGostFixture(t)
	c := gostParams()
	d, err := c.parseGostPrivate(f.VKO.PrivateB64)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := c.decodePoint(unb64(t, f.VKO.PeerPublicB64))
	if err != nil {
		t.Fatal(err)
	}
	kek, err := c.vko(d, peer, unhex(t, f.VKO.UKMHex))
	if err != nil || hex.EncodeToString(kek) != f.VKO.KEKHex {
		t.Fatalf("vko: %v got %x want %s", err, kek, f.VKO.KEKHex)
	}
	if _, err := c.vko(d, peer, make([]byte, 8)); err == nil {
		t.Error("UKM = 0 must be refused")
	}
	if _, err := c.vko(d, peer, make([]byte, 7)); err == nil {
		t.Error("7-byte UKM must be refused")
	}
	// symmetry: VKO(d1, pk2) == VKO(d2, pk1)
	sk1, pk1, _ := GenerateGostKeyPair()
	sk2, pk2, _ := GenerateGostKeyPair()
	d1, _ := c.parseGostPrivate(sk1)
	d2, _ := c.parseGostPrivate(sk2)
	p1, _ := c.decodePoint(unb64(t, pk1))
	p2, _ := c.decodePoint(unb64(t, pk2))
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	k12, _ := c.vko(d1, p2, ukm)
	k21, _ := c.vko(d2, p1, ukm)
	if !bytes.Equal(k12, k21) {
		t.Error("VKO must be symmetric")
	}
}

func TestUnsealGostServerFixture(t *testing.T) {
	f := loadGostFixture(t)
	if f.Env.Sealed.Alg != SealedAlgGOST {
		t.Fatalf("fixture alg %q", f.Env.Sealed.Alg)
	}
	m, err := Unseal(f.Env.Sealed, f.Keypair.PrivateB64, f.Env.Name)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	for k, want := range f.Env.Payload {
		if m[k] != want {
			t.Errorf("payload[%s] = %v want %v", k, m[k], want)
		}
	}
	if len(m) != len(f.Env.Payload) {
		t.Errorf("payload keys %v want %v", m, f.Env.Payload)
	}
	// wrong name (AAD)
	if _, err := Unseal(f.Env.Sealed, f.Keypair.PrivateB64, "other-name"); err == nil || err.Error() != errSealedWrongKey.Error() {
		t.Errorf("wrong name must be refused with the wrong-key error, got %v", err)
	}
	// wrong key
	otherSK, _, _ := GenerateGostKeyPair()
	if _, err := Unseal(f.Env.Sealed, otherSK, f.Env.Name); err == nil || err.Error() != errSealedWrongKey.Error() {
		t.Errorf("another private key must be refused, got %v", err)
	}
	// an X25519 key (32 random bytes) may be out of range or just wrong — either way refused
	x25519SK, _, _ := GenerateKeyPair()
	if _, err := Unseal(f.Env.Sealed, x25519SK, f.Env.Name); err == nil {
		t.Error("X25519 key must not open a GOST envelope")
	}
	// tampered ct / epk off curve / bad ukm
	bad := f.Env.Sealed
	ct := unb64(t, bad.CT)
	ct[0] ^= 1
	bad.CT = base64.StdEncoding.EncodeToString(ct)
	if _, err := Unseal(bad, f.Keypair.PrivateB64, f.Env.Name); err == nil {
		t.Error("tampered ciphertext must be refused")
	}
	bad = f.Env.Sealed
	epk := unb64(t, bad.EPK)
	epk[1] ^= 1
	bad.EPK = base64.StdEncoding.EncodeToString(epk)
	if _, err := Unseal(bad, f.Keypair.PrivateB64, f.Env.Name); err == nil || err.Error() != errSealedWrongKey.Error() {
		t.Errorf("off-curve epk must be refused with the wrong-key error, got %v", err)
	}
	bad = f.Env.Sealed
	bad.UKM = base64.StdEncoding.EncodeToString(make([]byte, 8))
	if _, err := Unseal(bad, f.Keypair.PrivateB64, f.Env.Name); err == nil {
		t.Error("zero UKM must be refused")
	}
	bad = f.Env.Sealed
	bad.V = 2
	if _, err := Unseal(bad, f.Keypair.PrivateB64, f.Env.Name); err == nil {
		t.Error("v2 must be refused")
	}
	// the X25519 path is untouched by the dispatch
	if m, err := Unseal(fixtureEnv, fixtureSK, "core-db"); err != nil || m["value"] != "pg-pass-2026" {
		t.Errorf("X25519 fixture after dispatch: %v %v", err, m)
	}
}

func TestGostSealedThroughClient(t *testing.T) {
	f := loadGostFixture(t)
	env := f.Env.Sealed
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/v1/m/secret/core-db" {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(Secret{Name: "core-db", Version: 3, UpdatedAt: "x", Sealed: &env})
	}))
	defer srv.Close()
	c, err := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: f.Keypair.PrivateB64})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.GetFull(context.Background(), "core-db")
	if err != nil || s.Value != "pg-pass-2026" || s.Login != "core" || s.TOTP == nil || *s.TOTP != "123456" || s.Sealed != nil || s.Version != 3 {
		t.Fatalf("gost sealed via client: %v %+v", err, s)
	}
	if v, err := c.Get(context.Background(), "core-db"); err != nil || v != "pg-pass-2026" || hits.Load() != 1 {
		t.Fatalf("cached get: %v %q hits=%d", err, v, hits.Load())
	}
	// the JSON round trip must keep ukm (omitempty field) — otherwise VKO cannot run
	var back Secret
	raw, _ := json.Marshal(Secret{Sealed: &env})
	_ = json.Unmarshal(raw, &back)
	if back.Sealed == nil || back.Sealed.UKM != env.UKM {
		t.Fatal("ukm lost in JSON round trip")
	}
	// wrong client key through the client surfaces the wrong-key error
	otherSK, _, _ := GenerateGostKeyPair()
	wrong, _ := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: otherSK})
	if _, err := wrong.Get(context.Background(), "core-db"); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("wrong key via client: %v", err)
	}
	t.Setenv("VAULT_CLIENT_KEY", "")
	noKey, _ := New(srv.URL, "vlt_test_token")
	if _, err := noKey.Get(context.Background(), "core-db"); err == nil || !strings.Contains(err.Error(), "sealed values") {
		t.Fatalf("without a key the client must refuse, got %v", err)
	}
}

func BenchmarkUnsealGost(b *testing.B) {
	raw, err := os.ReadFile("../fixtures/gost-sealed.json")
	if err != nil {
		b.Fatal(err)
	}
	var j struct {
		Keypair struct {
			PrivateB64 string `json:"private_b64"`
		} `json:"keypair"`
		Env struct {
			Name   string         `json:"name"`
			Sealed SealedEnvelope `json:"sealed"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := unsealGost(j.Env.Sealed, j.Keypair.PrivateB64, j.Env.Name); err != nil {
			b.Fatal(err)
		}
	}
}

func TestEnroll(t *testing.T) {
	var gotPk string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/enroll" || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["code"] != "enr_ok" {
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "enrolment code is unknown, revoked or expired"})
			return
		}
		gotPk = b["public_key"]
		_ = json.NewEncoder(w).Encode(map[string]any{"raw_token": "vlt_enrolled", "token_name": "node-" + b["name"], "folder_name": "f", "sealed": true})
	}))
	defer srv.Close()
	e, err := Enroll(context.Background(), srv.URL, "enr_ok", "host-1", false)
	if err != nil || e.Token != "vlt_enrolled" || e.TokenName != "node-host-1" || e.PublicKey != gotPk || e.VaultURL != srv.URL {
		t.Fatalf("enrol: %v %+v", err, e)
	}
	g, err := Enroll(context.Background(), srv.URL, "enr_ok", "host-2", true)
	if err != nil || len(g.PublicKey) < 80 {
		t.Fatalf("gost enrol: %v %+v", err, g)
	}
	if _, err := Enroll(context.Background(), srv.URL, "enr_bad", "x", false); err == nil {
		t.Fatal("bad code must fail")
	}
}

type scalarProvider struct{ k *ecdh.PrivateKey }

func (p scalarProvider) PublicKey() []byte { return p.k.PublicKey().Bytes() }
func (p scalarProvider) ECDH(peer []byte) ([]byte, error) {
	pk, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return p.k.ECDH(pk)
}

func TestP256EnvelopeFixtureAndProvider(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/p256-sealed.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Keypair struct {
			Private string `json:"private_b64"`
			Public  string `json:"public_b64"`
		} `json:"keypair"`
		Envelope struct {
			Payload map[string]any `json:"payload"`
			Sealed  SealedEnvelope `json:"sealed"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	m, err := Unseal(fx.Envelope.Sealed, fx.Keypair.Private, "core-db")
	if err != nil || m["value"] != "pg-pass-2026" || m["login"] != "core" {
		t.Fatalf("p256 fixture: %v %v", err, m)
	}
	skb, _ := base64.StdEncoding.DecodeString(fx.Keypair.Private)
	sk, _ := ecdh.P256().NewPrivateKey(skb)
	if m, err := unsealP256(fx.Envelope.Sealed, "", scalarProvider{sk}, "core-db"); err != nil || m["value"] != "pg-pass-2026" {
		t.Fatalf("p256 via KeyProvider: %v %v", err, m)
	}
	otherSK, _, _ := GenerateP256KeyPair()
	if _, err := Unseal(fx.Envelope.Sealed, otherSK, "core-db"); err == nil {
		t.Fatal("another key must not open the envelope")
	}
	if _, err := Unseal(fx.Envelope.Sealed, fx.Keypair.Private, "other"); err == nil {
		t.Fatal("another name must not open the envelope")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := fx.Envelope.Sealed
		_ = json.NewEncoder(w).Encode(Secret{Name: "core-db", Version: 1, UpdatedAt: "x", Sealed: &s})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token", Options{KeyProvider: scalarProvider{sk}})
	s, err := c.GetFull(context.Background(), "core-db")
	if err != nil || s.Value != "pg-pass-2026" {
		t.Fatalf("client with KeyProvider: %v %+v", err, s)
	}
}

// ── PQC hybrid envelope (0.27): clients/fixtures/pqc-sealed.json ──────────────

type pqcFixture struct {
	Alg            string `json:"alg"`
	HKDFInfoPrefix string `json:"hkdf_info_prefix"`
	Keypair        struct {
		Private string `json:"private_b64"`
		Public  string `json:"public_b64"`
	} `json:"keypair"`
	Envelopes []struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
		Sealed  SealedEnvelope `json:"sealed"`
	} `json:"envelopes"`
}

func loadPqcFixture(t *testing.T) pqcFixture {
	t.Helper()
	raw, err := os.ReadFile("../fixtures/pqc-sealed.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var f pqcFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	if f.Alg != SealedAlgPQC || f.HKDFInfoPrefix != string(sealedInfoPQC) {
		t.Fatalf("fixture alg/info %q %q do not match the client constants", f.Alg, f.HKDFInfoPrefix)
	}
	if len(f.Envelopes) < 2 {
		t.Fatalf("fixture has %d envelopes, want at least 2 (ASCII + Cyrillic)", len(f.Envelopes))
	}
	return f
}

// sealPqcForTest is the sender side (what backend/sealed.py seal_pqc does): ephemeral X25519 with the
// client's X25519 half, ML-KEM-768 encapsulation to the client's ML-KEM half, HKDF over both secrets,
// AES-256-GCM with the name as AAD.
func sealPqcForTest(t *testing.T, publicB64, name string, payload map[string]any) SealedEnvelope {
	t.Helper()
	pub := unb64(t, publicB64)
	if len(pub) != pqcPublicKeyLen {
		t.Fatalf("public key %d bytes, want %d", len(pub), pqcPublicKeyLen)
	}
	clientX, err := ecdh.X25519().NewPublicKey(pub[:32])
	if err != nil {
		t.Fatal(err)
	}
	ek, err := mlkem.NewEncapsulationKey768(pub[32:])
	if err != nil {
		t.Fatal(err)
	}
	esk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epk := esk.PublicKey().Bytes()
	ssX, err := esk.ECDH(clientX)
	if err != nil {
		t.Fatal(err)
	}
	ssKem, kem := ek.Encapsulate()
	ikm := append(append([]byte{}, ssX...), ssKem...)
	info := append(append(append([]byte{}, sealedInfoPQC...), epk...), kem...)
	block, _ := aes.NewCipher(hkdfSHA256(ikm, info, 32))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	pt, _ := json.Marshal(payload)
	ct := gcm.Seal(nil, nonce, pt, []byte(name))
	b64 := base64.StdEncoding.EncodeToString
	return SealedEnvelope{Alg: SealedAlgPQC, V: 1, EPK: b64(epk), KEM: b64(kem), Nonce: b64(nonce), CT: b64(ct)}
}

func TestPqcPublicFromPrivateFixture(t *testing.T) {
	f := loadPqcFixture(t)
	if len(unb64(t, f.Keypair.Private)) != 96 || len(unb64(t, f.Keypair.Public)) != 1216 {
		t.Fatalf("fixture key sizes changed")
	}
	got, err := PqcPublicFromPrivate(f.Keypair.Private)
	if err != nil {
		t.Fatal(err)
	}
	if got != f.Keypair.Public {
		t.Fatalf("public from private:\n got %s\nwant %s", got, f.Keypair.Public)
	}
	// not 96 bytes → a clear error, not a panic
	x25519SK, _, _ := GenerateKeyPair()
	if _, err := PqcPublicFromPrivate(x25519SK); err == nil || !strings.Contains(err.Error(), "96 bytes") {
		t.Errorf("32-byte key must be refused with a size error, got %v", err)
	}
	if _, err := PqcPublicFromPrivate("not base64!"); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestUnsealPqcServerFixture(t *testing.T) {
	f := loadPqcFixture(t)
	sawCyrillic := false
	for _, e := range f.Envelopes {
		if e.Sealed.Alg != SealedAlgPQC || e.Sealed.V != 1 {
			t.Fatalf("fixture %q alg/v %q %d", e.Name, e.Sealed.Alg, e.Sealed.V)
		}
		if len(unb64(t, e.Sealed.KEM)) != 1088 || len(unb64(t, e.Sealed.EPK)) != 32 || len(unb64(t, e.Sealed.Nonce)) != 12 {
			t.Fatalf("fixture %q field sizes changed", e.Name)
		}
		if strings.ContainsRune(e.Name, 'к') {
			sawCyrillic = true
		}
		m, err := Unseal(e.Sealed, f.Keypair.Private, e.Name)
		if err != nil {
			t.Fatalf("unseal %q: %v", e.Name, err)
		}
		for k, want := range e.Payload {
			// JSON decodes numbers into float64 on both sides (payload and opened map)
			if m[k] != want {
				t.Errorf("%q payload[%s] = %#v want %#v", e.Name, k, m[k], want)
			}
		}
		if len(m) != len(e.Payload) {
			t.Errorf("%q payload keys %v want %v", e.Name, m, e.Payload)
		}
	}
	if !sawCyrillic {
		t.Error("fixture must contain a Cyrillic secret name")
	}
	// the first envelope has value/login/notes/version: check the exact typed values too
	e := f.Envelopes[0]
	m, err := Unseal(e.Sealed, f.Keypair.Private, e.Name)
	if err != nil || m["value"] != "pg-pass-2026" || m["login"] != "core" || m["notes"] != "hybrid fixture" || m["version"] != float64(7) {
		t.Fatalf("first envelope: %v %#v", err, m)
	}
}

func TestUnsealPqcNegative(t *testing.T) {
	f := loadPqcFixture(t)
	e := f.Envelopes[0]
	flip := func(b64 string, i int) string {
		b := unb64(t, b64)
		b[i] ^= 0x01
		return base64.StdEncoding.EncodeToString(b)
	}
	wrongKey := func(name string, env SealedEnvelope, key string) {
		t.Helper()
		if _, err := Unseal(env, key, e.Name); err == nil || err.Error() != errSealedWrongKey.Error() {
			t.Errorf("%s must be refused with the wrong-key error, got %v", name, err)
		}
	}
	bad := e.Sealed
	bad.KEM = flip(bad.KEM, 100)
	wrongKey("flipped kem byte", bad, f.Keypair.Private) // ML-KEM implicit rejection → GCM tag mismatch
	bad = e.Sealed
	bad.EPK = flip(bad.EPK, 3)
	wrongKey("flipped epk byte", bad, f.Keypair.Private)
	bad = e.Sealed
	bad.CT = flip(bad.CT, 0)
	wrongKey("flipped ct byte", bad, f.Keypair.Private)
	bad = e.Sealed
	bad.CT = flip(bad.CT, len(unb64(t, bad.CT))-1) // last tag byte
	wrongKey("flipped tag byte", bad, f.Keypair.Private)
	bad = e.Sealed
	bad.Nonce = flip(bad.Nonce, 0)
	wrongKey("flipped nonce byte", bad, f.Keypair.Private)
	// wrong name (AAD)
	if _, err := Unseal(e.Sealed, f.Keypair.Private, e.Name+"x"); err == nil || err.Error() != errSealedWrongKey.Error() {
		t.Errorf("another name must be refused with the wrong-key error, got %v", err)
	}
	// another hybrid key
	otherSK, _, err := GeneratePqcKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey("another hybrid key", e.Sealed, otherSK)
	// same X25519 half, different ML-KEM seed: X25519 alone must not be enough
	sk := unb64(t, f.Keypair.Private)
	half := append(append([]byte{}, sk[:32]...), unb64(t, otherSK)[32:]...)
	wrongKey("right X25519 half, wrong ML-KEM half", e.Sealed, base64.StdEncoding.EncodeToString(half))
	half = append(append([]byte{}, unb64(t, otherSK)[:32]...), sk[32:]...)
	wrongKey("wrong X25519 half, right ML-KEM half", e.Sealed, base64.StdEncoding.EncodeToString(half))
	// a 32-byte key with the PQC envelope → clear size error
	x25519SK, _, _ := GenerateKeyPair()
	if _, err := Unseal(e.Sealed, x25519SK, e.Name); err == nil || !strings.Contains(err.Error(), "96 bytes") {
		t.Errorf("32-byte key must be refused with a size error, got %v", err)
	}
	// missing / truncated kem, wrong version, wrong alg
	bad = e.Sealed
	bad.KEM = ""
	if _, err := Unseal(bad, f.Keypair.Private, e.Name); err == nil {
		t.Error("missing kem must be refused")
	}
	bad = e.Sealed
	bad.KEM = base64.StdEncoding.EncodeToString(unb64(t, bad.KEM)[:1087])
	if _, err := Unseal(bad, f.Keypair.Private, e.Name); err == nil {
		t.Error("1087-byte kem must be refused")
	}
	bad = e.Sealed
	bad.V = 2
	if _, err := Unseal(bad, f.Keypair.Private, e.Name); err == nil {
		t.Error("v2 must be refused")
	}
	// the hybrid key does not open the plain X25519 envelope (and does not panic on it)
	if _, err := Unseal(fixtureEnv, f.Keypair.Private, "core-db"); err == nil {
		t.Error("a 96-byte key must not open the X25519 envelope")
	}
	// the other dispatch paths are untouched
	if m, err := Unseal(fixtureEnv, fixtureSK, "core-db"); err != nil || m["value"] != "pg-pass-2026" {
		t.Errorf("X25519 fixture after dispatch: %v %v", err, m)
	}
}

func TestPqcLocalRoundtrip(t *testing.T) {
	priv, pub, err := GeneratePqcKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(unb64(t, priv)) != 96 || len(unb64(t, pub)) != 1216 {
		t.Fatalf("key sizes %d %d", len(unb64(t, priv)), len(unb64(t, pub)))
	}
	derived, err := PqcPublicFromPrivate(priv)
	if err != nil || derived != pub {
		t.Fatalf("generated public must equal the one derived from the private: %v", err)
	}
	payload := map[string]any{"value": "p@ss ✓", "login": "svc", "notes": "кириллица", "totp": "123456"}
	env := sealPqcForTest(t, pub, "имя/секрета", payload)
	if len(unb64(t, env.KEM)) != 1088 {
		t.Fatalf("kem %d bytes", len(unb64(t, env.KEM)))
	}
	m, err := Unseal(env, priv, "имя/секрета")
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	for k, want := range payload {
		if m[k] != want {
			t.Errorf("payload[%s] = %v want %v", k, m[k], want)
		}
	}
	if _, err := Unseal(env, priv, "other"); err == nil {
		t.Error("another name must not open the envelope")
	}
	other, _, _ := GeneratePqcKeyPair()
	if _, err := Unseal(env, other, "имя/секрета"); err == nil {
		t.Error("another key must not open the envelope")
	}
	// two seals of the same payload differ (fresh epk/kem/nonce) and both open
	env2 := sealPqcForTest(t, pub, "имя/секрета", payload)
	if env2.KEM == env.KEM || env2.EPK == env.EPK {
		t.Error("sealing must use fresh ephemeral material")
	}
	if m, err := Unseal(env2, priv, "имя/секрета"); err != nil || m["value"] != "p@ss ✓" {
		t.Errorf("second seal: %v %v", err, m)
	}
	// the JSON round trip must keep kem (omitempty field) — otherwise decapsulation cannot run
	var back Secret
	raw, _ := json.Marshal(Secret{Sealed: &env})
	_ = json.Unmarshal(raw, &back)
	if back.Sealed == nil || back.Sealed.KEM != env.KEM {
		t.Fatal("kem lost in JSON round trip")
	}
}

func TestPqcSealedThroughClient(t *testing.T) {
	f := loadPqcFixture(t)
	e := f.Envelopes[0]
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/v1/m/secret/"+e.Name {
			w.WriteHeader(404)
			return
		}
		env := e.Sealed
		_ = json.NewEncoder(w).Encode(Secret{Name: e.Name, Version: 7, UpdatedAt: "x", Sealed: &env})
	}))
	defer srv.Close()
	c, err := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: f.Keypair.Private})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.GetFull(context.Background(), e.Name)
	if err != nil || s.Value != "pg-pass-2026" || s.Login != "core" || s.Notes != "hybrid fixture" || s.Sealed != nil || s.Version != 7 {
		t.Fatalf("pqc sealed via client: %v %+v", err, s)
	}
	if v, err := c.Get(context.Background(), e.Name); err != nil || v != "pg-pass-2026" || hits.Load() != 1 {
		t.Fatalf("cached get: %v %q hits=%d", err, v, hits.Load())
	}
	otherSK, _, _ := GeneratePqcKeyPair()
	wrong, _ := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: otherSK})
	if _, err := wrong.Get(context.Background(), e.Name); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("wrong key via client: %v", err)
	}
	// a hardware P-256 provider cannot open the hybrid envelope — refused, not mis-decrypted
	hw, _ := ecdh.P256().GenerateKey(rand.Reader)
	prov, _ := New(srv.URL, "vlt_test_token", Options{KeyProvider: scalarProvider{hw}})
	if _, err := prov.Get(context.Background(), e.Name); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("KeyProvider with a PQC envelope: %v", err)
	}
	t.Setenv("VAULT_CLIENT_KEY", "")
	noKey, _ := New(srv.URL, "vlt_test_token")
	if _, err := noKey.Get(context.Background(), e.Name); err == nil || !strings.Contains(err.Error(), "sealed values") {
		t.Fatalf("without a key the client must refuse, got %v", err)
	}
}

func TestEnrollPqc(t *testing.T) {
	var gotPk string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		gotPk = b["public_key"]
		_ = json.NewEncoder(w).Encode(map[string]any{"raw_token": "vlt_enrolled", "token_name": "node-" + b["name"], "folder_name": "f", "sealed": true})
	}))
	defer srv.Close()
	e, err := EnrollWith(context.Background(), srv.URL, "enr_ok", "host-pqc", "pqc", nil)
	if err != nil || e.Token != "vlt_enrolled" || e.PublicKey != gotPk {
		t.Fatalf("pqc enrol: %v %+v", err, e)
	}
	if pk := unb64(t, gotPk); len(pk) != 1216 {
		t.Fatalf("sent public_key is %d bytes, want 1216", len(pk))
	}
	if len(unb64(t, e.PrivateKey)) != 96 {
		t.Fatalf("private key is %d bytes, want 96", len(unb64(t, e.PrivateKey)))
	}
	// the returned pair is consistent and usable
	if derived, err := PqcPublicFromPrivate(e.PrivateKey); err != nil || derived != e.PublicKey {
		t.Fatalf("enrolled pair inconsistent: %v", err)
	}
	env := sealPqcForTest(t, e.PublicKey, "n", map[string]any{"value": "v"})
	if m, err := Unseal(env, e.PrivateKey, "n"); err != nil || m["value"] != "v" {
		t.Fatalf("enrolled key must open a seal to its public half: %v %v", err, m)
	}
}

// ── GOST post-quantum hybrid (0.32): clients/fixtures/gost-pqc-sealed.json ─────

type gostPqcFixture struct {
	Alg      string `json:"alg"`
	KdfLabel string `json:"kdf_label"`
	Keypair  struct {
		Private   string `json:"private_b64"`
		Public    string `json:"public_b64"`
		GostSkHex string `json:"gost_sk_hex"`
		SeedHex   string `json:"mlkem_seed_hex"`
	} `json:"keypair"`
	Envelopes []struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
		Sealed  SealedEnvelope `json:"sealed"`
	} `json:"envelopes"`
}

func loadGostPqcFixture(t *testing.T) gostPqcFixture {
	t.Helper()
	raw, err := os.ReadFile("../fixtures/gost-pqc-sealed.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var f gostPqcFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	if f.Alg != SealedAlgGOSTPQC || f.KdfLabel != string(sealedLabelGOSTPQC) {
		t.Fatalf("fixture alg/label %q %q do not match the client constants", f.Alg, f.KdfLabel)
	}
	if len(f.Envelopes) < 2 {
		t.Fatalf("fixture has %d envelopes, want at least 2", len(f.Envelopes))
	}
	return f
}

func TestGostPqcPublicFromPrivateFixture(t *testing.T) {
	f := loadGostPqcFixture(t)
	priv, pub := unb64(t, f.Keypair.Private), unb64(t, f.Keypair.Public)
	if len(priv) != 96 || len(pub) != 1248 {
		t.Fatalf("fixture key sizes %d/%d", len(priv), len(pub))
	}
	if hex.EncodeToString(priv[:32]) != f.Keypair.GostSkHex || hex.EncodeToString(priv[32:]) != f.Keypair.SeedHex {
		t.Fatal("private = gost scalar ‖ ml-kem seed")
	}
	got, err := GostPqcPublicFromPrivate(f.Keypair.Private)
	if err != nil {
		t.Fatal(err)
	}
	if got != f.Keypair.Public {
		t.Fatalf("public from private:\n got %s\nwant %s", got, f.Keypair.Public)
	}
	// the GOST half of the fixture is the plain GOST fixture key: same point
	g := loadGostFixture(t)
	if !bytes.Equal(pub[:64], unb64(t, g.Keypair.PublicB64)) {
		t.Error("the first 64 public bytes must be the plain GOST fixture point")
	}
	gostSK, _, _ := GenerateGostKeyPair()
	if _, err := GostPqcPublicFromPrivate(gostSK); err == nil || !strings.Contains(err.Error(), "96 bytes") {
		t.Errorf("32-byte key must be refused with a size error, got %v", err)
	}
	mine, minePub, err := GenerateGostPqcKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := GostPqcPublicFromPrivate(mine); got != minePub {
		t.Error("a generated pair must round-trip through GostPqcPublicFromPrivate")
	}
}

func TestUnsealGostPqcServerFixture(t *testing.T) {
	f := loadGostPqcFixture(t)
	sawCyrillic := false
	for _, e := range f.Envelopes {
		if e.Sealed.Alg != SealedAlgGOSTPQC || e.Sealed.V != 1 {
			t.Fatalf("fixture %q alg/v", e.Name)
		}
		if len(unb64(t, e.Sealed.KEM)) != 1088 || len(unb64(t, e.Sealed.EPK)) != 64 || len(unb64(t, e.Sealed.UKM)) != 8 || len(unb64(t, e.Sealed.Nonce)) != 16 {
			t.Fatalf("fixture %q field sizes changed", e.Name)
		}
		if strings.ContainsRune(e.Name, 'к') {
			sawCyrillic = true
		}
		m, err := Unseal(e.Sealed, f.Keypair.Private, e.Name)
		if err != nil {
			t.Fatalf("unseal %q: %v", e.Name, err)
		}
		for k, want := range e.Payload {
			if m[k] != want {
				t.Errorf("%q payload[%s] = %#v want %#v", e.Name, k, m[k], want)
			}
		}
		if len(m) != len(e.Payload) {
			t.Errorf("%q payload keys %v want %v", e.Name, m, e.Payload)
		}
	}
	if !sawCyrillic {
		t.Error("fixture must contain a Cyrillic secret name")
	}
}

func TestUnsealGostPqcNegative(t *testing.T) {
	f := loadGostPqcFixture(t)
	e := f.Envelopes[0]
	flip := func(b64 string, i int) string {
		b := unb64(t, b64)
		b[i] ^= 1
		return base64.StdEncoding.EncodeToString(b)
	}
	wrongKey := func(err error) bool { return err != nil && err.Error() == errSealedWrongKey.Error() }
	for _, c := range []struct {
		name string
		env  SealedEnvelope
	}{
		{"kem[0]", func() SealedEnvelope { x := e.Sealed; x.KEM = flip(x.KEM, 0); return x }()},
		{"kem[last]", func() SealedEnvelope { x := e.Sealed; x.KEM = flip(x.KEM, 1087); return x }()},
		{"epk", func() SealedEnvelope { x := e.Sealed; x.EPK = flip(x.EPK, 5); return x }()},
		{"ukm", func() SealedEnvelope { x := e.Sealed; x.UKM = flip(x.UKM, 0); return x }()},
		{"ct", func() SealedEnvelope { x := e.Sealed; x.CT = flip(x.CT, 0); return x }()},
		{"tag", func() SealedEnvelope { x := e.Sealed; x.CT = flip(x.CT, len(unb64(t, x.CT))-1); return x }()},
		{"nonce", func() SealedEnvelope { x := e.Sealed; x.Nonce = flip(x.Nonce, 2); return x }()},
	} {
		if _, err := Unseal(c.env, f.Keypair.Private, e.Name); !wrongKey(err) {
			t.Errorf("%s: want wrong-key error, got %v", c.name, err)
		}
	}
	if _, err := Unseal(e.Sealed, f.Keypair.Private, "other-name"); !wrongKey(err) {
		t.Errorf("wrong name: %v", err)
	}
	other, _, _ := GenerateGostPqcKeyPair()
	if _, err := Unseal(e.Sealed, other, e.Name); !wrongKey(err) {
		t.Errorf("another hybrid key: %v", err)
	}
	priv := unb64(t, f.Keypair.Private)
	half := append([]byte{}, priv...)
	half[40] ^= 1 // right GOST half, wrong seed
	if _, err := Unseal(e.Sealed, base64.StdEncoding.EncodeToString(half), e.Name); !wrongKey(err) {
		t.Errorf("wrong ML-KEM half: %v", err)
	}
	half = append([]byte{}, priv...)
	half[3] ^= 1 // wrong GOST half, right seed
	if _, err := Unseal(e.Sealed, base64.StdEncoding.EncodeToString(half), e.Name); !wrongKey(err) {
		t.Errorf("wrong GOST half: %v", err)
	}
	g := loadGostFixture(t)
	if _, err := Unseal(e.Sealed, g.Keypair.PrivateB64, e.Name); err == nil || !strings.Contains(err.Error(), "96 bytes") {
		t.Errorf("a plain 32-byte GOST key must be refused with a shape message, got %v", err)
	}
	if _, err := Unseal(g.Env.Sealed, f.Keypair.Private, g.Env.Name); err == nil {
		t.Error("the hybrid key must not open the plain GOST envelope")
	}
}

func TestGostPqcSealedThroughClient(t *testing.T) {
	f := loadGostPqcFixture(t)
	e := f.Envelopes[0]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/m/secret/"+e.Name {
			w.WriteHeader(404)
			return
		}
		env := e.Sealed
		_ = json.NewEncoder(w).Encode(Secret{Name: e.Name, Version: 7, UpdatedAt: "x", Sealed: &env})
	}))
	defer srv.Close()
	c, err := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: f.Keypair.Private})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.GetFull(context.Background(), e.Name)
	if err != nil || s.Value != "pg-pass-2026" || s.Login != "core" || s.Notes != "hybrid fixture" || s.Sealed != nil {
		t.Fatalf("gost-pqc sealed via client: %v %+v", err, s)
	}
	var back Secret
	raw, _ := json.Marshal(Secret{Sealed: &e.Sealed})
	_ = json.Unmarshal(raw, &back)
	if back.Sealed == nil || back.Sealed.UKM != e.Sealed.UKM || back.Sealed.KEM != e.Sealed.KEM {
		t.Fatal("ukm/kem lost in JSON round trip")
	}
	otherSK, _, _ := GenerateGostPqcKeyPair()
	wrong, _ := New(srv.URL, "vlt_test_token", Options{ClientPrivateKey: otherSK})
	if _, err := wrong.Get(context.Background(), e.Name); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("wrong key via client: %v", err)
	}
}
