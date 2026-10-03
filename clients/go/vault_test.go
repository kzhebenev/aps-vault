package vault

import (
	"bytes"
	"context"
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
