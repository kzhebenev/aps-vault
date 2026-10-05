package vault

// GOST sealed-delivery envelope (0.19): Streebog (GOST R 34.11-2012), HMAC-Streebog-256 and
// KDF_TREE (R 50.1.113), Kuznyechik (GOST R 34.12-2015), MGM (RFC 9058), the 256-bit curve
// id-tc26-gost-3410-2012-256-paramSetB with VKO (RFC 7836 §4.3). Standard library only; see
// clients/GOST-PORTING.md for the specification and clients/fixtures/gost-sealed.json for the
// vectors the tests reproduce. Constant tables live in gost_consts.go (generated).

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// SealedAlgGOST is the GOST envelope algorithm the vault emits for a token bound to a
// GOST R 34.10-2012 public key (64 bytes X‖Y little-endian).
const SealedAlgGOST = "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM"

var sealedLabelGOST = []byte("aps-vault/sealed-gost/v1")

// SealedAlgGOSTPQC (0.32) is the GOST post-quantum hybrid: VKO GOST R 34.10-2012 + ML-KEM-768, both secrets
// through KDF_TREE_GOSTR3411_2012_256, Kuznyechik-MGM on the wire. Client key = GOST point X‖Y (64) ‖ ML-KEM-768
// encapsulation key (1184) = 1248 bytes; private = GOST scalar big-endian (32) ‖ ML-KEM seed d‖z (64) = 96 bytes.
const SealedAlgGOSTPQC = "VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM"

var sealedLabelGOSTPQC = []byte("aps-vault/sealed-gost-pqc/v1")

const (
	gostPqcPrivateKeyLen = 32 + mlkem.SeedSize                // 96
	gostPqcPublicKeyLen  = 64 + mlkem.EncapsulationKeySize768 // 1248
)

var errSealedWrongKey = errors.New("vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)")

// ── Streebog — GOST R 34.11-2012 ─────────────────────────────────────────────

type streebogBlock = [64]byte

func streebogLPS(x *streebogBlock) {
	var out streebogBlock
	for i := 0; i < 8; i++ {
		w := streebogT[0][x[i]] ^ streebogT[1][x[i+8]] ^ streebogT[2][x[i+16]] ^ streebogT[3][x[i+24]] ^
			streebogT[4][x[i+32]] ^ streebogT[5][x[i+40]] ^ streebogT[6][x[i+48]] ^ streebogT[7][x[i+56]]
		binary.LittleEndian.PutUint64(out[8*i:], w)
	}
	*x = out
}

func streebogXor(a, b *streebogBlock) streebogBlock {
	var out streebogBlock
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// streebogE is the block cipher E(K, m) of the compression function.
func streebogE(k, m *streebogBlock) streebogBlock {
	key := *k
	s := streebogXor(&key, m)
	for i := 0; i < 12; i++ {
		streebogLPS(&s)
		for j := range key {
			key[j] ^= streebogC[i][j]
		}
		streebogLPS(&key)
		s = streebogXor(&s, &key)
	}
	return s
}

// streebogG is the compression function g(h, N, m) = E(LPS(h ^ N), m) ^ h ^ m.
func streebogG(h, n, m *streebogBlock) streebogBlock {
	k := streebogXor(h, n)
	streebogLPS(&k)
	e := streebogE(&k, m)
	e = streebogXor(&e, h)
	return streebogXor(&e, m)
}

// streebogAdd512 adds b to a as 512-bit little-endian integers (carry dropped).
func streebogAdd512(a *streebogBlock, b *streebogBlock) {
	var carry uint16
	for i := 0; i < 64; i++ {
		carry = uint16(a[i]) + uint16(b[i]) + (carry >> 8)
		a[i] = byte(carry)
	}
}

func streebogHash(data []byte, size int) []byte {
	var h, n, sigma streebogBlock
	if size == 32 {
		for i := range h {
			h[i] = 0x01
		}
	}
	var v512 streebogBlock
	v512[1] = 0x02
	for len(data) >= 64 {
		var m streebogBlock
		copy(m[:], data[:64])
		h = streebogG(&h, &n, &m)
		streebogAdd512(&n, &v512)
		streebogAdd512(&sigma, &m)
		data = data[64:]
	}
	var m streebogBlock
	r := copy(m[:], data)
	m[r] = 0x01
	h = streebogG(&h, &n, &m)
	var bits streebogBlock
	bits[0] = byte(r * 8)
	bits[1] = byte((r * 8) >> 8)
	streebogAdd512(&n, &bits)
	streebogAdd512(&sigma, &m)
	var zero streebogBlock
	h = streebogG(&h, &zero, &n)
	h = streebogG(&h, &zero, &sigma)
	out := make([]byte, size)
	copy(out, h[64-size:])
	return out
}

// Streebog256 is GOST R 34.11-2012 with a 256-bit digest.
func Streebog256(data []byte) []byte { return streebogHash(data, 32) }

// Streebog512 is GOST R 34.11-2012 with a 512-bit digest.
func Streebog512(data []byte) []byte { return streebogHash(data, 64) }

// hmacStreebog256 is RFC 2104 HMAC over Streebog-256 (R 50.1.113-2016, block size 64).
func hmacStreebog256(key, data []byte) []byte {
	if len(key) > 64 {
		key = Streebog256(key)
	}
	var ipad, opad [64]byte
	for i := 0; i < 64; i++ {
		var k byte
		if i < len(key) {
			k = key[i]
		}
		ipad[i] = k ^ 0x36
		opad[i] = k ^ 0x5C
	}
	inner := Streebog256(append(append([]byte{}, ipad[:]...), data...))
	return Streebog256(append(append([]byte{}, opad[:]...), inner...))
}

// kdfTree256 is KDF_TREE_GOSTR3411_2012_256 (R 50.1.113-2016 §4.5) for one 256-bit key:
// HMAC256(key, 0x01 ‖ label ‖ 0x00 ‖ seed ‖ 0x01 0x00).
func kdfTree256(key, label, seed []byte) []byte {
	msg := make([]byte, 0, 1+len(label)+1+len(seed)+2)
	msg = append(msg, 0x01)
	msg = append(msg, label...)
	msg = append(msg, 0x00)
	msg = append(msg, seed...)
	msg = append(msg, 0x01, 0x00)
	return hmacStreebog256(key, msg)
}

// ── Kuznyechik — GOST R 34.12-2015 ───────────────────────────────────────────

// u128 is a 128-bit block as a big-endian integer: byte 0 is the most significant byte of hi.
type u128 struct{ hi, lo uint64 }

func (a u128) xor(b u128) u128 { return u128{a.hi ^ b.hi, a.lo ^ b.lo} }

func u128FromBytes(b []byte) u128 {
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:16])}
}

func (a u128) bytes() [16]byte {
	var out [16]byte
	binary.BigEndian.PutUint64(out[:8], a.hi)
	binary.BigEndian.PutUint64(out[8:], a.lo)
	return out
}

// byteAt returns byte i (0 = most significant).
func (a u128) byteAt(i int) byte {
	if i < 8 {
		return byte(a.hi >> (8 * uint(7-i)))
	}
	return byte(a.lo >> (8 * uint(15-i)))
}

var kuznyechikLVec = [16]byte{148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1}

// gfMul multiplies in GF(2^8) with the polynomial x^8 + x^7 + x^6 + x + 1.
func gfMul(a, b byte) byte {
	var p byte
	x, y := uint16(a), b
	for y != 0 {
		if y&1 != 0 {
			p ^= byte(x)
		}
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x1C3
		}
		y >>= 1
	}
	return p
}

var (
	kuzOnce   sync.Once
	kuzPiInv  [256]byte
	kuzLS     [16][256]u128 // LS[i][x] = L(e_i · π[x])
	kuzLSI    [16][256]u128 // LSI[i][x] = L⁻¹(e_i · x)
	kuzRoundC [32]u128
)

func kuzLStep(s *[16]byte) {
	var acc byte
	for i := 0; i < 16; i++ {
		acc ^= gfMul(s[i], kuznyechikLVec[i])
	}
	copy(s[1:], s[:15])
	s[0] = acc
}

func kuzLInvStep(s *[16]byte) {
	a := s[0]
	copy(s[:15], s[1:])
	s[15] = 0
	var acc byte
	for i := 0; i < 16; i++ {
		acc ^= gfMul(s[i], kuznyechikLVec[i])
	}
	s[15] = a ^ acc
}

func kuzL(s [16]byte) [16]byte {
	for i := 0; i < 16; i++ {
		kuzLStep(&s)
	}
	return s
}

func kuzLInv(s [16]byte) [16]byte {
	for i := 0; i < 16; i++ {
		kuzLInvStep(&s)
	}
	return s
}

func kuzInit() {
	for i, v := range kuznyechikPi {
		kuzPiInv[v] = byte(i)
	}
	for pos := 0; pos < 16; pos++ {
		for x := 0; x < 256; x++ {
			var blk [16]byte
			blk[pos] = kuznyechikPi[x]
			l := kuzL(blk)
			kuzLS[pos][x] = u128FromBytes(l[:])
			var blk2 [16]byte
			blk2[pos] = byte(x)
			li := kuzLInv(blk2)
			kuzLSI[pos][x] = u128FromBytes(li[:])
		}
	}
	for i := 1; i <= 32; i++ {
		var blk [16]byte
		blk[15] = byte(i)
		l := kuzL(blk)
		kuzRoundC[i-1] = u128FromBytes(l[:])
	}
}

func kuzLS16(x u128) u128 {
	var acc u128
	for i := 0; i < 16; i++ {
		acc = acc.xor(kuzLS[i][x.byteAt(i)])
	}
	return acc
}

func kuzLInv16(x u128) u128 {
	var acc u128
	for i := 0; i < 16; i++ {
		acc = acc.xor(kuzLSI[i][x.byteAt(i)])
	}
	return acc
}

func kuzSInv16(x u128) u128 {
	b := x.bytes()
	for i := range b {
		b[i] = kuzPiInv[b[i]]
	}
	return u128FromBytes(b[:])
}

// kuznyechik is the GOST R 34.12-2015 block cipher with a 256-bit key.
type kuznyechik struct{ k [10]u128 }

func newKuznyechik(key []byte) (*kuznyechik, error) {
	if len(key) != 32 {
		return nil, errors.New("kuznyechik: key must be 32 bytes")
	}
	kuzOnce.Do(kuzInit)
	c := &kuznyechik{}
	k1, k2 := u128FromBytes(key[:16]), u128FromBytes(key[16:])
	c.k[0], c.k[1] = k1, k2
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			k1, k2 = kuzLS16(k1.xor(kuzRoundC[8*i+j])).xor(k2), k1
		}
		c.k[2*i+2], c.k[2*i+3] = k1, k2
	}
	return c, nil
}

func (c *kuznyechik) encrypt(x u128) u128 {
	for i := 0; i < 9; i++ {
		x = kuzLS16(x.xor(c.k[i]))
	}
	return x.xor(c.k[9])
}

func (c *kuznyechik) decrypt(x u128) u128 {
	x = x.xor(c.k[9])
	for i := 8; i >= 0; i-- {
		x = kuzSInv16(kuzLInv16(x)).xor(c.k[i])
	}
	return x
}

// EncryptBlock / DecryptBlock work on 16-byte blocks.
func (c *kuznyechik) EncryptBlock(block []byte) []byte {
	out := c.encrypt(u128FromBytes(block)).bytes()
	return out[:]
}

func (c *kuznyechik) DecryptBlock(block []byte) []byte {
	out := c.decrypt(u128FromBytes(block)).bytes()
	return out[:]
}

// ── MGM — R 1323565.1.026-2019 / RFC 9058 ────────────────────────────────────

const mgmTagSize = 16

// gf128Mul multiplies in GF(2^128) with f(w) = w^128 + w^7 + w^2 + w + 1 (bit 0 = w^0, big-endian).
func gf128Mul(a, b u128) u128 {
	var p u128
	for i := 0; i < 128; i++ {
		if b.lo&1 != 0 {
			p = p.xor(a)
		}
		carry := a.hi >> 63
		a.hi = (a.hi << 1) | (a.lo >> 63)
		a.lo <<= 1
		if carry != 0 {
			a.lo ^= 0x87
		}
		b.lo = (b.lo >> 1) | (b.hi << 63)
		b.hi >>= 1
	}
	return p
}

func mgmIncrR(x u128) u128 { x.lo++; return x }
func mgmIncrL(x u128) u128 { x.hi++; return x }

func mgmCheckNonce(nonce []byte) (u128, error) {
	if len(nonce) != 16 || nonce[0]&0x80 != 0 {
		return u128{}, errors.New("mgm: nonce must be 16 bytes with the top bit clear")
	}
	return u128FromBytes(nonce), nil
}

func mgmPadBlock(part []byte) u128 {
	var blk [16]byte
	copy(blk[:], part)
	return u128FromBytes(blk[:])
}

func mgmTag(c *kuznyechik, nonce u128, aad, ct []byte) [16]byte {
	z := c.encrypt(u128{nonce.hi | 1<<63, nonce.lo})
	var acc u128
	for _, part := range [][]byte{aad, ct} {
		for i := 0; i < len(part); i += 16 {
			end := i + 16
			if end > len(part) {
				end = len(part)
			}
			h := c.encrypt(z)
			acc = acc.xor(gf128Mul(h, mgmPadBlock(part[i:end])))
			z = mgmIncrL(z)
		}
	}
	h := c.encrypt(z)
	lens := u128{uint64(len(aad)) * 8, uint64(len(ct)) * 8}
	acc = acc.xor(gf128Mul(h, lens))
	return c.encrypt(acc).bytes()
}

func mgmKeystreamXor(c *kuznyechik, nonce u128, data []byte) []byte {
	out := make([]byte, len(data))
	y := c.encrypt(nonce)
	for i := 0; i < len(data); i += 16 {
		ks := c.encrypt(y).bytes()
		for j := 0; j < 16 && i+j < len(data); j++ {
			out[i+j] = data[i+j] ^ ks[j]
		}
		y = mgmIncrR(y)
	}
	return out
}

// mgmSeal returns ciphertext ‖ 16-byte tag.
func mgmSeal(c *kuznyechik, nonce, plaintext, aad []byte) ([]byte, error) {
	n, err := mgmCheckNonce(nonce)
	if err != nil {
		return nil, err
	}
	ct := mgmKeystreamXor(c, n, plaintext)
	tag := mgmTag(c, n, aad, ct)
	return append(ct, tag[:]...), nil
}

// mgmOpen verifies the tag in constant time and returns the plaintext.
func mgmOpen(c *kuznyechik, nonce, ciphertext, aad []byte) ([]byte, error) {
	n, err := mgmCheckNonce(nonce)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < mgmTagSize {
		return nil, errors.New("mgm: ciphertext too short")
	}
	ct, tag := ciphertext[:len(ciphertext)-mgmTagSize], ciphertext[len(ciphertext)-mgmTagSize:]
	expected := mgmTag(c, n, aad, ct)
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return nil, errors.New("mgm: tag mismatch")
	}
	return mgmKeystreamXor(c, n, ct), nil
}

// ── Curve id-tc26-gost-3410-2012-256-paramSetB and VKO ───────────────────────

type gostCurve struct {
	p, a, b, q, gx, gy *big.Int
}

var (
	curveOnce sync.Once
	curve     gostCurve
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("gost: bad curve constant " + s)
	}
	return n
}

func gostParams() *gostCurve {
	curveOnce.Do(func() {
		curve = gostCurve{p: mustHex(curveP), a: mustHex(curveA), b: mustHex(curveB),
			q: mustHex(curveQ), gx: mustHex(curveGX), gy: mustHex(curveGY)}
	})
	return &curve
}

// jacobian point (X, Y, Z) with x = X/Z², y = Y/Z²; Z = 0 is the point at infinity.
type jpoint struct{ x, y, z *big.Int }

// affine point; nil means the point at infinity.
type apoint struct{ x, y *big.Int }

func (c *gostCurve) jInfinity() jpoint {
	return jpoint{big.NewInt(0), big.NewInt(1), big.NewInt(0)}
}

func (c *gostCurve) jDouble(pt jpoint) jpoint {
	if pt.y.Sign() == 0 || pt.z.Sign() == 0 {
		return c.jInfinity()
	}
	p := c.p
	ysq := new(big.Int).Mul(pt.y, pt.y)
	ysq.Mod(ysq, p)
	s := new(big.Int).Mul(pt.x, ysq)
	s.Lsh(s, 2)
	s.Mod(s, p)
	zsq := new(big.Int).Mul(pt.z, pt.z)
	zsq.Mod(zsq, p)
	z4 := new(big.Int).Mul(zsq, zsq)
	z4.Mod(z4, p)
	m := new(big.Int).Mul(pt.x, pt.x)
	m.Mul(m, big.NewInt(3))
	az4 := new(big.Int).Mul(c.a, z4)
	m.Add(m, az4)
	m.Mod(m, p)
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, new(big.Int).Lsh(s, 1))
	x3.Mod(x3, p)
	y4 := new(big.Int).Mul(ysq, ysq)
	y4.Lsh(y4, 3)
	y3 := new(big.Int).Sub(s, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y4)
	y3.Mod(y3, p)
	z3 := new(big.Int).Mul(pt.y, pt.z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, p)
	return jpoint{x3, y3, z3}
}

func (c *gostCurve) jAdd(p1, p2 jpoint) jpoint {
	if p1.z.Sign() == 0 {
		return p2
	}
	if p2.z.Sign() == 0 {
		return p1
	}
	p := c.p
	z1sq := new(big.Int).Mul(p1.z, p1.z)
	z1sq.Mod(z1sq, p)
	z2sq := new(big.Int).Mul(p2.z, p2.z)
	z2sq.Mod(z2sq, p)
	u1 := new(big.Int).Mul(p1.x, z2sq)
	u1.Mod(u1, p)
	u2 := new(big.Int).Mul(p2.x, z1sq)
	u2.Mod(u2, p)
	s1 := new(big.Int).Mul(p1.y, z2sq)
	s1.Mul(s1, p2.z)
	s1.Mod(s1, p)
	s2 := new(big.Int).Mul(p2.y, z1sq)
	s2.Mul(s2, p1.z)
	s2.Mod(s2, p)
	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) != 0 {
			return c.jInfinity()
		}
		return c.jDouble(p1)
	}
	h := new(big.Int).Sub(u2, u1)
	h.Mod(h, p)
	r := new(big.Int).Sub(s2, s1)
	r.Mod(r, p)
	h2 := new(big.Int).Mul(h, h)
	h2.Mod(h2, p)
	h3 := new(big.Int).Mul(h2, h)
	h3.Mod(h3, p)
	u1h2 := new(big.Int).Mul(u1, h2)
	u1h2.Mod(u1h2, p)
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, h3)
	x3.Sub(x3, new(big.Int).Lsh(u1h2, 1))
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(u1h2, x3)
	y3.Mul(y3, r)
	y3.Sub(y3, new(big.Int).Mul(s1, h3))
	y3.Mod(y3, p)
	z3 := new(big.Int).Mul(h, p1.z)
	z3.Mul(z3, p2.z)
	z3.Mod(z3, p)
	return jpoint{x3, y3, z3}
}

func (c *gostCurve) toAffine(pt jpoint) *apoint {
	if pt.z.Sign() == 0 {
		return nil
	}
	zi := new(big.Int).ModInverse(pt.z, c.p)
	zi2 := new(big.Int).Mul(zi, zi)
	zi2.Mod(zi2, c.p)
	x := new(big.Int).Mul(pt.x, zi2)
	x.Mod(x, c.p)
	y := new(big.Int).Mul(pt.y, zi2)
	y.Mul(y, zi)
	y.Mod(y, c.p)
	return &apoint{x, y}
}

// mul is k·pt by double-and-add in Jacobian coordinates (one inversion). Not constant-time:
// the vault's ephemeral scalars are single-use and the client's key runs on the client's own
// machine, the same model as the X25519 envelope.
func (c *gostCurve) mul(k *big.Int, pt *apoint) *apoint {
	k = new(big.Int).Mod(k, c.q)
	if k.Sign() == 0 || pt == nil {
		return nil
	}
	result := c.jInfinity()
	addend := jpoint{new(big.Int).Set(pt.x), new(big.Int).Set(pt.y), big.NewInt(1)}
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = c.jAdd(result, addend)
		}
		addend = c.jDouble(addend)
	}
	return c.toAffine(result)
}

func (c *gostCurve) onCurve(pt *apoint) bool {
	if pt == nil || pt.x.Sign() < 0 || pt.y.Sign() < 0 || pt.x.Cmp(c.p) >= 0 || pt.y.Cmp(c.p) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(pt.y, pt.y)
	lhs.Mod(lhs, c.p)
	rhs := new(big.Int).Mul(pt.x, pt.x)
	rhs.Mul(rhs, pt.x)
	rhs.Add(rhs, new(big.Int).Mul(c.a, pt.x))
	rhs.Add(rhs, c.b)
	rhs.Mod(rhs, c.p)
	return lhs.Cmp(rhs) == 0
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// encodePoint is the GOST form: X ‖ Y, each 32 bytes little-endian.
func encodePoint(pt *apoint) []byte {
	var xb, yb [32]byte
	pt.x.FillBytes(xb[:])
	pt.y.FillBytes(yb[:])
	return append(reverseBytes(xb[:]), reverseBytes(yb[:])...)
}

// decodePoint parses X ‖ Y little-endian and validates the point is on the curve
// (prime order, cofactor 1 ⇒ on the curve means in the group).
func (c *gostCurve) decodePoint(raw []byte) (*apoint, error) {
	if len(raw) != 64 {
		return nil, errors.New("gost: public key must be 64 bytes (X‖Y little-endian)")
	}
	pt := &apoint{new(big.Int).SetBytes(reverseBytes(raw[:32])), new(big.Int).SetBytes(reverseBytes(raw[32:]))}
	if !c.onCurve(pt) {
		return nil, errors.New("gost: point is not on the curve")
	}
	return pt, nil
}

func (c *gostCurve) generator() *apoint { return &apoint{c.gx, c.gy} }

func (c *gostCurve) publicFromPrivate(d *big.Int) *apoint { return c.mul(d, c.generator()) }

// GenerateGostKeyPair returns (privateB64, publicB64) for the GOST envelope: the private key is a
// 32-byte big-endian scalar 1 ≤ d < q, the public key the 64-byte X‖Y little-endian point, both
// in standard base64. Give the public half to the vault administrator (token field
// client_public_key); keep the private half with the token.
func GenerateGostKeyPair() (string, string, error) {
	c := gostParams()
	qm1 := new(big.Int).Sub(c.q, big.NewInt(1))
	d, err := rand.Int(rand.Reader, qm1)
	if err != nil {
		return "", "", err
	}
	d.Add(d, big.NewInt(1))
	var sk [32]byte
	d.FillBytes(sk[:])
	pub := encodePoint(c.publicFromPrivate(d))
	return base64.StdEncoding.EncodeToString(sk[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// vko is VKO_GOSTR3410_2012_256 (RFC 7836 §4.3): Streebog-256 of X‖Y little-endian of UKM·d·Q,
// with UKM an 8-byte little-endian integer ≥ 1.
func (c *gostCurve) vko(d *big.Int, peer *apoint, ukm []byte) ([]byte, error) {
	if len(ukm) != 8 {
		return nil, errors.New("gost: UKM must be 8 bytes")
	}
	u := new(big.Int).SetBytes(reverseBytes(ukm))
	if u.Sign() == 0 {
		return nil, errors.New("gost: UKM must be non-zero")
	}
	k := new(big.Int).Mul(u, d)
	k.Mod(k, c.q)
	shared := c.mul(k, peer)
	if shared == nil {
		return nil, errors.New("gost: degenerate shared point")
	}
	return Streebog256(encodePoint(shared)), nil
}

// parseGostPrivate decodes a base64 32-byte big-endian scalar in [1, q-1].
func (c *gostCurve) parseGostPrivate(privateKeyB64 string) (*big.Int, error) {
	skb, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("vault: client private key is not base64: %w", err)
	}
	if len(skb) != 32 {
		return nil, fmt.Errorf("vault: client private key: GOST key must be 32 bytes, got %d", len(skb))
	}
	d := new(big.Int).SetBytes(skb)
	if d.Sign() == 0 || d.Cmp(c.q) >= 0 {
		return nil, errors.New("vault: client private key: GOST scalar out of range")
	}
	return d, nil
}

// unsealGost opens the GOST envelope: VKO(d, epk, ukm) → KEK; KDF_TREE(KEK, label, epk ‖ our_pk)
// → key; Kuznyechik-MGM with AAD = name. Any cryptographic failure maps to errSealedWrongKey.
func unsealGost(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
	c := gostParams()
	d, err := c.parseGostPrivate(privateKeyB64)
	if err != nil {
		return nil, err
	}
	epkb, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope epk: %w", err)
	}
	ukm, err := base64.StdEncoding.DecodeString(env.UKM)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope ukm: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("vault: sealed envelope ct: %w", err)
	}
	epk, err := c.decodePoint(epkb)
	if err != nil {
		return nil, errSealedWrongKey
	}
	ourPK := encodePoint(c.publicFromPrivate(d))
	kek, err := c.vko(d, epk, ukm)
	if err != nil {
		return nil, errSealedWrongKey
	}
	seed := append(append([]byte{}, epkb...), ourPK...)
	key := kdfTree256(kek, sealedLabelGOST, seed)
	cipher, err := newKuznyechik(key)
	if err != nil {
		return nil, err
	}
	pt, err := mgmOpen(cipher, nonce, ct, []byte(name))
	if err != nil {
		return nil, errSealedWrongKey
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// ── GOST post-quantum hybrid (0.32) ───────────────────────────────────────────

// GenerateGostPqcKeyPair returns (privateB64, publicB64) for the GOST hybrid envelope: a fresh GOST R 34.10-2012
// scalar and a fresh ML-KEM-768 pair stored as its 64-byte seed, from which every client library derives the
// same encapsulation key (see GostPqcPublicFromPrivate).
func GenerateGostPqcKeyPair() (string, string, error) {
	c := gostParams()
	qm1 := new(big.Int).Sub(c.q, big.NewInt(1))
	d, err := rand.Int(rand.Reader, qm1)
	if err != nil {
		return "", "", err
	}
	d.Add(d, big.NewInt(1))
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", "", err
	}
	var sk [32]byte
	d.FillBytes(sk[:])
	priv := append(append([]byte{}, sk[:]...), dk.Bytes()...)
	pub := append(append([]byte{}, encodePoint(c.publicFromPrivate(d))...), dk.EncapsulationKey().Bytes()...)
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// parseGostPqcPrivate splits the 96-byte GOST hybrid private key into the GOST scalar and the ML-KEM-768 key.
func (c *gostCurve) parseGostPqcPrivate(privateKeyB64 string) (*big.Int, *mlkem.DecapsulationKey768, error) {
	skb, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: client private key is not base64: %w", err)
	}
	if len(skb) != gostPqcPrivateKeyLen {
		return nil, nil, fmt.Errorf("vault: GOST hybrid private key must be %d bytes (GOST R 34.10-2012 scalar ‖ ML-KEM-768 seed), got %d", gostPqcPrivateKeyLen, len(skb))
	}
	d := new(big.Int).SetBytes(skb[:32])
	if d.Sign() == 0 || d.Cmp(c.q) >= 0 {
		return nil, nil, errors.New("vault: client private key: GOST scalar out of range")
	}
	dk, err := mlkem.NewDecapsulationKey768(skb[32:])
	if err != nil {
		return nil, nil, fmt.Errorf("vault: client private key (ML-KEM-768 seed): %w", err)
	}
	return d, dk, nil
}

// GostPqcPublicFromPrivate returns the 1248-byte public key (base64) that belongs to a 96-byte GOST hybrid
// private key — what the vault administrator enters as client_public_key.
func GostPqcPublicFromPrivate(privateKeyB64 string) (string, error) {
	c := gostParams()
	d, dk, err := c.parseGostPqcPrivate(privateKeyB64)
	if err != nil {
		return "", err
	}
	pub := append(append([]byte{}, encodePoint(c.publicFromPrivate(d))...), dk.EncapsulationKey().Bytes()...)
	return base64.StdEncoding.EncodeToString(pub), nil
}

// unsealGostPqc opens the GOST hybrid envelope: KEK = VKO(d, epk, ukm); ss = ML-KEM-768.Decaps(dk, kem);
// key = KDF_TREE(KEK ‖ ss, label, epk ‖ kem); Kuznyechik-MGM with AAD = name. Key-shape errors are reported as
// such; every cryptographic failure maps to errSealedWrongKey.
func unsealGostPqc(env SealedEnvelope, privateKeyB64, name string) (map[string]any, error) {
	c := gostParams()
	d, dk, err := c.parseGostPqcPrivate(privateKeyB64)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{"epk": env.EPK, "ukm": env.UKM, "kem": env.KEM, "nonce": env.Nonce, "ct": env.CT}
	raw := map[string][]byte{}
	for k, v := range fields {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("vault: sealed envelope %s: %w", k, err)
		}
		raw[k] = b
	}
	if len(raw["kem"]) != mlkem.CiphertextSize768 {
		return nil, errSealedWrongKey
	}
	epk, err := c.decodePoint(raw["epk"])
	if err != nil {
		return nil, errSealedWrongKey
	}
	kek, err := c.vko(d, epk, raw["ukm"])
	if err != nil {
		return nil, errSealedWrongKey
	}
	ss, err := dk.Decapsulate(raw["kem"]) // implicit rejection: a tampered kem yields a different secret, not an error
	if err != nil {
		return nil, errSealedWrongKey
	}
	seed := append(append([]byte{}, raw["epk"]...), raw["kem"]...)
	key := kdfTree256(append(append([]byte{}, kek...), ss...), sealedLabelGOSTPQC, seed)
	cipher, err := newKuznyechik(key)
	if err != nil {
		return nil, err
	}
	pt, err := mgmOpen(cipher, raw["nonce"], raw["ct"], []byte(name))
	if err != nil {
		return nil, errSealedWrongKey
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}
