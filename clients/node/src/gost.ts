/**
 * GOST cryptography for the sealed-delivery envelope (APS Vault 0.19), pure TypeScript, no
 * dependencies — see clients/GOST-PORTING.md for the specification and
 * clients/fixtures/gost-sealed.json for the vectors every port must reproduce.
 *
 *  - Streebog (GOST R 34.11-2012) 256/512, HMAC-Streebog-256, KDF_TREE_GOSTR3411_2012_256
 *  - Kuznyechik (GOST R 34.12-2015) with precomputed LS tables
 *  - MGM (R 1323565.1.026-2019 / RFC 9058) AEAD over Kuznyechik
 *  - curve id-tc26-gost-3410-2012-256-paramSetB (Jacobian coordinates, BigInt) and VKO (RFC 7836 §4.3)
 *  - the envelope: unsealGost() and generateGostKeyPair()
 *  - the GOST post-quantum hybrid (0.32): VKO + ML-KEM-768 (@noble/post-quantum) → KDF_TREE → Kuznyechik-MGM —
 *    unsealGostPqc() and generateGostPqcKeyPair()
 *
 * Algorithm-level conformance, verified against the published test vectors; not a certified СКЗИ.
 */
import { randomBytes } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { STREEBOG_T, STREEBOG_C, KUZNYECHIK_PI, CURVE } from './gost-consts.js';

export class GostError extends Error {
  constructor(message: string) { super(message); this.name = 'GostError'; }
}

const concat = (...parts: Uint8Array[]): Uint8Array => {
  let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// ── Streebog — GOST R 34.11-2012 ──────────────────────────────────────────────
// T as two Uint32Array halves (lo/hi) so LPS runs on 32-bit numbers, not BigInt.
const T_LO = new Uint32Array(8 * 256);
const T_HI = new Uint32Array(8 * 256);
for (let i = 0; i < 8; i++) for (let x = 0; x < 256; x++) {
  const v = STREEBOG_T[i][x];
  T_LO[i * 256 + x] = Number(v & 0xffffffffn);
  T_HI[i * 256 + x] = Number(v >> 32n);
}

function lps(x: Uint8Array): Uint8Array {
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    let lo = 0, hi = 0;
    for (let j = 0; j < 8; j++) {
      const idx = j * 256 + x[i + 8 * j];
      lo ^= T_LO[idx]; hi ^= T_HI[idx];
    }
    const o = 8 * i;                              // little-endian encoding of the 64-bit word
    out[o] = lo & 0xff; out[o + 1] = (lo >>> 8) & 0xff; out[o + 2] = (lo >>> 16) & 0xff; out[o + 3] = lo >>> 24;
    out[o + 4] = hi & 0xff; out[o + 5] = (hi >>> 8) & 0xff; out[o + 6] = (hi >>> 16) & 0xff; out[o + 7] = hi >>> 24;
  }
  return out;
}

function xor64(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = a[i] ^ b[i];
  return out;
}

function add512(a: Uint8Array, b: Uint8Array): Uint8Array {   // little-endian, carry dropped
  const out = new Uint8Array(64);
  let c = 0;
  for (let i = 0; i < 64; i++) { c = a[i] + b[i] + (c >> 8); out[i] = c & 0xff; }
  return out;
}

function streebogE(K: Uint8Array, m: Uint8Array): Uint8Array {
  let s = xor64(K, m);
  for (let i = 0; i < 12; i++) {
    s = lps(s);
    K = lps(xor64(K, STREEBOG_C[i]));
    s = xor64(s, K);
  }
  return s;
}

const streebogG = (h: Uint8Array, N: Uint8Array, m: Uint8Array): Uint8Array =>
  xor64(xor64(streebogE(lps(xor64(h, N)), m), h), m);

const V512 = new Uint8Array(64); V512[1] = 0x02;
const V0 = new Uint8Array(64);

function streebog(data: Uint8Array, outLen: 32 | 64): Uint8Array {
  let h: Uint8Array = new Uint8Array(64); if (outLen === 32) h.fill(0x01);
  let N: Uint8Array = new Uint8Array(64), S: Uint8Array = new Uint8Array(64);
  const full = data.length - (data.length % 64);
  for (let off = 0; off < full; off += 64) {
    const m = data.subarray(off, off + 64);
    h = streebogG(h, N, m); N = add512(N, V512); S = add512(S, m);
  }
  const r = data.length - full;
  const m = new Uint8Array(64); m.set(data.subarray(full)); m[r] = 0x01;
  const bits = new Uint8Array(64); bits[0] = (r * 8) & 0xff; bits[1] = (r * 8) >> 8;
  h = streebogG(h, N, m); N = add512(N, bits); S = add512(S, m);
  h = streebogG(h, V0, N);
  h = streebogG(h, V0, S);
  return h.slice(64 - outLen);
}

export const streebog256 = (data: Uint8Array): Uint8Array => streebog(data, 32);
export const streebog512 = (data: Uint8Array): Uint8Array => streebog(data, 64);

/** HMAC (RFC 2104, block 64) over Streebog-256 — R 50.1.113-2016; long keys are hashed first. */
export function hmacStreebog256(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length > 64) key = streebog256(key);
  const k = new Uint8Array(64); k.set(key);
  const ipad = k.map(b => b ^ 0x36), opad = k.map(b => b ^ 0x5c);
  return streebog256(concat(opad, streebog256(concat(ipad, data))));
}

/** KDF_TREE_GOSTR3411_2012_256 (R 50.1.113 §4.5): K(i) = HMAC256(key, i ‖ label ‖ 0x00 ‖ seed ‖ L), returns keys × 32 bytes. */
export function kdfTree256(key: Uint8Array, label: Uint8Array, seed: Uint8Array, keys = 1): Uint8Array {
  if (keys < 1 || keys > 255) throw new GostError('kdf_tree: keys out of range');
  const L = 256 * keys;
  const out: Uint8Array[] = [];
  for (let i = 1; i <= keys; i++)
    out.push(hmacStreebog256(key, concat(Uint8Array.of(i), label, Uint8Array.of(0), seed, Uint8Array.of(L >> 8, L & 0xff))));
  return concat(...out);
}

// ── Kuznyechik — GOST R 34.12-2015 ────────────────────────────────────────────
// Blocks are Uint8Array(16), byte 0 the most significant (a₀ in the standard).
const PI = KUZNYECHIK_PI;
const PI_INV = new Uint8Array(256);
for (let i = 0; i < 256; i++) PI_INV[PI[i]] = i;
const LVEC = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1];

function gfMul(a: number, b: number): number {        // GF(2^8), x^8 + x^7 + x^6 + x + 1
  let p = 0;
  while (b) {
    if (b & 1) p ^= a;
    a <<= 1;
    if (a & 0x100) a ^= 0x1c3;
    b >>= 1;
  }
  return p;
}
// MULL[x * 16 + i] = x · LVEC[i]
const MULL = new Uint8Array(256 * 16);
for (let x = 0; x < 256; x++) for (let i = 0; i < 16; i++) MULL[x * 16 + i] = gfMul(x, LVEC[i]);

function ell(s: Uint8Array): number {                   // ℓ(a₀..a₁₅)
  let acc = 0;
  for (let i = 0; i < 16; i++) acc ^= MULL[s[i] * 16 + i];
  return acc;
}

function L(block: Uint8Array): Uint8Array {              // R¹⁶: shift right, new byte 0 = ℓ(state)
  const s = Uint8Array.from(block);
  for (let r = 0; r < 16; r++) {
    const acc = ell(s);
    s.copyWithin(1, 0, 15); s[0] = acc;
  }
  return s;
}

function Linv(block: Uint8Array): Uint8Array {           // (R⁻¹)¹⁶: shift left, a₁₅' = a₀ ⊕ ℓ(a₁..a₁₅, 0)
  const s = Uint8Array.from(block);
  for (let r = 0; r < 16; r++) {
    const a0 = s[0];
    s.copyWithin(0, 1, 16); s[15] = 0;
    s[15] = a0 ^ ell(s);
  }
  return s;
}

// LS[((i << 8) | x) << 4 .. +16] = L(e_i · π[x]);  LSI likewise with L⁻¹(e_i · x).
// L is linear over GF(2), so each table is built from 16 × 8 basis images L(e_i · 2^bit) (128 evaluations
// of L instead of 4096) and XORs of those — this keeps module load well under 100 ms.
const LS = new Uint8Array(16 * 256 * 16);
const LSI = new Uint8Array(16 * 256 * 16);
{
  const basis = (fn: (b: Uint8Array) => Uint8Array): Uint8Array[][] => {
    const out: Uint8Array[][] = [];
    const blk = new Uint8Array(16);
    for (let pos = 0; pos < 16; pos++) {
      const row: Uint8Array[] = [];
      for (let bit = 0; bit < 8; bit++) { blk.fill(0); blk[pos] = 1 << bit; row.push(fn(blk)); }
      out.push(row);
    }
    return out;
  };
  const fill = (table: Uint8Array, basisImages: Uint8Array[][], map: (x: number) => number) => {
    for (let pos = 0; pos < 16; pos++) for (let x = 0; x < 256; x++) {
      const v = map(x), o = ((pos << 8) | x) << 4;
      for (let bit = 0; bit < 8; bit++) if (v & (1 << bit)) {
        const img = basisImages[pos][bit];
        for (let j = 0; j < 16; j++) table[o + j] ^= img[j];
      }
    }
  };
  fill(LS, basis(L), x => PI[x]);
  fill(LSI, basis(Linv), x => x);
}

function lsBlock(x: Uint8Array): Uint8Array {            // L(S(x))
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const base = ((i << 8) | x[i]) << 4;
    for (let j = 0; j < 16; j++) out[j] ^= LS[base + j];
  }
  return out;
}

function linvBlock(x: Uint8Array): Uint8Array {          // L⁻¹(x)
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const base = ((i << 8) | x[i]) << 4;
    for (let j = 0; j < 16; j++) out[j] ^= LSI[base + j];
  }
  return out;
}

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

// round constants C_i = L(Vec₁₂₈(i)), i = 1..32
const KC: Uint8Array[] = [];
for (let i = 1; i <= 32; i++) { const b = new Uint8Array(16); b[15] = i; KC.push(L(b)); }

export class Kuznyechik {
  private readonly k: Uint8Array[];
  constructor(key: Uint8Array) {
    if (key.length !== 32) throw new GostError('Kuznyechik key must be 32 bytes');
    let k1: Uint8Array = Uint8Array.from(key.subarray(0, 16)), k2: Uint8Array = Uint8Array.from(key.subarray(16));
    const keys = [k1, k2];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 8; j++) {
        const n1 = xor16(lsBlock(xor16(k1, KC[8 * i + j])), k2);
        k2 = k1; k1 = n1;
      }
      keys.push(k1, k2);
    }
    this.k = keys;
  }
  encryptBlock(block: Uint8Array): Uint8Array {
    let x = block;
    for (let i = 0; i < 9; i++) x = lsBlock(xor16(x, this.k[i]));
    return xor16(x, this.k[9]);
  }
  decryptBlock(block: Uint8Array): Uint8Array {
    let x = xor16(block, this.k[9]);
    for (let i = 8; i >= 0; i--) {
      const y = linvBlock(x);
      for (let j = 0; j < 16; j++) y[j] = PI_INV[y[j]];
      x = xor16(y, this.k[i]);
    }
    return x;
  }
}

// ── MGM — RFC 9058 / R 1323565.1.026-2019 ─────────────────────────────────────
const MASK128 = (1n << 128n) - 1n;
const toBig = (b: Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex'));
const fromBig = (v: bigint, len: number): Uint8Array => Uint8Array.from(Buffer.from(v.toString(16).padStart(len * 2, '0'), 'hex'));

function gf128Mul(a: bigint, b: bigint): bigint {       // f(w) = w¹²⁸ + w⁷ + w² + w + 1, big-endian integers
  let p = 0n;
  for (let i = 0; i < 128; i++) {
    if (b & 1n) p ^= a;
    const carry = a >> 127n;
    a = (a << 1n) & MASK128;
    if (carry) a ^= 0x87n;
    b >>= 1n;
  }
  return p;
}

function incrHalf(x: Uint8Array, from: number): void {   // increment bytes [from, from+8) big-endian in place
  for (let i = from + 7; i >= from; i--) { x[i] = (x[i] + 1) & 0xff; if (x[i] !== 0) break; }
}

export class MGM {
  static readonly TAG = 16;
  static readonly NONCE = 16;
  constructor(private readonly cipher: Kuznyechik) {}

  private checkNonce(nonce: Uint8Array): void {
    if (nonce.length !== 16 || nonce[0] & 0x80) throw new GostError('MGM nonce must be 16 bytes with the top bit clear');
  }

  private tag(nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
    const enc = (b: Uint8Array) => this.cipher.encryptBlock(b);
    const z = Uint8Array.from(nonce); z[0] |= 0x80;
    let Z = enc(z);
    let acc = 0n;
    for (const part of [aad, ct]) {
      for (let off = 0; off < part.length; off += 16) {
        const blk = new Uint8Array(16); blk.set(part.subarray(off, Math.min(off + 16, part.length)));
        acc ^= gf128Mul(toBig(enc(Z)), toBig(blk));
        incrHalf(Z, 0);
      }
    }
    const len = new Uint8Array(16);
    new DataView(len.buffer).setBigUint64(0, BigInt(aad.length) * 8n);
    new DataView(len.buffer).setBigUint64(8, BigInt(ct.length) * 8n);
    acc ^= gf128Mul(toBig(enc(Z)), toBig(len));
    return enc(fromBig(acc, 16));
  }

  private keystreamXor(nonce: Uint8Array, data: Uint8Array): Uint8Array {
    const Y = this.cipher.encryptBlock(nonce);
    const out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += 16) {
      const ks = this.cipher.encryptBlock(Y);
      const n = Math.min(16, data.length - off);
      for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
      incrHalf(Y, 8);
    }
    return out;
  }

  seal(nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    this.checkNonce(nonce);
    const ct = this.keystreamXor(nonce, plaintext);
    return concat(ct, this.tag(nonce, aad, ct));
  }

  open(nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    this.checkNonce(nonce);
    if (ciphertext.length < MGM.TAG) throw new GostError('MGM ciphertext too short');
    const ct = ciphertext.subarray(0, ciphertext.length - MGM.TAG), tag = ciphertext.subarray(ciphertext.length - MGM.TAG);
    const expected = this.tag(nonce, aad, ct);
    let diff = 0;                                   // constant-time compare
    for (let i = 0; i < MGM.TAG; i++) diff |= expected[i] ^ tag[i];
    if (diff !== 0) throw new GostError('MGM tag mismatch');
    return this.keystreamXor(nonce, ct);
  }
}

export function mgmNonce(): Uint8Array {
  const n = Uint8Array.from(randomBytes(16)); n[0] &= 0x7f; return n;
}

// ── Curve id-tc26-gost-3410-2012-256-paramSetB and VKO (RFC 7836 §4.3) ─────────
const { P, A, B, Q, GX, GY } = CURVE;
export type Point = { x: bigint; y: bigint } | null;     // null = point at infinity
type Jac = [bigint, bigint, bigint];
const JINF: Jac = [0n, 1n, 0n];

const mod = (a: bigint, m: bigint = P): bigint => { const r = a % m; return r < 0n ? r + m : r; };

function inv(a: bigint): bigint {                       // extended Euclid, a⁻¹ mod P
  let [r0, r1] = [mod(a), P], [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new GostError('not invertible');
  return mod(s0);
}

function jDouble([X1, Y1, Z1]: Jac): Jac {
  if (Y1 === 0n) return JINF;
  const S = mod(4n * X1 * Y1 * Y1);
  const Z1sq = mod(Z1 * Z1);
  const M = mod(3n * X1 * X1 + A * Z1sq * Z1sq);
  const X3 = mod(M * M - 2n * S);
  const Y1sq = mod(Y1 * Y1);
  const Y3 = mod(M * (S - X3) - 8n * Y1sq * Y1sq);
  const Z3 = mod(2n * Y1 * Z1);
  return [X3, Y3, Z3];
}

function jAdd(p1: Jac, p2: Jac): Jac {
  if (p1[2] === 0n) return p2;
  if (p2[2] === 0n) return p1;
  const [X1, Y1, Z1] = p1, [X2, Y2, Z2] = p2;
  const Z1sq = mod(Z1 * Z1), Z2sq = mod(Z2 * Z2);
  const U1 = mod(X1 * Z2sq), U2 = mod(X2 * Z1sq);
  const S1 = mod(Y1 * Z2sq * Z2), S2 = mod(Y2 * Z1sq * Z1);
  if (U1 === U2) return S1 !== S2 ? JINF : jDouble(p1);
  const H = mod(U2 - U1), R = mod(S2 - S1);
  const H2 = mod(H * H), H3 = mod(H2 * H);
  const X3 = mod(R * R - H3 - 2n * U1 * H2);
  const Y3 = mod(R * (U1 * H2 - X3) - S1 * H3);
  const Z3 = mod(H * Z1 * Z2);
  return [X3, Y3, Z3];
}

function toAffine([X, Y, Z]: Jac): Point {
  if (Z === 0n) return null;
  const zi = inv(Z), zi2 = mod(zi * zi);
  return { x: mod(X * zi2), y: mod(Y * zi2 * zi) };
}

/** k·pt by double-and-add in Jacobian coordinates (not constant-time — same model as the X25519 path's libraries). */
export function pointMul(k: bigint, pt: Point): Point {
  k = mod(k, Q);
  if (k === 0n || pt === null) return null;
  let result = JINF, addend: Jac = [pt.x, pt.y, 1n];
  while (k > 0n) {
    if (k & 1n) result = jAdd(result, addend);
    addend = jDouble(addend);
    k >>= 1n;
  }
  return toAffine(result);
}

export function onCurve(pt: Point): boolean {
  if (pt === null) return false;
  const { x, y } = pt;
  return x >= 0n && x < P && y >= 0n && y < P && mod(y * y - (x * x * x + A * x + B)) === 0n;
}

const G: Point = { x: GX, y: GY };

const leBytes = (v: bigint, len: number): Uint8Array => fromBig(v, len).reverse();
const leInt = (b: Uint8Array): bigint => toBig(Uint8Array.from(b).reverse());

/** X ‖ Y, each 32 bytes little-endian (the GOST encoding). */
export function encodePoint(pt: Point): Uint8Array {
  if (pt === null) throw new GostError('cannot encode the point at infinity');
  return concat(leBytes(pt.x, 32), leBytes(pt.y, 32));
}

/** Decode and validate a 64-byte X ‖ Y little-endian point; cofactor 1 ⇒ on the curve means in the group. */
export function decodePoint(raw: Uint8Array): Point {
  if (raw.length !== 64) throw new GostError('GOST public key must be 64 bytes (X‖Y little-endian)');
  const pt: Point = { x: leInt(raw.subarray(0, 32)), y: leInt(raw.subarray(32)) };
  if (!onCurve(pt)) throw new GostError('point is not on the GOST curve');
  return pt;
}

export function publicFromPrivate(d: bigint): Point { return pointMul(d, G); }

export function generatePrivate(): bigint {
  for (;;) {
    const d = toBig(randomBytes(32));
    if (d >= 1n && d < Q) return d;
  }
}

/** A GOST R 34.10-2012 key pair: private = 32-byte big-endian scalar, public = X‖Y little-endian 64 bytes, both standard base64. */
export function generateGostKeyPair(): { privateKey: string; publicKey: string } {
  const d = generatePrivate();
  return {
    privateKey: Buffer.from(fromBig(d, 32)).toString('base64'),
    publicKey: Buffer.from(encodePoint(publicFromPrivate(d))).toString('base64'),
  };
}

/** VKO_GOSTR3410_2012_256: Streebog-256( X‖Y little-endian of (UKM·d)·peer ), UKM 8 bytes little-endian ≥ 1. */
export function vko(d: bigint, peer: Point, ukm: Uint8Array): Uint8Array {
  if (ukm.length !== 8) throw new GostError('UKM must be 8 bytes');
  const u = leInt(ukm);
  if (u === 0n) throw new GostError('UKM must be non-zero');
  const shared = pointMul(mod(u * d, Q), peer);
  if (shared === null) throw new GostError('degenerate shared point');
  return streebog256(encodePoint(shared));
}

// ── The envelope ──────────────────────────────────────────────────────────────
export const SEALED_ALG_GOST = 'VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM';
const LABEL_GOST = Buffer.from('aps-vault/sealed-gost/v1');

export interface GostSealedEnvelope { alg: string; v: number; epk: string; ukm: string; nonce: string; ct: string; }

const b64 = (s: string, len?: number): Uint8Array => {
  const b = Uint8Array.from(Buffer.from(String(s ?? ''), 'base64'));
  if (len !== undefined && b.length !== len) throw new GostError(`expected ${len} bytes, got ${b.length}`);
  return b;
};

/**
 * Open a GOST envelope with the 32-byte big-endian private scalar (base64) for secret `name` (the AAD).
 * Any failure — point off the curve, wrong key, tampered ciphertext, wrong name — throws GostError
 * 'does not open'; the caller maps it to its own error type.
 */
export function unsealGost(env: GostSealedEnvelope, privateKeyB64: string, name: string): Record<string, string | null> {
  let pt: Uint8Array;
  try {
    const d = toBig(b64(privateKeyB64, 32));
    if (d < 1n || d >= Q) throw new GostError('private key out of range');
    const ourPk = encodePoint(publicFromPrivate(d));
    const epk = b64(env.epk, 64);
    const kek = vko(d, decodePoint(epk), b64(env.ukm, 8));
    const key = kdfTree256(kek, LABEL_GOST, concat(epk, ourPk), 1);
    pt = new MGM(new Kuznyechik(key)).open(b64(env.nonce, 16), b64(env.ct), Buffer.from(name, 'utf8'));
  } catch {
    throw new GostError('does not open');
  }
  return JSON.parse(Buffer.from(pt).toString('utf8'));
}

/** Seal like the server does (tests, tooling): fresh ephemeral key pair and UKM, random nonce. */
export function sealGost(payload: Record<string, unknown>, clientPublicKeyB64: string, name: string): GostSealedEnvelope {
  const clientPk = b64(clientPublicKeyB64, 64);
  const peer = decodePoint(clientPk);
  const d = generatePrivate();
  const epk = encodePoint(publicFromPrivate(d));
  const ukm = Uint8Array.from(randomBytes(8)); if (ukm.every(b => b === 0)) ukm[0] = 1;
  const kek = vko(d, peer, ukm);
  const key = kdfTree256(kek, LABEL_GOST, concat(epk, clientPk), 1);
  const nonce = mgmNonce();
  const ct = new MGM(new Kuznyechik(key)).seal(nonce, Buffer.from(JSON.stringify(payload), 'utf8'), Buffer.from(name, 'utf8'));
  const enc = (b: Uint8Array) => Buffer.from(b).toString('base64');
  return { alg: SEALED_ALG_GOST, v: 1, epk: enc(epk), ukm: enc(ukm), nonce: enc(nonce), ct: enc(ct) };
}

// ── The GOST post-quantum hybrid (0.32): VKO GOST R 34.10-2012 + ML-KEM-768 → KDF_TREE → Kuznyechik-MGM ─────
// Client key = GOST point X‖Y (64) ‖ ML-KEM-768 ek (1184) = 1248 bytes; private = GOST scalar big-endian (32) ‖
// ML-KEM seed d‖z (64) = 96 bytes. key = KDF_TREE_256(KEK ‖ ss_kem, label, epk ‖ kem): both agreements feed one key.
export const SEALED_ALG_GOST_PQC = 'VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM';
const LABEL_GOST_PQC = Buffer.from('aps-vault/sealed-gost-pqc/v1');
const GOST_PQC_SK_LEN = 96, GOST_PQC_PK_LEN = 64 + 1184, MLKEM_SEED_LEN = 64, MLKEM_CT_LEN = 1088;
const GOST_PQC_KEY_ERR = 'GOST hybrid private key must be 96 bytes — GOST R 34.10-2012 scalar (32) ‖ ML-KEM-768 seed (64), base64';
export interface GostPqcSealedEnvelope extends GostSealedEnvelope { kem: string; }

function gostPqcSplit(privateKeyB64: string): { d: bigint; seed: Uint8Array } {
  const raw = Uint8Array.from(Buffer.from(String(privateKeyB64 ?? ''), 'base64'));
  if (raw.length !== GOST_PQC_SK_LEN) throw new GostError(`${GOST_PQC_KEY_ERR}; got ${raw.length} bytes`);
  const d = toBig(raw.subarray(0, 32));
  if (d < 1n || d >= Q) throw new GostError('GOST hybrid private key: scalar out of range');
  return { d, seed: raw.subarray(32) };
}

/** A GOST hybrid pair: fresh GOST R 34.10-2012 scalar + fresh 64-byte ML-KEM seed (the ML-KEM pair is FIPS 203
 *  KeyGen from the seed, so every client re-derives the same public key — see gostPqcPublicFromPrivate). */
export function generateGostPqcKeyPair(): { privateKey: string; publicKey: string } {
  const d = generatePrivate();
  const seed = Uint8Array.from(randomBytes(MLKEM_SEED_LEN));
  const kem = ml_kem768.keygen(seed);
  return {
    privateKey: Buffer.concat([Buffer.from(fromBig(d, 32)), Buffer.from(seed)]).toString('base64'),
    publicKey: Buffer.concat([Buffer.from(encodePoint(publicFromPrivate(d))), Buffer.from(kem.publicKey)]).toString('base64'),
  };
}

/** The 1248-byte public key (base64) that belongs to a 96-byte GOST hybrid private key. */
export function gostPqcPublicFromPrivate(privateKeyB64: string): string {
  const { d, seed } = gostPqcSplit(privateKeyB64);
  return Buffer.concat([Buffer.from(encodePoint(publicFromPrivate(d))), Buffer.from(ml_kem768.keygen(seed).publicKey)]).toString('base64');
}

/** Open the GOST hybrid envelope: KEK = VKO(d, epk, ukm); ss = ML-KEM-768.Decaps(seed-derived dk, kem);
 *  key = KDF_TREE_256(KEK ‖ ss, label, epk ‖ kem); Kuznyechik-MGM with the name as AAD. A wrong key shape throws its
 *  own message; every cryptographic failure (wrong key, tampered field, wrong name) throws 'does not open'. */
export function unsealGostPqc(env: GostPqcSealedEnvelope, privateKeyB64: string, name: string): Record<string, string | null> {
  const { d, seed } = gostPqcSplit(privateKeyB64);
  let pt: Uint8Array;
  try {
    const epk = b64(env.epk, 64), kemCt = b64(env.kem, MLKEM_CT_LEN);
    const kek = vko(d, decodePoint(epk), b64(env.ukm, 8));
    const ss = ml_kem768.decapsulate(kemCt, ml_kem768.keygen(seed).secretKey);   // implicit rejection: garbage, not an error
    const key = kdfTree256(concat(kek, ss), LABEL_GOST_PQC, concat(epk, kemCt), 1);
    pt = new MGM(new Kuznyechik(key)).open(b64(env.nonce, 16), b64(env.ct), Buffer.from(name, 'utf8'));
  } catch {
    throw new GostError('does not open');
  }
  return JSON.parse(Buffer.from(pt).toString('utf8'));
}

/** Seal like the server does (tests, tooling): fresh ephemeral GOST pair, UKM, ML-KEM encapsulation, random nonce. */
export function sealGostPqc(payload: Record<string, unknown>, clientPublicKeyB64: string, name: string): GostPqcSealedEnvelope {
  const clientPk = b64(clientPublicKeyB64, GOST_PQC_PK_LEN);
  const peer = decodePoint(clientPk.subarray(0, 64));
  const d = generatePrivate();
  const epk = encodePoint(publicFromPrivate(d));
  const ukm = Uint8Array.from(randomBytes(8)); if (ukm.every(b => b === 0)) ukm[0] = 1;
  const kek = vko(d, peer, ukm);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(clientPk.subarray(64));
  const key = kdfTree256(concat(kek, sharedSecret), LABEL_GOST_PQC, concat(epk, cipherText), 1);
  const nonce = mgmNonce();
  const ct = new MGM(new Kuznyechik(key)).seal(nonce, Buffer.from(JSON.stringify(payload), 'utf8'), Buffer.from(name, 'utf8'));
  const enc = (b: Uint8Array) => Buffer.from(b).toString('base64');
  return { alg: SEALED_ALG_GOST_PQC, v: 1, epk: enc(epk), ukm: enc(ukm), kem: enc(cipherText), nonce: enc(nonce), ct: enc(ct) };
}
