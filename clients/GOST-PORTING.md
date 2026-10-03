# Porting the GOST sealed-delivery envelope to a client library

This is the specification the Node, Go and Java clients implement (0.19). The reference
implementation is Python: `backend/gost.py` (Kuznyechik, MGM, HMAC-Streebog, KDF_TREE),
`backend/gostec.py` (curve, VKO) and `backend/sealed.py` (`seal_gost` / `unseal_gost`). The
client copy is `clients/python/aps_vault/gost.py`. All numbers a port needs are in
`clients/fixtures/gost-sealed.json`; constant tables are generated into each language by
`ops/gen-gost-consts.py` (never typed by hand).

A port is done when its test suite reproduces **every** entry of the fixture file and, in
particular, decrypts `envelope.sealed` to `envelope.payload` with `keypair.private_b64`.
No external dependencies: `BigInt` (Node), `math/big` (Go), `BigInteger` (Java).

## 1. Streebog — GOST R 34.11-2012 (hash, 256 and 512 bit)

State: three 64-byte vectors `h`, `N`, `Σ`; all zero, except `h = 0x01 × 64` for the 256-bit
variant. Bytes are processed **as stored**; "little-endian" below means byte 0 is the least
significant.

- `LPS(x)` (64 bytes → 64 bytes): for output word `i` (0..7), bytes `[8i .. 8i+7]` =
  little-endian encoding of `T[0][x[i]] ^ T[1][x[i+8]] ^ T[2][x[i+16]] ^ … ^ T[7][x[i+56]]`,
  with `T` the generated 8 × 256 table of uint64.
- `E(K, m)`: `s = K ^ m`; for `i` in 0..11: `s = LPS(s)`; `K = LPS(K ^ C[i])`; `s = s ^ K`.
  Returns `s`. `C` is the generated 12 × 64-byte table.
- `g(h, N, m) = E(LPS(h ^ N), m) ^ h ^ m`.
- `add512(a, b)`: 512-bit little-endian addition (byte 0 least significant), carry dropped.
- Update: for every full 64-byte block `m` of the input, in order: `h = g(h, N, m)`;
  `N = add512(N, 512)` (512 = bytes `00 02 00 … 00`); `Σ = add512(Σ, m)`.
- Final: the remaining `r` bytes (0 ≤ r < 64) are padded to 64: `m = rest ‖ 0x01 ‖ 0x00…`.
  Then `h = g(h, N, m)`; `N = add512(N, r·8)` (as a little-endian 64-byte number);
  `Σ = add512(Σ, m)`; `h = g(h, 0, N)`; `h = g(h, 0, Σ)`.
- Digest: Streebog-512 = `h`; Streebog-256 = the **last** 32 bytes of `h` (`h[32:64]`).
- Vectors: `streebog.M1/M2` with both digests, `streebog.empty_256`.

**HMAC-Streebog-256** (R 50.1.113): RFC 2104 with block size 64 and Streebog-256; keys longer
than 64 bytes are hashed first. Vector `hmac_streebog256`.

**KDF_TREE_GOSTR3411_2012_256** (R 50.1.113 §4.5), one key: `HMAC256(key, 0x01 ‖ label ‖ 0x00 ‖
seed ‖ 0x01 0x00)` → 32 bytes. Vector `kdf_tree_256` (equals the HMAC vector by construction).

## 2. Kuznyechik — GOST R 34.12-2015 (128-bit block, 256-bit key)

Work on the block as a 128-bit big-endian integer (byte 0 is the most significant).

- `π` — generated 256-byte S-box (`KUZNYECHIK_PI`); `π⁻¹` is its inverse.
- GF(2⁸) multiplication with the polynomial `x⁸ + x⁷ + x⁶ + x + 1` (reduce with 0x1C3).
- `ℓ(a₀..a₁₅) = 148·a₀ ⊕ 32·a₁ ⊕ 133·a₂ ⊕ 16·a₃ ⊕ 194·a₄ ⊕ 192·a₅ ⊕ 1·a₆ ⊕ 251·a₇ ⊕ 1·a₈ ⊕
  192·a₉ ⊕ 194·a₁₀ ⊕ 16·a₁₁ ⊕ 133·a₁₂ ⊕ 32·a₁₃ ⊕ 148·a₁₄ ⊕ 1·a₁₅` (bytes indexed from the most
  significant). `R(a) = (ℓ(a), a₀, …, a₁₄)`; `L = R¹⁶`; `L⁻¹` the inverse (`R⁻¹` shifts left and
  recomputes the last byte: `a₁₅' = a₀ ⊕ ℓ(a₁..a₁₅, 0)`).
- Precompute `LS[i][x] = L(e_i · π[x])` (16 × 256 128-bit values): then `L(S(a)) = ⊕ᵢ LS[i][aᵢ]`.
  Likewise `LSI[i][x] = L⁻¹(e_i · x)`.
- Round constants `Cᵢ = L(Vec₁₂₈(i))`, i = 1..32 (i in the least significant byte).
- Key schedule: `K₁ = key[0:16]`, `K₂ = key[16:32]`; for i in 0..3, for j in 0..7:
  `(K₁, K₂) = (LS(K₁ ⊕ C[8i+j]) ⊕ K₂, K₁)`; after each group of 8 append `(K₁, K₂)` → 10 round keys.
- Encrypt: `x = block`; for i in 0..8: `x = LS(x ⊕ K[i])`; result `x ⊕ K[9]`.
- Decrypt: `x = block ⊕ K[9]`; for i in 8..0: `x = π⁻¹(L⁻¹(x)) ⊕ K[i]`.
- Vector `kuznyechik`.

## 3. MGM — R 1323565.1.026-2019 = RFC 9058 (AEAD over Kuznyechik)

Nonce 16 bytes with the top bit clear; tag 16 bytes appended to the ciphertext.

- `Y₁ = E_K(nonce)`; `Yᵢ₊₁ = incr_r(Yᵢ)` (increment the low 64-bit half, big-endian);
  `Cᵢ = Pᵢ ⊕ E_K(Yᵢ)` (last block truncated).
- `Z₁ = E_K(nonce with the top bit set)`; `Zᵢ₊₁ = incr_l(Zᵢ)` (increment the high half);
  `Hᵢ = E_K(Zᵢ)`.
- Tag: `acc = ⊕ Hᵢ ⊗ Aᵢ` over the AAD blocks (zero-padded), then `⊕ Hᵢ ⊗ Cᵢ` over the ciphertext
  blocks (zero-padded, continuing the `Z` counter), then `⊕ H_last ⊗ (len(A)·8 ‖ len(C)·8)` (two
  64-bit big-endian lengths in bits); `tag = E_K(acc)`.
- `⊗` is multiplication in GF(2¹²⁸) with `f(w) = w¹²⁸ + w⁷ + w² + w + 1`, integers big-endian,
  bit 0 = w⁰ (shift-left-and-reduce with 0x87 on overflow).
- Compare tags in constant time. Vector `mgm_rfc9058` (ciphertext and tag).

## 4. Curve and VKO — GOST R 34.10-2012, 256-bit, RFC 7836 §4.3

Curve `id-tc26-gost-3410-2012-256-paramSetB` (short Weierstrass `y² = x³ + ax + b` over GF(p),
prime order `q`, cofactor 1); parameters in `fixture.curve` and the generated constants.
Jacobian coordinates recommended (one inversion per scalar multiplication).

- **Private key**: 32-byte **big-endian** integer `d`, 1 ≤ d < q. **Public key**: `X ‖ Y`, each
  32 bytes **little-endian** (64 bytes) — the GOST encoding. Base64 (standard, padded) in the
  API. Validate a received point: on the curve (cofactor 1 ⇒ in the group).
- `public = d · G`. Vector `keypair` (private → public, also the coordinates in hex).
- `VKO(d, Q, UKM) = Streebog256( encode(UKM · d · Q) )` with `UKM` an 8-byte little-endian
  integer ≥ 1 and `encode` the X‖Y little-endian form. Vector `vko`.

## 5. The envelope

```
{"alg": "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM", "v": 1,
 "epk": b64(64 bytes X‖Y LE), "ukm": b64(8 bytes), "nonce": b64(16 bytes), "ct": b64(ciphertext ‖ tag)}
```

Open it with private key `d` for secret `name`:

1. `our_pk = encode(d · G)`; `epk = decode(envelope.epk)` (validate on curve).
2. `kek = VKO(d, epk_point, ukm)`.
3. `key = KDF_TREE_256(kek, label = "aps-vault/sealed-gost/v1", seed = epk_bytes ‖ our_pk)`.
4. `plaintext = MGM_open(Kuznyechik(key), nonce, ct, aad = name as UTF-8)` → JSON
   `{value, login?, notes?, totp?}`.

Any failure (point off curve, tag mismatch) → the same "does not open" error the X25519 path
raises. The X25519 envelope (`alg = X25519-HKDF-SHA256-AES256GCM`) stays as it is; dispatch on
`alg`. A key pair generator for GOST keys sits next to the X25519 one (`generateKeyPair({gost})`,
`GenerateGostKeyPair()`, `generateGostKeyPair()`), producing the base64 forms above.

## 6. Tests a port must have

- Streebog: M1/M2 both lengths, empty string; HMAC and KDF_TREE vectors.
- Kuznyechik vector; MGM RFC 9058 vector (encrypt and decrypt), tag tampering refused.
- Curve: `keypair` vector, point validation refuses an off-curve point; `vko` vector.
- Envelope: the fixture decrypts to `payload`; wrong key refused; wrong name (AAD) refused;
  through the client's `get()` from a fake server returning the fixture.
