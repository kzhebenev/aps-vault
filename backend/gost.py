"""GOST cryptography for the `gost` cipher suite (0.18) — algorithm-level conformance.

* **Kuznyechik** — GOST R 34.12-2015, 128-bit block, 256-bit key. Own implementation with
  precomputed LS tables (16 × 256 × 128-bit) so a block costs ~150 Python operations; the
  pure-Python libraries on PyPI do ~25 KB/s, which is too slow for a server that decrypts on
  every read. Checked against the standard's test vector.
* **MGM** — Multilinear Galois Mode, R 1323565.1.026-2019 / RFC 9058: the AEAD mode for GOST
  block ciphers (the analogue of GCM). Nonce 16 bytes with the top bit clear, 16-byte tag.
  Checked against RFC 9058 Appendix A (Kuznyechik example).
* **Streebog** — GOST R 34.11-2012 (256/512), **HMAC-Streebog** (R 50.1.113-2016),
  **KDF_TREE_GOSTR3411_2012_256** (R 50.1.113, the key-derivation function) and
  **PBKDF2-HMAC-Streebog-512** (R 50.1.111-2016) come from the MIT-licensed `gostcrypto`
  package; the HMAC test vector of R 50.1.113 is in the tests.

Side channels — read this before using the suite in production. The LS tables are indexed by
bytes of the round state, which depend on the key and the plaintext; on a shared CPU, cache
timing of those look-ups is a known way to recover a table-based block cipher's key (the same
class of attack as on table-based AES without AES-NI). Python adds its own data-dependent timing.
The AES suite does not have this problem: `cryptography` uses AES-NI / constant-time code. So
the gost suite is **experimental**: correct by the test vectors, not hardened against an
attacker who shares the host. The server says so in its startup log and in Settings.

What this is and is not: the algorithms match the standards and are verified against the
published test vectors — "соответствие по алгоритму". It is **not** a certified СКЗИ: no
FSB licence, no evaluation of the execution environment, no certificate. Deployments that
need the certified kind take the code and go through that process themselves, or keep the
master key in a certified HSM (docs/HSM.md) — the licence (MIT) allows both.
"""
from __future__ import annotations

import os
import struct

# ── Kuznyechik (GOST R 34.12-2015) ───────────────────────────────────────────
_PI = bytes([
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
])
_PI_INV = bytes(256)
_PI_INV = bytearray(256)
for _i, _v in enumerate(_PI):
    _PI_INV[_v] = _i
_PI_INV = bytes(_PI_INV)
_LVEC = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)


def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) with the polynomial x^8 + x^7 + x^6 + x + 1 (0x1C3)."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1C3
        b >>= 1
    return p


_MUL = [[_gf_mul(a, b) for b in range(256)] for a in range(256)]


def _l_step(state: list[int]) -> list[int]:
    """One R step of the linear transform: shift right, new byte 0 = l(state)."""
    acc = 0
    for i in range(16):
        acc ^= _MUL[state[i]][_LVEC[i]]
    return [acc] + state[:15]


def _l(state: list[int]) -> list[int]:
    for _ in range(16):
        state = _l_step(state)
    return state


def _l_inv_step(state: list[int]) -> list[int]:
    a = state[0]
    state = state[1:] + [0]
    acc = 0
    for i in range(16):
        acc ^= _MUL[state[i]][_LVEC[i]]
    state[15] = a ^ acc
    return state


def _l_inv(state: list[int]) -> list[int]:
    for _ in range(16):
        state = _l_inv_step(state)
    return state


def _vec(b: bytes) -> list[int]:
    return list(b)


def _to_int(v: list[int]) -> int:
    return int.from_bytes(bytes(v), "big")


# LS tables: LS[i][x] = L(e_i * pi(x)) as a 128-bit int — the linear map is linear, so
# L(S(block)) = XOR_i LS[i][block[i]]. Inverse tables for decryption: LS_INV[i][x] = L^-1(e_i * x).
_LS = []
_LSI = []
for _pos in range(16):
    _t = []
    _ti = []
    for _x in range(256):
        _blk = [0] * 16
        _blk[_pos] = _PI[_x]
        _t.append(_to_int(_l(_blk)))
        _blk2 = [0] * 16
        _blk2[_pos] = _x
        _ti.append(_to_int(_l_inv(_blk2)))
    _LS.append(_t)
    _LSI.append(_ti)

_MASK128 = (1 << 128) - 1
_SHIFTS = [8 * (15 - i) for i in range(16)]       # byte i of a big-endian 128-bit int


def _ls_int(x: int) -> int:
    acc = 0
    for i in range(16):
        acc ^= _LS[i][(x >> _SHIFTS[i]) & 0xFF]
    return acc


def _l_inv_int(x: int) -> int:
    acc = 0
    for i in range(16):
        acc ^= _LSI[i][(x >> _SHIFTS[i]) & 0xFF]
    return acc


def _s_inv_int(x: int) -> int:
    out = 0
    for i in range(16):
        out |= _PI_INV[(x >> _SHIFTS[i]) & 0xFF] << _SHIFTS[i]
    return out


# round constants C_i = L(Vec(i)), i = 1..32
_C = []
for _i in range(1, 33):
    _blk = [0] * 15 + [_i]
    _C.append(_to_int(_l(_blk)))


class Kuznyechik:
    """GOST R 34.12-2015 block cipher; `key` is 32 bytes."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Kuznyechik key must be 32 bytes")
        k1 = int.from_bytes(key[:16], "big")
        k2 = int.from_bytes(key[16:], "big")
        keys = [k1, k2]
        for i in range(4):
            for j in range(8):
                c = _C[8 * i + j]
                k1, k2 = _ls_int(k1 ^ c) ^ k2, k1
            keys += [k1, k2]
        self._k = keys                       # 10 round keys
        self._kd = keys[::-1]

    def encrypt_block(self, block: bytes) -> bytes:
        x = int.from_bytes(block, "big")
        k = self._k
        for i in range(9):
            x = _ls_int(x ^ k[i])
        return (x ^ k[9]).to_bytes(16, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        x = int.from_bytes(block, "big")
        k = self._kd
        x ^= k[0]
        for i in range(1, 10):
            x = _s_inv_int(_l_inv_int(x)) ^ k[i]
        return x.to_bytes(16, "big")


# ── MGM (RFC 9058 / R 1323565.1.026-2019) ─────────────────────────────────────
_R = 0x87          # reduction for the GF(2^128) polynomial w^128 + w^7 + w^2 + w + 1


def _gf128_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^128) with f(w) = w^128 + w^7 + w^2 + w + 1 (RFC 9058 §4.1), MSB-first."""
    p = 0
    for _ in range(128):
        if b & 1:
            p ^= a
        carry = a >> 127
        a = (a << 1) & _MASK128
        if carry:
            a ^= _R
        b >>= 1
    return p


def _incr_r(x: int) -> int:
    hi, lo = x >> 64, x & ((1 << 64) - 1)
    return (hi << 64) | ((lo + 1) & ((1 << 64) - 1))


def _incr_l(x: int) -> int:
    hi, lo = x >> 64, x & ((1 << 64) - 1)
    return (((hi + 1) & ((1 << 64) - 1)) << 64) | lo


def _blocks(data: bytes):
    for i in range(0, len(data), 16):
        yield data[i:i + 16]


class MGM:
    """AEAD over a 128-bit block cipher: nonce 16 bytes (top bit must be 0), tag 16 bytes."""

    TAG = 16
    NONCE = 16

    def __init__(self, cipher: Kuznyechik) -> None:
        self._c = cipher

    def _check_nonce(self, nonce: bytes) -> int:
        if len(nonce) != 16 or nonce[0] & 0x80:
            raise ValueError("MGM nonce must be 16 bytes with the top bit clear")
        return int.from_bytes(nonce, "big")

    def _tag(self, nonce_int: int, aad: bytes, ct: bytes) -> bytes:
        enc = self._c.encrypt_block
        z = int.from_bytes(enc(((1 << 127) | nonce_int).to_bytes(16, "big")), "big")
        acc = 0
        for part in (aad, ct):
            for blk in _blocks(part):
                if len(blk) < 16:
                    blk = blk + b"\x00" * (16 - len(blk))
                h = int.from_bytes(enc(z.to_bytes(16, "big")), "big")
                acc ^= _gf128_mul(h, int.from_bytes(blk, "big"))
                z = _incr_l(z)
        h = int.from_bytes(enc(z.to_bytes(16, "big")), "big")
        length_block = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
        acc ^= _gf128_mul(h, int.from_bytes(length_block, "big"))
        return enc(acc.to_bytes(16, "big"))[: self.TAG]

    def _keystream_xor(self, nonce_int: int, data: bytes) -> bytes:
        enc = self._c.encrypt_block
        y = int.from_bytes(enc(nonce_int.to_bytes(16, "big")), "big")   # top bit of the nonce is 0
        out = bytearray()
        for blk in _blocks(data):
            ks = enc(y.to_bytes(16, "big"))
            out += bytes(a ^ b for a, b in zip(blk, ks))
            y = _incr_r(y)
        return bytes(out)

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        n = self._check_nonce(nonce)
        ct = self._keystream_xor(n, plaintext)
        return ct + self._tag(n, aad, ct)

    def open(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        n = self._check_nonce(nonce)
        if len(ciphertext) < self.TAG:
            raise ValueError("ciphertext too short")
        ct, tag = ciphertext[: -self.TAG], ciphertext[-self.TAG:]
        expected = self._tag(n, aad, ct)
        # constant-time compare
        diff = 0
        for a, b in zip(expected, tag):
            diff |= a ^ b
        if diff:
            raise ValueError("MGM tag mismatch")
        return self._keystream_xor(n, ct)


def mgm_nonce() -> bytes:
    n = bytearray(os.urandom(16))
    n[0] &= 0x7F
    return bytes(n)


# ── Streebog family via gostcrypto (MIT) ─────────────────────────────────────
def streebog256(data: bytes) -> bytes:
    from gostcrypto import gosthash
    return gosthash.new("streebog256", data=data).digest()


def streebog512(data: bytes) -> bytes:
    from gostcrypto import gosthash
    return gosthash.new("streebog512", data=data).digest()


_HMAC_BLOCK = 64     # Streebog block size (R 50.1.113-2016 §4.1: B = 64 bytes for both lengths)


def _hmac(hash_fn, key: bytes, data: bytes) -> bytes:
    """RFC 2104 HMAC over Streebog. gostcrypto's HMAC refuses keys longer than 64 bytes, whereas
    the standard hashes them first — and our tokens (vlt_…, 83 characters) are longer."""
    if len(key) > _HMAC_BLOCK:
        key = hash_fn(key)
    key = key + b"\x00" * (_HMAC_BLOCK - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return hash_fn(opad + hash_fn(ipad + data))


def hmac_streebog256(key: bytes, data: bytes) -> bytes:
    return _hmac(streebog256, key, data)


def hmac_streebog512(key: bytes, data: bytes) -> bytes:
    return _hmac(streebog512, key, data)


def kdf_tree_256(key: bytes, label: bytes, seed: bytes, keys: int = 1) -> bytes:
    """KDF_TREE_GOSTR3411_2012_256 (R 50.1.113-2016 §4.5): K(i) = HMAC256(key, i‖label‖0x00‖seed‖L),
    i one byte (R = 1), L = 256·keys bits as two bytes big-endian. Returns `keys` × 32 bytes."""
    if not 1 <= keys <= 255:
        raise ValueError("keys out of range")
    L = (256 * keys).to_bytes(2, "big")
    out = b""
    for i in range(1, keys + 1):
        out += hmac_streebog256(key, bytes([i]) + label + b"\x00" + seed + L)
    return out


def pbkdf2_streebog512(password: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    """PBKDF2 with HMAC_GOSTR3411_2012_512 (R 50.1.111-2016)."""
    from gostcrypto import gostpbkdf
    return gostpbkdf.new(password, salt=salt, counter=iterations).derive(length)
