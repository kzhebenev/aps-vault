"""KDBX reader (0.35): KeePass 2.x database files, versions 3.1 and 4.x, opened in memory for the import.

Only what the import needs — read the database, hand the decrypted XML (the same document the KeePass XML
export produces) to the KeePass XML parser. Written from the format description (KeePass source, KeePassXC
`KdbxReader`); verified against KeePassXC's published test databases and files written by pykeepass.

    composite key  = SHA256( SHA256(password) ‖ keyfile_key )          (either part may be absent)
    KDBX 3.1       : transformed = SHA256(AES-ECB^rounds(seed, composite)); master = SHA256(master_seed ‖ transformed)
                     payload = cipher⁻¹(master, iv); first 32 bytes must equal StreamStartBytes (else wrong key);
                     hashed block stream (index, SHA256, length, data); optional gzip; inner stream Salsa20 / ChaCha20
    KDBX 4.x       : transformed = AES-KDF | Argon2d | Argon2id (VariantDictionary); master as above;
                     SHA256(header) and HMAC-SHA256(header) checked before anything is decrypted;
                     HMAC block stream (per-block key SHA512(index ‖ SHA512(master_seed ‖ transformed ‖ 0x01)));
                     cipher⁻¹; optional gzip; inner header (stream id, stream key, binaries); XML
    ciphers        : AES-256-CBC (PKCS#7), ChaCha20 (12-byte nonce). Twofish is refused with a clear message.
    inner stream   : protected values (<Value Protected="True">) are XOR-ed with Salsa20 (key SHA256(k), fixed nonce)
                     or ChaCha20 (SHA512(k) → key ‖ nonce) in document order — history entries included.
    key file       : 32 raw bytes, 64 hex characters, KeePass XML key file v1 (base64) / v2 (hex + SHA256 check),
                     anything else → SHA256 of the file.
Algorithm conformance only (this is not a certified module); Argon2 comes from argon2-cffi, AES / ChaCha20 from
`cryptography`, Salsa20 is the 40-line reference implementation below.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import re
import struct
import xml.etree.ElementTree as ET

SIG1, SIG2 = 0x9AA2D903, 0xB54BFB67
CIPHER_AES = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
CIPHER_CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
CIPHER_TWOFISH = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")
KDF_AES = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
KDF_ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
KDF_ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
MAX_ARGON2_MEMORY = 1024 * 1024 * 1024    # 1 GiB: refuse absurd parameters before allocating


class KdbxError(ValueError):
    """Anything that stops the import — malformed file, unsupported cipher, wrong key — with a message for the UI."""


# ─── Salsa20 (reference, for the KDBX 3 inner stream) ─────────────────────────
def _rotl(v: int, c: int) -> int:
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    k = struct.unpack("<8I", key)
    n = struct.unpack("<2I", nonce)
    c = (counter & 0xFFFFFFFF, counter >> 32)
    s = [0x61707865, k[0], k[1], k[2], k[3], 0x3320646E, n[0], n[1], c[0], c[1], 0x79622D32, k[4], k[5], k[6], k[7], 0x6B206574]
    x = list(s)

    def qr(a, b, c_, d):
        x[b] ^= _rotl((x[a] + x[d]) & 0xFFFFFFFF, 7)
        x[c_] ^= _rotl((x[b] + x[a]) & 0xFFFFFFFF, 9)
        x[d] ^= _rotl((x[c_] + x[b]) & 0xFFFFFFFF, 13)
        x[a] ^= _rotl((x[d] + x[c_]) & 0xFFFFFFFF, 18)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
        qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
    return struct.pack("<16I", *[(x[i] + s[i]) & 0xFFFFFFFF for i in range(16)])


class _Keystream:
    """XOR-keystream for protected values: Salsa20 (KDBX 3) or ChaCha20 (KDBX 4), consumed in document order."""

    def __init__(self, stream_id: int, key: bytes):
        self.buf = b""
        if stream_id == 2:                                      # Salsa20
            self.kind, self.key, self.nonce, self.counter = "salsa", hashlib.sha256(key).digest(), bytes.fromhex("e830094b97205d2a"), 0
        elif stream_id == 3:                                    # ChaCha20
            h = hashlib.sha512(key).digest()
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            self.kind = "chacha"
            self.enc = Cipher(algorithms.ChaCha20(h[:32], b"\x00" * 4 + h[32:44]), mode=None).encryptor()
        elif stream_id == 0:
            self.kind = "none"
        else:
            raise KdbxError("this database protects fields with ArcFour (KeePass 1.x era) — save it with a current KeePass first")

    def xor(self, data: bytes) -> bytes:
        if self.kind == "none":
            return data
        while len(self.buf) < len(data):
            if self.kind == "salsa":
                self.buf += _salsa20_block(self.key, self.nonce, self.counter); self.counter += 1
            else:
                self.buf += self.enc.update(b"\x00" * 64)
        ks, self.buf = self.buf[:len(data)], self.buf[len(data):]
        return bytes(a ^ b for a, b in zip(data, ks))


# ─── keys ────────────────────────────────────────────────────────────────────
def keyfile_key(data: bytes) -> bytes:
    """The 32 bytes a key file contributes to the composite key (KeePass rules)."""
    if len(data) == 32:
        return data
    text = data.strip()
    if len(text) == 64 and re.fullmatch(rb"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text.decode())
    if text.startswith(b"<"):
        try:
            root = ET.fromstring(data)
            if root.tag == "KeyFile":
                version = (root.findtext("Meta/Version") or "1.0").strip()
                node = root.find("Key/Data")
                raw = (node.text or "").strip() if node is not None else ""
                if version.startswith("2"):
                    key = bytes.fromhex(re.sub(r"\s+", "", raw))
                    want = (node.get("Hash") or "").strip().lower()
                    if len(key) != 32:
                        raise KdbxError("key file v2: the key is not 32 bytes")
                    if want and hashlib.sha256(key).hexdigest()[:len(want)] != want:
                        raise KdbxError("key file v2: the hash does not match the key — the file is damaged")
                    return key
                key = base64.b64decode(raw, validate=True)
                if len(key) == 32:
                    return key
                raise KdbxError("key file v1: the key is not 32 bytes of base64")
        except KdbxError:
            raise
        except Exception:
            pass                                                # not a KeePass XML key file: hashed like any other file
    return hashlib.sha256(data).digest()


def composite_key(password: str | None, keyfile: bytes | None) -> bytes:
    parts = b""
    if password is not None and password != "":
        parts += hashlib.sha256(password.encode("utf-8")).digest()
    if keyfile:
        parts += keyfile_key(keyfile)
    if not parts:
        raise KdbxError("a password or a key file is required")
    return hashlib.sha256(parts).digest()


def _aes_kdf(composite: bytes, seed: bytes, rounds: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if rounds > 100_000_000:
        raise KdbxError("AES-KDF rounds beyond any sane setting — refusing")
    enc = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    data = composite
    # ECB has no chaining: r rounds over the 32 bytes = the two halves encrypted r times each
    for _ in range(rounds):
        data = enc.update(data)
    enc.finalize()
    return hashlib.sha256(data).digest()


def _argon2(composite: bytes, params: dict, kind: str) -> bytes:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:                                           # pragma: no cover — argon2-cffi is a runtime dependency
        raise KdbxError("argon2-cffi is not installed")
    salt, mem, it, par = params.get("S"), params.get("M"), params.get("I"), params.get("P")
    ver = params.get("V", 0x13)
    if not isinstance(salt, bytes) or not all(isinstance(x, int) for x in (mem, it, par)):
        raise KdbxError("Argon2 parameters are incomplete")
    if mem > MAX_ARGON2_MEMORY or it > 1000 or par > 64:
        raise KdbxError("Argon2 parameters beyond what this importer allows (memory ≤ 1 GiB, ≤ 1000 iterations, ≤ 64 lanes)")
    return hash_secret_raw(composite, salt, time_cost=int(it), memory_cost=int(mem) // 1024, parallelism=int(par), hash_len=32,
                           type=Type.ID if kind == "id" else Type.D, version=int(ver))


def _variant_dict(data: bytes) -> dict:
    (ver,) = struct.unpack_from("<H", data, 0)
    if ver >> 8 != 1:
        raise KdbxError(f"unsupported KDF parameter dictionary version {ver >> 8}")
    out, pos = {}, 2
    while True:
        t = data[pos]; pos += 1
        if t == 0:
            break
        (nlen,) = struct.unpack_from("<I", data, pos); pos += 4
        name = data[pos:pos + nlen].decode("utf-8"); pos += nlen
        (vlen,) = struct.unpack_from("<I", data, pos); pos += 4
        raw = data[pos:pos + vlen]; pos += vlen
        if t == 0x04: out[name] = struct.unpack("<I", raw)[0]
        elif t == 0x05: out[name] = struct.unpack("<Q", raw)[0]
        elif t == 0x08: out[name] = raw != b"\x00"
        elif t == 0x0C: out[name] = struct.unpack("<i", raw)[0]
        elif t == 0x0D: out[name] = struct.unpack("<q", raw)[0]
        elif t == 0x18: out[name] = raw.decode("utf-8")
        elif t == 0x42: out[name] = raw
        else:
            raise KdbxError(f"unknown KDF parameter type 0x{t:02x}")
    return out


# ─── ciphers and block streams ───────────────────────────────────────────────
def _decrypt(cipher_id: bytes, key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if cipher_id == CIPHER_AES:
        if len(iv) != 16:
            raise KdbxError("AES needs a 16-byte IV")
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(data) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        try:
            return unpad.update(padded) + unpad.finalize()
        except ValueError:
            raise KdbxError("wrong password or key file (padding check failed)")
    if cipher_id == CIPHER_CHACHA20:
        if len(iv) != 12:
            raise KdbxError("ChaCha20 needs a 12-byte nonce")
        dec = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + iv), mode=None).decryptor()
        return dec.update(data) + dec.finalize()
    if cipher_id == CIPHER_TWOFISH:
        raise KdbxError("this database is encrypted with Twofish, which this importer does not implement — in KeePass choose Database settings → Security → AES or ChaCha20, save, and import again")
    raise KdbxError(f"unknown cipher {cipher_id.hex()}")


def _hashed_blocks(data: bytes) -> bytes:
    """KDBX 3 payload: index(4) hash(32) length(4) data …; the end block has length 0 and a zero hash."""
    out, pos, expect = [], 0, 0
    while True:
        if pos + 40 > len(data):
            raise KdbxError("truncated database (hashed block stream)")
        idx, h, ln = struct.unpack_from("<I32sI", data, pos); pos += 40
        if idx != expect:
            raise KdbxError("block stream out of order")
        if ln == 0:
            if h != b"\x00" * 32:
                raise KdbxError("block stream end marker is damaged")
            break
        chunk = data[pos:pos + ln]; pos += ln
        if hashlib.sha256(chunk).digest() != h:
            raise KdbxError("block hash mismatch — damaged file or wrong key")
        out.append(chunk); expect += 1
    return b"".join(out)


def _hmac_blocks(data: bytes, hmac_base: bytes) -> bytes:
    """KDBX 4 payload: hmac(32) length(4) data …; each block's key is SHA512(index ‖ base); the end block has length 0."""
    out, pos, idx = [], 0, 0
    while True:
        if pos + 36 > len(data):
            raise KdbxError("truncated database (HMAC block stream)")
        mac, ln = struct.unpack_from("<32sI", data, pos); pos += 36
        chunk = data[pos:pos + ln]; pos += ln
        if len(chunk) != ln:
            raise KdbxError("truncated database (block shorter than announced)")
        key = hashlib.sha512(struct.pack("<Q", idx) + hmac_base).digest()
        if not hmac.compare_digest(hmac.new(key, struct.pack("<Q", idx) + struct.pack("<I", ln) + chunk, hashlib.sha256).digest(), mac):
            raise KdbxError("wrong password or key file (block HMAC mismatch)" if idx == 0 else "damaged database (block HMAC mismatch)")
        if ln == 0:
            break
        out.append(chunk); idx += 1
    return b"".join(out)


# ─── the reader ──────────────────────────────────────────────────────────────
def read_xml(data: bytes, password: str | None = None, keyfile: bytes | None = None) -> bytes:
    """Open a .kdbx and return the plaintext XML with every protected value decrypted in place
    (Protected="True" attributes removed) — the input the KeePass XML import expects."""
    if len(data) < 12 or struct.unpack_from("<II", data, 0) != (SIG1, SIG2):
        raise KdbxError("not a KeePass 2.x database (.kdbx signature missing)")
    minor, major = struct.unpack_from("<HH", data, 8)
    if major not in (3, 4):
        raise KdbxError(f"KDBX version {major}.{minor} is not supported (3.x and 4.x are)")
    pos, fields = 12, {}
    while True:
        fid = data[pos]; pos += 1
        if major >= 4:
            (ln,) = struct.unpack_from("<I", data, pos); pos += 4
        else:
            (ln,) = struct.unpack_from("<H", data, pos); pos += 2
        val = data[pos:pos + ln]; pos += ln
        if fid == 0:
            break
        fields[fid] = val
    header = data[:pos]
    cipher_id = fields.get(2, b"")
    compression = struct.unpack("<I", fields.get(3, b"\x00\x00\x00\x00"))[0]
    master_seed, iv = fields.get(4, b""), fields.get(7, b"")
    if len(master_seed) != 32:
        raise KdbxError("master seed missing")
    composite = composite_key(password, keyfile)
    if major == 3:
        if 5 not in fields or 6 not in fields:
            raise KdbxError("KDBX 3 header without transform seed / rounds")
        transformed = _aes_kdf(composite, fields[5], struct.unpack("<Q", fields[6])[0])
    else:
        params = _variant_dict(fields.get(11, b""))
        uuid = params.get("$UUID")
        if uuid == KDF_AES:
            transformed = _aes_kdf(composite, params["S"], int(params["R"]))
        elif uuid == KDF_ARGON2D:
            transformed = _argon2(composite, params, "d")
        elif uuid == KDF_ARGON2ID:
            transformed = _argon2(composite, params, "id")
        else:
            raise KdbxError("unknown key derivation function in the header")
    master = hashlib.sha256(master_seed + transformed).digest()
    body = data[pos:]
    if major >= 4:
        if hashlib.sha256(header).digest() != body[:32]:
            raise KdbxError("header hash mismatch — the file is damaged")
        hmac_base = hashlib.sha512(master_seed + transformed + b"\x01").digest()
        hkey = hashlib.sha512(b"\xff" * 8 + hmac_base).digest()
        if not hmac.compare_digest(hmac.new(hkey, header, hashlib.sha256).digest(), body[32:64]):
            raise KdbxError("wrong password or key file (header HMAC mismatch)")
        payload = _decrypt(cipher_id, master, iv, _hmac_blocks(body[64:], hmac_base))
        if compression == 1:
            payload = gzip.decompress(payload)
        # inner header
        ipos, stream_id, stream_key = 0, 0, b""
        while True:
            t = payload[ipos]; (ln,) = struct.unpack_from("<I", payload, ipos + 1); ipos += 5
            v = payload[ipos:ipos + ln]; ipos += ln
            if t == 0:
                break
            if t == 1:
                stream_id = struct.unpack("<I", v)[0]
            elif t == 2:
                stream_key = v
        xml_bytes = payload[ipos:]
    else:
        plain = _decrypt(cipher_id, master, iv, body)
        start = fields.get(9, b"")
        if not hmac.compare_digest(plain[:32], start):
            raise KdbxError("wrong password or key file (stream start bytes do not match)")
        payload = _hashed_blocks(plain[32:])
        if compression == 1:
            payload = gzip.decompress(payload)
        stream_id = struct.unpack("<I", fields.get(10, b"\x02\x00\x00\x00"))[0]
        stream_key = fields.get(8, b"")
        xml_bytes = payload
    return _unprotect(xml_bytes, stream_id, stream_key)


def _unprotect(xml_bytes: bytes, stream_id: int, stream_key: bytes) -> bytes:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise KdbxError(f"the decrypted content is not KeePass XML: {e}")
    ks = _Keystream(stream_id, stream_key)
    for node in root.iter("Value"):                             # document order — the stream position depends on it
        if (node.get("Protected") or "").lower() == "true":
            raw = base64.b64decode(node.text or "")
            node.text = ks.xor(raw).decode("utf-8", "replace")
            del node.attrib["Protected"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
