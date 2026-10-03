"""Sealed delivery (0.17): a secret leaves the vault encrypted to the *client's* public key.

A service token may carry an X25519 public key (`client_public_key`). For such a token the
machine API never returns plaintext: the value (with login / notes / TOTP as granted) is
encrypted to that key and only the holder of the matching private key — the application
itself, in its own process — can open it. Along the way nothing can read it: not the reverse
proxy, not a TLS-terminating load balancer, not a captured response, not a log, and not
someone who copied the token without the private key (the token alone yields ciphertext).

What it does *not* do: once the application has decrypted the value it is in that process's
memory like any other secret; this protects the path, and binds the token to a key the
application holds, not the application's host.

Envelope (one per response, fresh ephemeral key every time):

    shared = X25519(ephemeral_sk, client_pk)
    key    = HKDF-SHA256(ikm=shared, salt="", info="aps-vault/sealed/v1" || ephemeral_pk || client_pk, L=32)
    ct     = AES-256-GCM(key, nonce=random 12 bytes, plaintext=JSON payload, aad=secret name)
    → {"alg": "X25519-HKDF-SHA256-AES256GCM", "v": 1, "epk": b64, "nonce": b64, "ct": b64}

The AAD is the secret name, so a sealed blob for one secret cannot be presented as another.
Keys are raw 32-byte X25519 keys in standard base64 — the same bytes every client library
(Python, Node, Go, Java) produces with its `generate_keypair` helper.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ALG = "X25519-HKDF-SHA256-AES256GCM"
_INFO = b"aps-vault/sealed/v1"
# GOST envelope (0.19): VKO GOST R 34.10-2012 (256-bit, paramSetB) → KDF_TREE_GOSTR3411_2012_256 → Kuznyechik-MGM.
# Selected by the client's key: a 64-byte X‖Y point means GOST, a 32-byte key means X25519.
ALG_GOST = "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM"
_LABEL_GOST = b"aps-vault/sealed-gost/v1"
# P-256 envelope (0.22): for keys that live in hardware — TPM 2.0, HSMs and smart cards speak ECDH on
# NIST P-256 through PKCS#11, almost never X25519. Client key = uncompressed point 0x04‖X‖Y (65 bytes).
ALG_P256 = "P256-HKDF-SHA256-AES256GCM"
_INFO_P256 = b"aps-vault/sealed-p256/v1"


def parse_public_key(b64: str) -> bytes:
    """Validate a client public key: standard base64 of a raw 32-byte X25519 key, or of a 64-byte
    GOST R 34.10-2012 point (X‖Y little-endian, curve paramSetB) for the GOST envelope."""
    s = (b64 or "").strip()
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raise ValueError("client_public_key must be standard base64 of a raw 32-byte X25519 key or a 64-byte GOST R 34.10 point")
    if len(raw) == 64:
        import gostec
        gostec.decode_point(raw)                      # raises ValueError when off the curve
        return raw
    if len(raw) == 65:
        if raw[0] != 0x04:
            raise ValueError("P-256 public key must be an uncompressed point (0x04 ‖ X ‖ Y)")
        from cryptography.hazmat.primitives.asymmetric import ec
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except Exception:
            raise ValueError("point is not on the P-256 curve")
        return raw
    if len(raw) != 32:
        raise ValueError(f"client_public_key must decode to 32 bytes (X25519), 64 bytes (GOST) or 65 bytes (P-256), got {len(raw)}")
    try:
        X25519PublicKey.from_public_bytes(raw)
    except Exception:
        raise ValueError("client_public_key is not a valid X25519 public key")
    if raw == b"\x00" * 32:
        raise ValueError("client_public_key is the all-zero point")
    return raw


def key_kind(b64: str) -> str:
    n = len(base64.b64decode(b64))
    return "gost" if n == 64 else "p256" if n == 65 else "x25519"


def normalize_public_key(b64: str) -> str:
    """Canonical storage form (re-encoded standard base64 with padding)."""
    return base64.b64encode(parse_public_key(b64)).decode()


def seal(payload: dict, client_pk_b64: str, aad: str) -> dict:
    client_pk = parse_public_key(client_pk_b64)
    if len(client_pk) == 64:
        return seal_gost(payload, client_pk, aad)
    if len(client_pk) == 65:
        return seal_p256(payload, client_pk, aad)
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = esk.exchange(X25519PublicKey.from_public_bytes(client_pk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + epk + client_pk).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), aad.encode("utf-8"))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"alg": ALG, "v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(ct)}


def seal_gost(payload: dict, client_pk: bytes, aad: str) -> dict:
    """GOST envelope: ephemeral 34.10 key pair, UKM, VKO → KEK; KDF_TREE(KEK, label, seed = epk‖client_pk) → key;
    Kuznyechik-MGM(key, nonce, payload, aad = secret name). Independent of the vault's cipher suite."""
    import gost
    import gostec
    peer = gostec.decode_point(client_pk)
    d = gostec.generate_private()
    epk = gostec.encode_point(gostec.public_from_private(d))
    ukm = os.urandom(8)
    if ukm == b"\x00" * 8:
        ukm = b"\x01" + ukm[1:]
    kek = gostec.vko(d, peer, ukm)
    key = gost.kdf_tree_256(kek, _LABEL_GOST, epk + client_pk, 1)
    nonce = gost.mgm_nonce()
    ct = gost.MGM(gost.Kuznyechik(key)).seal(nonce, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), aad.encode("utf-8"))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"alg": ALG_GOST, "v": 1, "epk": b64(epk), "ukm": b64(ukm), "nonce": b64(nonce), "ct": b64(ct)}


def unseal_gost(envelope: dict, client_sk_raw: bytes, aad: str) -> dict:
    import gost
    import gostec
    d = int.from_bytes(client_sk_raw, "big")
    client_pk = gostec.encode_point(gostec.public_from_private(d))
    epk = base64.b64decode(envelope["epk"])
    kek = gostec.vko(d, gostec.decode_point(epk), base64.b64decode(envelope["ukm"]))
    key = gost.kdf_tree_256(kek, _LABEL_GOST, epk + client_pk, 1)
    pt = gost.MGM(gost.Kuznyechik(key)).open(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), aad.encode("utf-8"))
    return json.loads(pt.decode("utf-8"))


def seal_p256(payload: dict, client_pk: bytes, aad: str) -> dict:
    """P-256 envelope: ephemeral ECDH on secp256r1 → HKDF-SHA256(info = label ‖ epk ‖ client_pk) → AES-256-GCM.
    A hardware token only has to do one ECDH1_DERIVE with the ephemeral point to open it."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pk)
    esk = ec.generate_private_key(ec.SECP256R1())
    epk = esk.public_key().public_bytes(_E.X962, _PF.UncompressedPoint)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO_P256 + epk + client_pk).derive(esk.exchange(ec.ECDH(), peer))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), aad.encode("utf-8"))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"alg": ALG_P256, "v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(ct)}


def unseal_p256(envelope: dict, client_sk_raw: bytes, aad: str) -> dict:
    """Reference software decryption: the private key is the 32-byte big-endian scalar."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
    sk = ec.derive_private_key(int.from_bytes(client_sk_raw, "big"), ec.SECP256R1())
    client_pk = sk.public_key().public_bytes(_E.X962, _PF.UncompressedPoint)
    epk = base64.b64decode(envelope["epk"])
    shared = sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO_P256 + epk + client_pk).derive(shared)
    pt = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), aad.encode("utf-8"))
    return json.loads(pt.decode("utf-8"))


def unseal(envelope: dict, client_sk_raw: bytes, aad: str) -> dict:
    """Reference decryption (tests, tooling) — the client libraries implement the same steps."""
    if envelope.get("alg") == ALG_GOST and envelope.get("v") == 1:
        return unseal_gost(envelope, client_sk_raw, aad)
    if envelope.get("alg") == ALG_P256 and envelope.get("v") == 1:
        return unseal_p256(envelope, client_sk_raw, aad)
    if envelope.get("alg") != ALG or envelope.get("v") != 1:
        raise ValueError("unsupported sealed envelope")
    sk = X25519PrivateKey.from_private_bytes(client_sk_raw)
    client_pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    epk = base64.b64decode(envelope["epk"])
    shared = sk.exchange(X25519PublicKey.from_public_bytes(epk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + epk + client_pk).derive(shared)
    pt = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), aad.encode("utf-8"))
    return json.loads(pt.decode("utf-8"))


def generate_keypair(kind: str = "x25519") -> tuple[str, str]:
    """(private_b64, public_b64) — raw keys in standard base64: X25519 32+32 bytes, or GOST R 34.10-2012
    32-byte big-endian scalar + 64-byte X‖Y little-endian point."""
    if kind == "gost":
        import gostec
        sk_raw, pk_raw = gostec.generate_keypair()
        return base64.b64encode(sk_raw).decode(), base64.b64encode(pk_raw).decode()
    if kind == "p256":
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
        sk = ec.generate_private_key(ec.SECP256R1())
        return (base64.b64encode(sk.private_numbers().private_value.to_bytes(32, "big")).decode(),
                base64.b64encode(sk.public_key().public_bytes(_E.X962, _PF.UncompressedPoint)).decode())
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    sk = X25519PrivateKey.generate()
    return (base64.b64encode(sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
            base64.b64encode(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
