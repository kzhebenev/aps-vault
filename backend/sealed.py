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


def parse_public_key(b64: str) -> bytes:
    """Validate a client public key: standard base64 of exactly 32 bytes that is a usable X25519 point."""
    s = (b64 or "").strip()
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raise ValueError("client_public_key must be standard base64 of a raw 32-byte X25519 public key")
    if len(raw) != 32:
        raise ValueError(f"client_public_key must decode to 32 bytes (got {len(raw)})")
    try:
        X25519PublicKey.from_public_bytes(raw)
    except Exception:
        raise ValueError("client_public_key is not a valid X25519 public key")
    if raw == b"\x00" * 32:
        raise ValueError("client_public_key is the all-zero point")
    return raw


def normalize_public_key(b64: str) -> str:
    """Canonical storage form (re-encoded standard base64 with padding)."""
    return base64.b64encode(parse_public_key(b64)).decode()


def seal(payload: dict, client_pk_b64: str, aad: str) -> dict:
    client_pk = parse_public_key(client_pk_b64)
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = esk.exchange(X25519PublicKey.from_public_bytes(client_pk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + epk + client_pk).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), aad.encode("utf-8"))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"alg": ALG, "v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(ct)}


def unseal(envelope: dict, client_sk_raw: bytes, aad: str) -> dict:
    """Reference decryption (tests, tooling) — the client libraries implement the same steps."""
    if envelope.get("alg") != ALG or envelope.get("v") != 1:
        raise ValueError("unsupported sealed envelope")
    sk = X25519PrivateKey.from_private_bytes(client_sk_raw)
    client_pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    epk = base64.b64decode(envelope["epk"])
    shared = sk.exchange(X25519PublicKey.from_public_bytes(epk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + epk + client_pk).derive(shared)
    pt = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), aad.encode("utf-8"))
    return json.loads(pt.decode("utf-8"))


def generate_keypair() -> tuple[str, str]:
    """(private_b64, public_b64) — raw 32-byte keys in standard base64."""
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    sk = X25519PrivateKey.generate()
    return (base64.b64encode(sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
            base64.b64encode(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
