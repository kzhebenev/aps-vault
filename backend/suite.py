"""Cipher suite (0.18): every symmetric primitive the vault uses goes through here, so the
whole product can run on one of two algorithm families.

| | `aes` (default) | `gost` |
|---|---|---|
| AEAD for values, folder keys, cells | AES-256-GCM, 96-bit nonce | Kuznyechik-MGM (GOST R 34.12-2015 + R 1323565.1.026-2019 / RFC 9058), 128-bit nonce |
| key derivation (session wrap, PRF cell, SSO cell, KMS PIN context) | HKDF-SHA256 | KDF_TREE_GOSTR3411_2012_256 (R 50.1.113-2016) |
| hashes for look-up (tokens, link tokens, session ids) | SHA-256 | Streebog-256 (GOST R 34.11-2012) |
| token / share-link key | Argon2id (m=8 MiB, t=2) | KDF_TREE over the random token |
| master password → master key | Argon2id (m=64 MiB, t=3, p=4) | Argon2id too, unless `VAULT_GOST_PBKDF2=<iterations>` selects PBKDF2-HMAC-Streebog-512 (R 50.1.111-2016) |

The suite is chosen at **initialisation** (`VAULT_CIPHER`) and stored in `vault_config`; after
that the stored value wins over the environment, because ciphertext written under one family
cannot be read with the other. Moving a vault between suites = export → new vault → import.

Outside the suite, deliberately: TOTP (HMAC-SHA1, the authenticator apps' standard), WebAuthn
signatures (ES256/RS256, the authenticators' standard), OIDC PKCE (SHA-256, the IdP's
standard), AWS SigV4 (SHA-256, AWS's protocol), webhook signatures (HMAC-SHA256, our published
contract to receivers), sealed delivery to clients (X25519 + HKDF-SHA256 + AES-256-GCM — the
four client libraries implement exactly that; a GOST envelope is a separate piece of work),
and the Argon2 hash of the recovery code and the approver password (password hashing, not
data protection). The documentation (`docs/GOST.md`) says so in the same words.
"""
from __future__ import annotations

import hashlib
import logging
import secrets as pysecrets

import settings

logger = logging.getLogger("aps-vault")

AES = "aes"
GOST = "gost"
SUITES = (AES, GOST)
LABELS = {AES: "AES-256-GCM · HKDF-SHA256 · Argon2id", GOST: "ГОСТ Р 34.12-2015 Кузнечик-MGM · ГОСТ Р 34.11-2012 Стрибог · KDF_TREE"}

_active: str | None = None          # set from vault_config once a vault exists


def requested() -> str:
    """What the environment asks for (used at init and before a vault exists)."""
    v = (getattr(settings.SETTINGS, "cipher", "") or AES).lower()
    if v not in SUITES:
        raise ValueError(f"VAULT_CIPHER must be one of {', '.join(SUITES)}, not {v!r}")
    return v


def active() -> str:
    return _active or requested()


def activate(name: str) -> None:
    """Called when the vault's config row is read: the stored suite wins over the environment."""
    global _active
    name = (name or AES).lower()
    if name not in SUITES:
        raise ValueError(f"unknown cipher suite in vault_config: {name!r}")
    if _active != name:
        if _active is not None or name != requested():
            logger.warning("cipher suite from the database: %s (environment asked for %s) — the database wins", name, requested())
        _active = name


def reset_for_tests() -> None:
    global _active
    _active = None


def label() -> str:
    return LABELS[active()]


# ── AEAD ─────────────────────────────────────────────────────────────────────
def nonce_len() -> int:
    return 12 if active() == AES else 16


def new_nonce() -> bytes:
    if active() == AES:
        return pysecrets.token_bytes(12)
    import gost
    return gost.mgm_nonce()


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if nonce is None:
        nonce = new_nonce()
    elif len(nonce) != nonce_len():
        raise ValueError(f"nonce must be {nonce_len()} bytes for the {active()} suite")
    if active() == AES:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, plaintext, aad or None), nonce
    import gost
    return gost.MGM(gost.Kuznyechik(key)).seal(nonce, plaintext, aad), nonce


class AuthError(Exception):
    """Authentication tag mismatch / wrong key (suite-neutral; `cryptography.exceptions.InvalidTag` is a subclass marker in the aes suite)."""


def aead_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if active() == AES:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ciphertext, aad or None)        # raises InvalidTag
    import gost
    try:
        return gost.MGM(gost.Kuznyechik(key)).open(nonce, ciphertext, aad)
    except ValueError as e:
        from cryptography.exceptions import InvalidTag
        raise InvalidTag(str(e))                                          # one exception type for callers


# ── key derivation and hashing ───────────────────────────────────────────────
def kdf(ikm: bytes, info: bytes, salt: bytes = b"", length: int = 32) -> bytes:
    """HKDF-SHA256(ikm, salt, info) in the aes suite; KDF_TREE_GOSTR3411_2012_256(key=ikm, label=info,
    seed=salt) in the gost suite. `length` ≤ 32 for gost (one derived key)."""
    if active() == AES:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info).derive(ikm)
    import gost
    if length > 32:
        raise ValueError("gost kdf derives at most 32 bytes")
    return gost.kdf_tree_256(ikm, info, salt, 1)[:length]


def digest(data: bytes) -> bytes:
    if active() == AES:
        return hashlib.sha256(data).digest()
    import gost
    return gost.streebog256(data)


def hexdigest(data: bytes) -> str:
    return digest(data).hex()


def password_kdf(password: str, salt: bytes) -> bytes:
    """Master password → 32-byte key. Argon2id in both suites (memory-hard); the gost suite can be
    switched to PBKDF2-HMAC-Streebog-512 (R 50.1.111-2016) with VAULT_GOST_PBKDF2=<iterations> —
    slower by design and not memory-hard, for deployments that want every KDF from the GOST family."""
    iters = getattr(settings.SETTINGS, "gost_pbkdf2_iterations", 0) if active() == GOST else 0
    if iters:
        import gost
        return gost.pbkdf2_streebog512(password.encode("utf-8"), salt, iters, 32)
    from argon2 import low_level
    return low_level.hash_secret_raw(secret=password.encode("utf-8"), salt=salt, time_cost=3, memory_cost=64 * 1024,
                                     parallelism=4, hash_len=32, type=low_level.Type.ID)


_TOKEN_LABEL = b"aps-vault/token-key/v1"


def token_kdf(secret: bytes, salt: bytes) -> bytes:
    """A random ≥192-bit token (service token, share link) → 32-byte wrap key. The input is random,
    so this is a one-way mapping, not a password stretcher: Argon2id with light parameters in the
    aes suite (unchanged since 0.3), KDF_TREE in the gost suite."""
    if active() == AES:
        from argon2 import low_level
        return low_level.hash_secret_raw(secret=secret, salt=salt, time_cost=2, memory_cost=8 * 1024,
                                         parallelism=2, hash_len=32, type=low_level.Type.ID)
    import gost
    return gost.kdf_tree_256(secret, _TOKEN_LABEL, salt, 1)
