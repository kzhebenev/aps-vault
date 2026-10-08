"""APS Vault client for Python 3.9+ — standard library only.

    from aps_vault import Vault
    v = Vault("https://vault.example.com", os.environ["VAULT_TOKEN"])
    db_password = v.get("db-password")             # str
    full = v.get_full("db-password")               # {"name","value","login"?,"notes"?,"totp"?,"updated_at"}
    v.put("db-password", "new-value", login="app")  # token needs can_write

Sealed delivery (0.17): a token bound to this application's X25519 public key gets values
encrypted to that key — plaintext never crosses the wire or the proxy chain. Generate a key
pair once (``python -m aps_vault keygen``), hand the public half to the vault administrator
for the token, keep the private half next to the token:

    v = Vault(url, token, client_private_key=os.environ["VAULT_CLIENT_KEY"])   # base64 raw 32 bytes
    v.get("db-password")                        # decrypted in this process; needs `cryptography`

Behaviour:
    * token must be a service token (``vlt_…``) — the master password never belongs in code;
    * in-memory cache (``cache_ttl``, default 300 s; 0 disables) so a restart storm does not
      hammer the vault, and a vault restart does not take the application down;
    * retries with exponential back-off on 429/5xx/network errors (``max_retries``);
    * ``fail_open_cache=True`` returns the last cached value when the vault is unreachable
      and the entry is stale — the right trade-off for an encryption key at startup — but only
      within ``max_stale`` (default 24 h, 0.41.11) of when it was fetched: after a revocation or a
      rotation an outage must not keep an old value alive forever. ``max_stale=None`` = no limit;
      a 401/403 is never answered from the cache;
    * nothing is logged; exceptions carry the HTTP status and the server's ``detail``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

__version__ = "0.41.11"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """0.37: never follow a redirect — urllib would carry the Authorization header to whatever host the answer names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"vault: redirect to {newurl[:100]} refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect())


class VaultError(Exception):
    """HTTP-level error from the vault (status + server detail)."""

    def __init__(self, status: int, message: str, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class _Entry:
    value: dict
    expires_at: float
    fetched_at: float = 0.0


SEALED_ALG = "X25519-HKDF-SHA256-AES256GCM"
_SEALED_INFO = b"aps-vault/sealed/v1"
SEALED_ALG_GOST = "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM"
_SEALED_LABEL_GOST = b"aps-vault/sealed-gost/v1"
SEALED_ALG_P256 = "P256-HKDF-SHA256-AES256GCM"
SEALED_ALG_PQC = "X25519MLKEM768-HKDF-SHA256-AES256GCM"      # 0.27: X25519 + ML-KEM-768 hybrid
SEALED_ALG_GOST_PQC = "VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM"   # 0.32: GOST + ML-KEM-768 hybrid
_SEALED_LABEL_GOST_PQC = b"aps-vault/sealed-gost-pqc/v1"
_SEALED_INFO_PQC = b"aps-vault/sealed-pqc/v1"
_SEALED_INFO_P256 = b"aps-vault/sealed-p256/v1"


class Pkcs11Key:
    """A P-256 private key that lives in a PKCS#11 token — a TPM 2.0 through tpm2-pkcs11, an HSM,
    a smart card, or SoftHSM2 for tests (0.22). The key never leaves the token: the client only
    asks it for one ECDH derivation per envelope. Needs `pip install 'aps-vault[pkcs11]'`.

        key = Pkcs11Key("/usr/lib/softhsm/libsofthsm2.so", token_label="node", pin="1234", key_label="vault-node")
        Pkcs11Key.generate(...)                 # make the pair inside the token (once, at install)
        Vault(url, token, client_private_key=key)
    """

    kind = "p256"

    def __init__(self, module: str, token_label: str, pin: str, key_label: str = "aps-vault-node") -> None:
        self.module, self.token_label, self.pin, self.key_label = module, token_label, pin, key_label

    def _lib(self):
        try:
            import pkcs11  # noqa: F401
        except ImportError:  # pragma: no cover
            raise RuntimeError("vault: a PKCS#11 key needs the `python-pkcs11` package (pip install 'aps-vault[pkcs11]')") from None
        import pkcs11
        return pkcs11, pkcs11.lib(self.module).get_token(token_label=self.token_label)

    @classmethod
    def generate(cls, module: str, token_label: str, pin: str, key_label: str = "aps-vault-node") -> "Pkcs11Key":
        """Create a non-extractable P-256 key pair in the token (fails if the label exists)."""
        self = cls(module, token_label, pin, key_label)
        pkcs11, tok = self._lib()
        from pkcs11 import Attribute, KeyType
        from pkcs11.util.ec import encode_named_curve_parameters
        with tok.open(user_pin=pin, rw=True) as s:
            try:
                s.get_key(label=key_label, object_class=pkcs11.ObjectClass.PRIVATE_KEY)
                raise RuntimeError(f"vault: a key labelled {key_label!r} already exists in the token")
            except pkcs11.exceptions.NoSuchKey:
                pass
            s.generate_keypair(KeyType.EC, 256, public_template={Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
                               private_template={Attribute.EXTRACTABLE: False, Attribute.SENSITIVE: True, Attribute.DERIVE: True}, store=True, label=key_label)
        return self

    def public_bytes(self) -> bytes:
        """Uncompressed point 0x04 ‖ X ‖ Y (65 bytes) — what goes into the token's `client_public_key`."""
        pkcs11, tok = self._lib()
        from pkcs11.util.ec import encode_ec_public_key
        from cryptography.hazmat.primitives import serialization
        with tok.open(user_pin=self.pin) as s:
            pub = s.get_key(label=self.key_label, object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            spki = encode_ec_public_key(pub)
        return serialization.load_der_public_key(spki).public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def public_b64(self) -> str:
        import base64
        return base64.b64encode(self.public_bytes()).decode()

    def ecdh(self, peer_point: bytes) -> bytes:
        """Shared secret with the vault's ephemeral point, computed inside the token (CKM_ECDH1_DERIVE)."""
        pkcs11, tok = self._lib()
        from pkcs11 import Attribute, KeyType
        with tok.open(user_pin=self.pin) as s:
            priv = s.get_key(label=self.key_label, object_class=pkcs11.ObjectClass.PRIVATE_KEY)
            shared = priv.derive_key(KeyType.GENERIC_SECRET, 256, mechanism_param=(pkcs11.KDF.NULL, None, peer_point),
                                     template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
            return bytes(shared[Attribute.VALUE])


def _p256_unseal(envelope: dict, key, name: str) -> dict:
    """P-256 envelope: ECDH with the ephemeral point (in software from the scalar, or inside a PKCS#11
    token), HKDF-SHA256(info = label ‖ epk ‖ our point), AES-256-GCM with the name as AAD."""
    import base64
    hashes, _, AESGCM, HKDF, ser = _crypto()
    from cryptography.hazmat.primitives.asymmetric import ec
    epk = base64.b64decode(envelope["epk"])
    try:
        if isinstance(key, Pkcs11Key):
            our = key.public_bytes()
            shared = key.ecdh(epk)
        else:
            sk = ec.derive_private_key(int.from_bytes(base64.b64decode(key), "big"), ec.SECP256R1())
            our = sk.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
            shared = sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk))
        k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_SEALED_INFO_P256 + epk + our).derive(shared)
        pt = AESGCM(k).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), name.encode("utf-8"))
    except Exception:
        raise VaultError(0, "vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)") from None
    return json.loads(pt.decode("utf-8"))


def _gost():
    try:
        import gostcrypto  # noqa: F401
    except ImportError:          # pragma: no cover
        raise RuntimeError("vault: the GOST envelope needs the `gostcrypto` package (pip install 'aps-vault[gost]')") from None
    from . import gost
    return gost


def _mlkem():
    try:
        from kyber_py.ml_kem import ML_KEM_768
    except ImportError:          # pragma: no cover
        raise RuntimeError("vault: the post-quantum envelope needs the `kyber-py` package (pip install 'aps-vault[pqc]')") from None
    return ML_KEM_768


def _pqc_unseal(envelope: dict, private_key_b64: str, name: str) -> dict:
    """Hybrid envelope (0.27): X25519 with the ephemeral key + ML-KEM-768 decapsulation with the key derived
    from our 64-byte seed; HKDF-SHA256 over both shared secrets (info = label ‖ epk ‖ kem_ct); AES-256-GCM
    with the secret name as AAD. Private key = X25519 sk (32) ‖ seed (64) = 96 bytes."""
    import base64
    hashes, x25519, AESGCM, HKDF, ser = _crypto()
    kem = _mlkem()
    raw = base64.b64decode(private_key_b64)
    if len(raw) != 96:
        raise VaultError(0, "vault: hybrid private key must be 96 bytes (X25519 sk ‖ ML-KEM-768 seed) — use generate_keypair('pqc')")
    try:
        _, dk = kem.key_derive(raw[32:])
        epk, kem_ct = base64.b64decode(envelope["epk"]), base64.b64decode(envelope["kem"])
        ss_x = x25519.X25519PrivateKey.from_private_bytes(raw[:32]).exchange(x25519.X25519PublicKey.from_public_bytes(epk))
        ss_kem = kem.decaps(dk, kem_ct)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_SEALED_INFO_PQC + epk + kem_ct).derive(ss_x + ss_kem)
        pt = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), name.encode("utf-8"))
    except Exception:
        raise VaultError(0, "vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)") from None
    return json.loads(pt.decode("utf-8"))


def _gost_pqc_unseal(envelope: dict, private_key_b64: str, name: str) -> dict:
    """GOST hybrid envelope (0.32): VKO GOST R 34.10-2012 with the ephemeral key (UKM from the envelope) + ML-KEM-768
    decapsulation with the key derived from our 64-byte seed; KDF_TREE_256(KEK ‖ ss_kem, label, epk ‖ kem) →
    Kuznyechik-MGM with the secret name as AAD. Private key = GOST scalar (32) ‖ seed (64) = 96 bytes."""
    import base64
    g = _gost()
    kem = _mlkem()
    raw = base64.b64decode(private_key_b64)
    if len(raw) != 96:
        raise VaultError(0, "vault: GOST hybrid private key must be 96 bytes (GOST scalar ‖ ML-KEM-768 seed) — use generate_keypair('gost-pqc')")
    try:
        d = int.from_bytes(raw[:32], "big")
        _, dk = kem.key_derive(raw[32:])
        epk, kem_ct = base64.b64decode(envelope["epk"]), base64.b64decode(envelope["kem"])
        kek = g.vko(d, g.decode_point(epk), base64.b64decode(envelope["ukm"]))
        ss_kem = kem.decaps(dk, kem_ct)
        key = g.kdf_tree_256(kek + ss_kem, _SEALED_LABEL_GOST_PQC, epk + kem_ct, 1)
        pt = g.MGM(g.Kuznyechik(key)).open(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), name.encode("utf-8"))
    except Exception:
        raise VaultError(0, "vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)") from None
    return json.loads(pt.decode("utf-8"))


def gost_pqc_public_from_private(private_key_b64: str) -> str:
    """The base64 1248-byte public key of a 96-byte GOST hybrid private key."""
    import base64
    g = _gost()
    raw = base64.b64decode(private_key_b64)
    if len(raw) != 96:
        raise VaultError(0, "vault: GOST hybrid private key must be 96 bytes (GOST scalar ‖ ML-KEM-768 seed)")
    gost_pk = g.encode_point(g.public_from_private(int.from_bytes(raw[:32], "big")))
    ek, _ = _mlkem().key_derive(raw[32:])
    return base64.b64encode(gost_pk + ek).decode()


def pqc_public_from_private(private_key_b64: str) -> str:
    """The base64 1216-byte public key of a 96-byte hybrid private key (for checking what the vault was given)."""
    import base64
    _, x25519, _, _, ser = _crypto()
    raw = base64.b64decode(private_key_b64)
    x_pk = x25519.X25519PrivateKey.from_private_bytes(raw[:32]).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    ek, _ = _mlkem().key_derive(raw[32:])
    return base64.b64encode(x_pk + ek).decode()


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import serialization
    except ImportError:          # pragma: no cover
        raise RuntimeError("vault: sealed delivery needs the `cryptography` package (pip install 'aps-vault[sealed]')") from None
    return hashes, x25519, AESGCM, HKDF, serialization


def generate_keypair(kind: str = "x25519") -> "tuple[str, str]":
    """(private_b64, public_b64) in standard base64. `x25519` (default): raw 32-byte keys.
    `gost`: GOST R 34.10-2012 key pair on id-tc26-gost-3410-2012-256-paramSetB — 32-byte big-endian
    scalar and a 64-byte X‖Y little-endian point; the vault then seals with VKO + Kuznyechik-MGM.
    `p256`: NIST P-256 — 32-byte scalar and a 65-byte uncompressed point; the curve a TPM or any PKCS#11
    token can hold (see Pkcs11Key for the hardware version).
    `pqc` (0.27): post-quantum hybrid X25519 + ML-KEM-768 — private = X25519 sk (32) ‖ ML-KEM seed (64),
    public = X25519 pk (32) ‖ ML-KEM encapsulation key (1184); needs `pip install 'aps-vault[pqc]'`.
    `gost-pqc` (0.32): GOST hybrid — private = GOST scalar (32) ‖ ML-KEM seed (64), public = GOST point (64) ‖
    ML-KEM ek (1184) = 1248 bytes; the vault seals with VKO + ML-KEM → KDF_TREE → Kuznyechik-MGM (gost + pqc extras).
    Give the public half to the vault administrator (token field `client_public_key`); keep the
    private half with the token (environment / secret store), never in the repository."""
    import base64
    if kind == "gost":
        g = _gost()
        sk_raw, pk_raw = g.generate_keypair()
        return base64.b64encode(sk_raw).decode(), base64.b64encode(pk_raw).decode()
    if kind == "gost-pqc":
        import os as _os
        g = _gost()
        sk_raw, pk_raw = g.generate_keypair()
        seed = _os.urandom(64)
        ek, _ = _mlkem().key_derive(seed)
        return base64.b64encode(sk_raw + seed).decode(), base64.b64encode(pk_raw + ek).decode()
    if kind == "pqc":
        _, x25519, _, _, ser = _crypto()
        import os as _os
        x = x25519.X25519PrivateKey.generate()
        seed = _os.urandom(64)
        ek, _ = _mlkem().key_derive(seed)
        return (base64.b64encode(x.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()) + seed).decode(),
                base64.b64encode(x.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw) + ek).decode())
    if kind == "p256":
        _, _, _, _, ser = _crypto()
        from cryptography.hazmat.primitives.asymmetric import ec
        sk = ec.generate_private_key(ec.SECP256R1())
        return (base64.b64encode(sk.private_numbers().private_value.to_bytes(32, "big")).decode(),
                base64.b64encode(sk.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)).decode())
    _, x25519, _, _, ser = _crypto()
    sk = x25519.X25519PrivateKey.generate()
    return (base64.b64encode(sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())).decode(),
            base64.b64encode(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode())


def unseal(envelope: dict, private_key_b64: str, name: str) -> dict:
    """Open a sealed envelope from GET /api/v1/m/secret/{name}: X25519 with the ephemeral key,
    HKDF-SHA256 over the shared secret (info = label || epk || our pk), AES-256-GCM with the
    secret name as AAD. Returns the payload dict ({value, login?, notes?, totp?})."""
    import base64
    if envelope.get("alg") == SEALED_ALG_PQC and envelope.get("v") == 1:
        if isinstance(private_key_b64, Pkcs11Key):
            raise VaultError(0, "vault: a PKCS#11 key opens only the P-256 envelope, the token sent the hybrid one")
        return _pqc_unseal(envelope, private_key_b64, name)
    if envelope.get("alg") == SEALED_ALG_GOST_PQC and envelope.get("v") == 1:
        if isinstance(private_key_b64, Pkcs11Key):
            raise VaultError(0, "vault: a PKCS#11 key opens only the P-256 envelope, the token sent the GOST hybrid one")
        return _gost_pqc_unseal(envelope, private_key_b64, name)
    if envelope.get("alg") == SEALED_ALG_GOST and envelope.get("v") == 1:
        return _unseal_gost(envelope, private_key_b64, name)
    if envelope.get("alg") == SEALED_ALG_P256 and envelope.get("v") == 1:
        return _p256_unseal(envelope, private_key_b64, name)
    if isinstance(private_key_b64, Pkcs11Key):
        raise VaultError(0, f"vault: a PKCS#11 key opens only the P-256 envelope, the token sent {envelope.get('alg')!r}")
    hashes, x25519, AESGCM, HKDF, ser = _crypto()
    if envelope.get("alg") != SEALED_ALG or envelope.get("v") != 1:
        raise VaultError(0, f"vault: unsupported sealed envelope {envelope.get('alg')!r} v{envelope.get('v')!r}")
    sk = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    pk = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    epk = base64.b64decode(envelope["epk"])
    shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(epk))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_SEALED_INFO + epk + pk).derive(shared)
    try:
        pt = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), name.encode("utf-8"))
    except Exception:
        raise VaultError(0, "vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)") from None
    return json.loads(pt.decode("utf-8"))


def _unseal_gost(envelope: dict, private_key_b64: str, name: str) -> dict:
    """GOST envelope: VKO GOST R 34.10-2012 (UKM from the envelope) → KEK; KDF_TREE(KEK, label, epk‖our pk)
    → key; Kuznyechik-MGM with the secret name as AAD."""
    import base64
    g = _gost()
    try:
        d = int.from_bytes(base64.b64decode(private_key_b64), "big")
        our_pk = g.encode_point(g.public_from_private(d))
        epk = base64.b64decode(envelope["epk"])
        kek = g.vko(d, g.decode_point(epk), base64.b64decode(envelope["ukm"]))
        key = g.kdf_tree_256(kek, _SEALED_LABEL_GOST, epk + our_pk, 1)
        pt = g.MGM(g.Kuznyechik(key)).open(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), name.encode("utf-8"))
    except Exception:
        raise VaultError(0, "vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)") from None
    return json.loads(pt.decode("utf-8"))


def enroll(base_url: str, code: str, *, name: str = "", gost: bool = False, kind: str | None = None,
           hardware_key: "Pkcs11Key | None" = None, timeout: float = 10.0) -> dict:
    """Node enrolment (0.21): generate this machine's key pair, present the one-time code, receive a
    token sealed to the new key. Returns {token, private_key, public_key, token_name, folder_name,
    vault_url}. Keep `token` and `private_key` with mode 0600 (VAULT_TOKEN / VAULT_CLIENT_KEY);
    the token alone opens nothing."""
    import socket
    if hardware_key is not None:
        private, public = hardware_key, hardware_key.public_b64()        # the private key stays in the token
    else:
        private, public = generate_keypair(kind or ("gost" if gost else "x25519"))
    body = json.dumps({"code": code, "public_key": public, "name": name or socket.gethostname()[:64]}).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + "/api/enroll", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"aps-vault-python/{__version__}"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:   # nosec — URL is the configured vault
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            detail = json.loads(raw).get("detail")
        except Exception:
            detail = raw.decode("utf-8", "replace")
        raise VaultError(e.code, f"vault enrol: HTTP {e.code} {detail}") from None
    return {"token": data["raw_token"], "private_key": private, "public_key": public, "token_name": data.get("token_name"),
            "folder_name": data.get("folder_name"), "vault_url": data.get("vault_url") or base_url}


class Vault:
    def __init__(self, base_url: str, token: str, *, cache_ttl: float = 300.0,
                 timeout: float = 5.0, max_retries: int = 3, fail_open_cache: bool = True, max_stale: Optional[float] = 86400.0,
                 user_agent: str = f"aps-vault-python/{__version__}", client_private_key: Optional[str] = None) -> None:
        if not base_url:
            raise ValueError("vault: base_url required")
        if not token or not token.startswith("vlt_"):
            raise ValueError("vault: a service token (vlt_…) is required, not a master password")
        self._base = base_url.rstrip("/")
        self._token = token
        self._ttl = cache_ttl
        self._timeout = timeout
        self._retries = max_retries
        self._fail_open = fail_open_cache
        self._max_stale = max_stale       # seconds since the fetch a stale value may still be served; None = no limit
        self._client_key = client_private_key or os.environ.get("VAULT_CLIENT_KEY") or None
        self._ua = user_agent
        self._cache: dict[str, _Entry] = {}

    @classmethod
    def from_env(cls, **kw: Any) -> "Vault":
        """VAULT_URL + VAULT_TOKEN, or VAULT_TOKEN_FILE pointing at a 0600 file."""
        url = os.environ.get("VAULT_URL", "")
        token = os.environ.get("VAULT_TOKEN", "")
        if not token and os.environ.get("VAULT_TOKEN_FILE"):
            with open(os.environ["VAULT_TOKEN_FILE"], encoding="utf-8") as f:
                token = f.read().strip()
        return cls(url, token, **kw)

    # ── public API ────────────────────────────────────────────────────────────
    def health(self) -> dict:
        return self._req("GET", "/api/v1/m/health")

    def list(self) -> list[dict]:
        return self._req("GET", "/api/v1/m/secrets")

    def get(self, name: str, version: int | None = None) -> str:
        """Current value, or an older one by number (`version`) — e.g. the previous encryption
        key while files encrypted with it are still being re-wrapped."""
        return self.get_full(name, version)["value"]

    def versions(self, name: str) -> dict:
        """{"current_version": N, "versions": [{"version", "current", "changed_at", ...}]} — no decrypt."""
        return self._req("GET", "/api/v1/m/secret/" + urllib.parse.quote(name, safe="") + "/versions")

    def get_full(self, name: str, version: int | None = None) -> dict:
        if not name:
            raise ValueError("vault: name required")
        now = time.time()
        key = f"{name}@{version}" if version else name
        hit = self._cache.get(key)
        if hit and hit.expires_at > now:
            return hit.value
        try:
            data = self._req("GET", "/api/v1/m/secret/" + urllib.parse.quote(name, safe="") + (f"?version={int(version)}" if version else ""))
        except (VaultError, OSError) as e:
            fresh_enough = hit is not None and (self._max_stale is None or now - hit.fetched_at <= self._max_stale)
            if hit and fresh_enough and self._fail_open and (not isinstance(e, VaultError) or e.status >= 500 or e.status == 429):
                return hit.value          # stale but known-good beats an outage — within max_stale
            raise
        if isinstance(data, dict) and "sealed" in data:
            if not self._client_key:
                raise VaultError(0, "vault: this token delivers sealed values — pass client_private_key (or VAULT_CLIENT_KEY)")
            # 0.37: the AAD is the name WE asked for — the response's own "name" could come from a swapped envelope
            payload = unseal(data.pop("sealed"), self._client_key, name)
            data.update(payload)
        elif self._client_key and isinstance(data, dict):
            # 0.37: with a key configured a plaintext answer is not accepted — a tampering proxy could drop the envelope
            raise VaultError(0, "vault: a client key is configured but the response is not sealed — refusing (a proxy may have replaced it)")
        if self._ttl > 0:
            self._cache[key] = _Entry(data, now + self._ttl, now)
        return data

    def put(self, name: str, value: str, *, login: str = "", tags: str = "", url: str = "") -> dict:
        """Create or update a secret in the token's folder (token must have can_write)."""
        body = {"value": value, "login": login, "tags": tags, "url": url}
        data = self._req("POST", "/api/v1/m/secret/" + urllib.parse.quote(name, safe=""), body)
        self._cache.pop(name, None)
        return data

    def totp(self, name: str) -> Optional[str]:
        """Current TOTP code (token must have can_read_totp); None if the secret has no seed."""
        self._cache.pop(name, None)       # codes change every 30 s — never serve from cache
        ttl, self._ttl = self._ttl, 0
        try:
            return self.get_full(name).get("totp")
        finally:
            self._ttl = ttl

    def clear_cache(self) -> None:
        self._cache.clear()

    # ── transport ─────────────────────────────────────────────────────────────
    def _req(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        last: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(self._base + path, data=payload, method=method, headers={
                "Authorization": f"Bearer {self._token}", "Accept": "application/json",
                "Content-Type": "application/json", "User-Agent": self._ua,
            })
            try:
                with _OPENER.open(req, timeout=self._timeout) as r:   # nosec — URL is the configured vault
                    return json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                raw = e.read()
                try:
                    parsed: Any = json.loads(raw)
                    detail = parsed.get("detail") if isinstance(parsed, dict) else None
                except Exception:
                    parsed, detail = raw.decode("utf-8", "replace"), None
                if (e.code == 429 or e.code >= 500) and attempt < self._retries:
                    time.sleep(2 ** attempt)
                    continue
                raise VaultError(e.code, f"vault {method} {path}: HTTP {e.code} {detail or e.reason}", parsed) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
                if attempt < self._retries:
                    time.sleep(2 ** attempt)
                    continue
        raise OSError(f"vault: request failed after {self._retries + 1} attempts: {last}")


__all__ = ["Vault", "VaultError", "Pkcs11Key", "generate_keypair", "unseal", "enroll", "__version__"]
