"""Cloud KMS master-key providers (v0.16): the master key encrypted by a key that lives in a
cloud KMS and is only usable by the vault's cloud identity.

Two providers, one shape — `encrypt(plaintext, aad) -> ciphertext`, `decrypt(ciphertext, aad)
-> plaintext`:

* **aws** — AWS KMS `Encrypt`/`Decrypt` with Signature V4 done here (no SDK). The optional
  `EncryptionContext` carries the AAD. `VAULT_KMS_ENDPOINT` points it at LocalStack for tests.
* **yandex** — Yandex Cloud KMS `:encrypt`/`:decrypt` with an IAM token minted from an
  authorized service-account key (PS256 JWT). `aadContext` carries the AAD.

The AAD is where the PIN goes: `HKDF(pin)` as a context value means the KMS refuses to
decrypt the cell for anyone who does not know the PIN — even someone with the cloud
credentials — and every attempt shows up in the cloud audit log (CloudTrail / Audit Trails).
Without a PIN the cell opens for the server itself (auto mode: SSO hand-over, re-wrap on
password change), which moves the trust to the cloud IAM policy of the vault's identity.

Nothing here is exercised against a real cloud in the test suite: AWS is tested through
LocalStack (same wire protocol); Yandex is implemented from the public API reference and needs
a real service-account key to be verified — see docs/KMS.md.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request


import settings


class KmsError(Exception):
    pass


def configured() -> bool:
    st = settings.SETTINGS
    return st.kms_provider in ("aws", "yandex") and bool(st.kms_key_id)


def aad_for_pin(pin: str | None) -> str:
    """Context value: a PIN-derived string, or a fixed marker when no PIN is used."""
    if not pin:
        return "aps-vault:no-pin"
    import suite
    return "aps-vault:pin:" + suite.kdf(pin.encode("utf-8"), b"aps-vault/kms/pin-context/v1", length=16).hex()


def _http(url: str, body: bytes, headers: dict, timeout: float = 10) -> dict:
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8", "replace"))
            msg = detail.get("message") or detail.get("Message") or detail.get("__type") or str(detail)[:120]
        except Exception:
            msg = e.reason
        raise KmsError(f"KMS {e.code}: {msg}")
    except Exception as e:
        raise KmsError(f"KMS unreachable: {e.__class__.__name__}")


# ── AWS KMS (SigV4) ───────────────────────────────────────────────────────────
def _sigv4(method: str, url: str, region: str, service: str, body: bytes, headers: dict, access_key: str, secret_key: str, session_token: str | None) -> dict:
    u = urllib.parse.urlparse(url)
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ"); date = now.strftime("%Y%m%d")
    h = {k.lower(): v.strip() for k, v in headers.items()}
    h["host"] = u.netloc; h["x-amz-date"] = amz_date
    if session_token:
        h["x-amz-security-token"] = session_token
    signed = ";".join(sorted(h))
    canonical = "\n".join([method, u.path or "/", u.query, "".join(f"{k}:{h[k]}\n" for k in sorted(h)), signed, hashlib.sha256(body).hexdigest()])
    scope = f"{date}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = hmac.new(("AWS4" + secret_key).encode(), date.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return h


def _aws_call(action: str, payload: dict) -> dict:
    st = settings.SETTINGS
    region = st.kms_region or "us-east-1"
    url = st.kms_endpoint or f"https://kms.{region}.amazonaws.com/"
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": f"TrentService.{action}"}
    if not st.kms_aws_access_key or not st.kms_aws_secret_key:
        raise KmsError("AWS credentials missing (VAULT_KMS_AWS_ACCESS_KEY / VAULT_KMS_AWS_SECRET_KEY)")
    signed = _sigv4("POST", url, region, "kms", body, headers, st.kms_aws_access_key, st.kms_aws_secret_key, st.kms_aws_session_token or None)
    return _http(url, body, signed)


def _aws_encrypt(plaintext: bytes, aad: str) -> bytes:
    r = _aws_call("Encrypt", {"KeyId": settings.SETTINGS.kms_key_id, "Plaintext": base64.b64encode(plaintext).decode(), "EncryptionContext": {"aps_vault": aad}})
    return base64.b64decode(r["CiphertextBlob"])


def _aws_decrypt(ciphertext: bytes, aad: str) -> bytes:
    r = _aws_call("Decrypt", {"KeyId": settings.SETTINGS.kms_key_id, "CiphertextBlob": base64.b64encode(ciphertext).decode(), "EncryptionContext": {"aps_vault": aad}})
    return base64.b64decode(r["Plaintext"])


# ── Yandex Cloud KMS ─────────────────────────────────────────────────────────
_iam_cache: dict = {"token": None, "exp": 0.0}


def _yandex_iam_token() -> str:
    """IAM token from an authorized key (JSON from `yc iam key create`), cached ~50 min."""
    st = settings.SETTINGS
    if st.kms_yandex_iam_token:
        return st.kms_yandex_iam_token           # static token (e.g. from the metadata service) — caller refreshes it
    if _iam_cache["token"] and _iam_cache["exp"] > time.time() + 60:
        return _iam_cache["token"]
    if not st.kms_yandex_key_file:
        raise KmsError("Yandex credentials missing (VAULT_KMS_YANDEX_KEY_FILE or VAULT_KMS_YANDEX_IAM_TOKEN)")
    try:
        key = json.loads(open(st.kms_yandex_key_file, encoding="utf-8").read())
    except Exception as e:
        raise KmsError(f"cannot read the authorized key file: {e.__class__.__name__}")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    priv = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise KmsError("the authorized key must be RSA (PS256) — regenerate it with `yc iam key create`")
    now = int(time.time())
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    header = b64(json.dumps({"typ": "JWT", "alg": "PS256", "kid": key["id"]}).encode())
    claims = b64(json.dumps({"aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens", "iss": key["service_account_id"], "iat": now, "exp": now + 3600}).encode())
    sig = priv.sign(f"{header}.{claims}".encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    r = _http(st.kms_yandex_iam_endpoint or "https://iam.api.cloud.yandex.net/iam/v1/tokens", json.dumps({"jwt": f"{header}.{claims}.{b64(sig)}"}).encode(), {"Content-Type": "application/json"})
    _iam_cache["token"] = r["iamToken"]; _iam_cache["exp"] = time.time() + 50 * 60
    return r["iamToken"]


def _yandex_call(op: str, payload: dict) -> dict:
    st = settings.SETTINGS
    base = (st.kms_endpoint or "https://kms.yandex/kms/v1").rstrip("/")
    url = f"{base}/keys/{st.kms_key_id}:{op}"
    return _http(url, json.dumps(payload).encode(), {"Content-Type": "application/json", "Authorization": f"Bearer {_yandex_iam_token()}"})


def _yandex_encrypt(plaintext: bytes, aad: str) -> bytes:
    r = _yandex_call("encrypt", {"plaintext": base64.b64encode(plaintext).decode(), "aadContext": base64.b64encode(aad.encode()).decode()})
    return base64.b64decode(r["ciphertext"])


def _yandex_decrypt(ciphertext: bytes, aad: str) -> bytes:
    r = _yandex_call("decrypt", {"ciphertext": base64.b64encode(ciphertext).decode(), "aadContext": base64.b64encode(aad.encode()).decode()})
    return base64.b64decode(r["plaintext"])


# ── facade ───────────────────────────────────────────────────────────────────
def encrypt(plaintext: bytes, pin: str | None) -> bytes:
    p = settings.SETTINGS.kms_provider
    aad = aad_for_pin(pin)
    if p == "aws":
        return _aws_encrypt(plaintext, aad)
    if p == "yandex":
        return _yandex_encrypt(plaintext, aad)
    raise KmsError("VAULT_KMS_PROVIDER must be aws or yandex")


def decrypt(ciphertext: bytes, pin: str | None) -> bytes:
    p = settings.SETTINGS.kms_provider
    aad = aad_for_pin(pin)
    if p == "aws":
        return _aws_decrypt(ciphertext, aad)
    if p == "yandex":
        return _yandex_decrypt(ciphertext, aad)
    raise KmsError("VAULT_KMS_PROVIDER must be aws or yandex")


def info() -> dict:
    st = settings.SETTINGS
    return {"provider": st.kms_provider, "key_id": st.kms_key_id, "region": st.kms_region or None,
            "endpoint": st.kms_endpoint or None, "credentials": bool((st.kms_aws_access_key and st.kms_aws_secret_key) or st.kms_yandex_key_file or st.kms_yandex_iam_token)}
