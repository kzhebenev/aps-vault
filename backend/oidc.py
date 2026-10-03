"""
APS Vault — OIDC (Authorization Code + PKCE).

Назначение: вход через OIDC-провайдер (Keycloak и др.) поверх master-password.
Без подмены криптографии: master нужен для расшифровки секретов в БД.

Стратегия unlock:
  - Если STATE уже разлочен (кто-то ввёл master в этот процесс) — OIDC-логин просто
    создаёт сессию для этого юзера (используется тот же master_key).
  - Если STATE НЕ разлочен И задан env VAULT_MASTER_PASSWORD — auto-unlock этим паролем.
    Это dev-режим: мастер-пароль оказывается в хранилище секретов оркестратора.
  - Иначе — 503 с просьбой сначала /api/auth/unlock мастером (graceful fallback).

Безопасность:
  - PKCE S256, state (CSRF), nonce (replay) — HttpOnly+Secure+SameSite=Lax+TTL 600s.
  - id_token RS256 через JWKS (cache 1h, retry on unknown kid).
  - iss/aud/exp/nonce строго, clock skew 60s.
  - email_verified обязательно, allowed_domains gate.
  - Fail-closed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.request
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

logger = logging.getLogger("aps-vault-oidc")


def _cfg() -> dict[str, Any]:
    return {
        "issuer": (os.environ.get("OIDC_ISSUER", "") or "").strip(),
        "client_id": (os.environ.get("OIDC_CLIENT_ID", "") or "").strip(),
        "client_secret": (os.environ.get("OIDC_CLIENT_SECRET", "") or "").strip(),
        "redirect_uri": (os.environ.get("OIDC_REDIRECT_URI", "") or "").strip(),
        "allowed_domains": [d for d in (os.environ.get("OIDC_ALLOWED_DOMAINS", "") or "").split() if d],
        "auto_unlock_master": os.environ.get("VAULT_MASTER_PASSWORD", "") or None,
    }


def is_enabled() -> bool:
    c = _cfg()
    return bool(c["issuer"] and c["client_id"] and c["client_secret"] and c["redirect_uri"])


STATE_COOKIE = "vault_oidc_state"
NONCE_COOKIE = "vault_oidc_nonce"
VERIFIER_COOKIE = "vault_oidc_pkce"
COOKIE_MAX = 600


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


_discovery_cache: dict[str, Any] = {"at": 0, "doc": None}
_jwks_cache: dict[str, Any] = {"at": 0, "keys": []}


def _urlopen_safe(url_or_req: Any):
    """Обёртка над urllib.request.urlopen с локальной nosemgrep-аннотацией.
    URL валидируется вызывающими: только https://-issuer из env (discovery, JWKS,
    token_endpoint). file:// невозможен (проверено в _http_get_json и exchange_code).
    """
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    return urllib.request.urlopen(url_or_req, timeout=5)


def _http_get_json(url: str) -> Any:
    # Discovery and JWKS carry the keys we verify identities with — https only, except in dev.
    import settings as _settings
    allowed = ("https://",) if not _settings.SETTINGS.dev else ("https://", "http://")
    if not url.startswith(allowed):
        raise RuntimeError("OIDC endpoints must be https")
    with _urlopen_safe(url) as r:
        return json.loads(r.read())


def _discovery() -> dict[str, Any]:
    c = _cfg()
    now = time.time()
    if _discovery_cache["doc"] and now - _discovery_cache["at"] < 3600:
        return _discovery_cache["doc"]
    doc = _http_get_json(f"{c['issuer']}/.well-known/openid-configuration")
    if doc.get("issuer") != c["issuer"]:
        raise RuntimeError("OIDC issuer mismatch")
    _discovery_cache["doc"] = doc
    _discovery_cache["at"] = now
    return doc


def _jwks(force: bool = False) -> list[dict[str, Any]]:
    now = time.time()
    if not force and _jwks_cache["keys"] and now - _jwks_cache["at"] < 3600:
        return _jwks_cache["keys"]
    doc = _discovery()
    j = _http_get_json(doc["jwks_uri"])
    _jwks_cache["keys"] = j.get("keys", [])
    _jwks_cache["at"] = now
    return _jwks_cache["keys"]


def _jwk_to_pubkey(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()


def _verify_id_token(token: str, expected_nonce: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("malformed id_token")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    if header.get("alg") != "RS256":
        raise RuntimeError("alg!=RS256")

    keys = _jwks()
    key = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if not key:
        keys = _jwks(force=True)
        key = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if not key:
        raise RuntimeError("unknown kid")

    pubkey = _jwk_to_pubkey(key)
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    pubkey.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())

    c = _cfg()
    now_ts = int(time.time())
    SKEW = 60
    if payload.get("iss") != c["issuer"]:
        raise RuntimeError("iss mismatch")
    aud = payload.get("aud")
    if not (aud == c["client_id"] or (isinstance(aud, list) and c["client_id"] in aud)):
        raise RuntimeError("aud mismatch")
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp + SKEW < now_ts:
        raise RuntimeError("expired")
    iat = payload.get("iat")
    if isinstance(iat, int) and iat - SKEW > now_ts:
        raise RuntimeError("future iat")
    if payload.get("nonce") != expected_nonce:
        raise RuntimeError("nonce mismatch")
    return payload


def login_redirect() -> RedirectResponse:
    if not is_enabled():
        raise HTTPException(404, "OIDC disabled")
    c = _cfg()
    state = _b64url(secrets.token_bytes(32))
    nonce = _b64url(secrets.token_bytes(32))
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    doc = _discovery()
    qs = (
        f"response_type=code&client_id={c['client_id']}"
        f"&redirect_uri={c['redirect_uri']}&scope=openid+email+profile"
        f"&state={state}&nonce={nonce}"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    url = f"{doc['authorization_endpoint']}?{qs}"
    resp = RedirectResponse(url, status_code=302)
    for name, value in ((STATE_COOKIE, state), (NONCE_COOKIE, nonce), (VERIFIER_COOKIE, verifier)):
        resp.set_cookie(name, value, max_age=COOKIE_MAX, httponly=True, secure=True, samesite="lax", path="/")
    return resp


def exchange_code(request: Request) -> dict[str, Any]:
    """Returns dict with email/name/sub. Raises HTTPException on failure.
    Cookies state/nonce/verifier потребляются (одноразовые) — вызывающий должен их погасить.
    """
    if not is_enabled():
        raise HTTPException(404, "OIDC disabled")
    c = _cfg()
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    cookie_state = request.cookies.get(STATE_COOKIE)
    cookie_nonce = request.cookies.get(NONCE_COOKIE)
    cookie_verifier = request.cookies.get(VERIFIER_COOKIE)
    if not (code and state and cookie_state and cookie_nonce and cookie_verifier):
        raise HTTPException(400, "missing oidc params")
    # timing-safe compare с защитой по длине
    sb = state.encode("ascii"); cb = cookie_state.encode("ascii")
    if len(sb) != len(cb) or not secrets.compare_digest(sb, cb):
        raise HTTPException(400, "state mismatch")

    # token exchange
    doc = _discovery()
    body = (
        f"grant_type=authorization_code&code={code}"
        f"&redirect_uri={c['redirect_uri']}"
        f"&client_id={c['client_id']}&client_secret={c['client_secret']}"
        f"&code_verifier={cookie_verifier}"
    ).encode("ascii")
    if not doc["token_endpoint"].startswith("https://"):
        raise HTTPException(503, "OIDC misconfigured")
    req = urllib.request.Request(
        doc["token_endpoint"],
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with _urlopen_safe(req) as r:
            tokens = json.loads(r.read())
    except Exception as e:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        # Логируем только класс исключения (str(e)/repr(e) могли бы протечь body).
        logger.warning("oidc exchange err type=%s", type(e).__name__)
        raise HTTPException(401, "token exchange failed")

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(401, "no id_token")
    try:
        payload = _verify_id_token(id_token, cookie_nonce)
    except Exception as e:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        # Логируем только класс исключения — сам JWT в логи не пишем.
        logger.warning("oidc verify err type=%s", type(e).__name__)
        raise HTTPException(401, "id_token invalid")

    email = (payload.get("email") or "").strip().lower()
    sub = payload.get("sub") or ""
    name = payload.get("name") or payload.get("preferred_username")
    if not email or not sub:
        raise HTTPException(401, "no email/sub")
    if payload.get("email_verified") is not True:
        raise HTTPException(401, "email not verified")
    if c["allowed_domains"]:
        dom = email.split("@")[-1] if "@" in email else ""
        if dom not in c["allowed_domains"]:
            raise HTTPException(403, "domain not allowed")
    return {"email": email, "name": name, "sub": sub}


def clear_oidc_cookies(resp: Response) -> None:
    for name in (STATE_COOKIE, NONCE_COOKIE, VERIFIER_COOKIE):
        resp.delete_cookie(name, path="/")


def auto_unlock_master_or_none() -> str | None:
    """Возвращает master-password из env VAULT_MASTER_PASSWORD,
    либо None если не задан. Только для dev-режима."""
    return _cfg()["auto_unlock_master"]
