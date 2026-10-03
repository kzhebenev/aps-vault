"""
APS Vault — main FastAPI app.

Endpoints:
  GET  /api/health             — статус (locked/unlocked, version)
  POST /api/init               — первичная инициализация (master + recovery code)
  POST /api/auth/unlock        — master password → session cookie (8h)
  POST /api/auth/lock          — снять master-key из памяти, инвалидировать session
  POST /api/auth/recover       — recovery code → новый master password

  GET  /api/folders            — список папок
  POST /api/folders            — создать
  DELETE /api/folders/{id}     — удалить (если пустая)

  GET  /api/secrets            — список (без values)
  POST /api/secrets            — создать
  GET  /api/secrets/{id}       — детально + value
  PATCH /api/secrets/{id}      — обновить
  DELETE /api/secrets/{id}     — удалить

  GET  /api/tokens             — service-токены (для M4)
  POST /api/tokens             — создать service-token (показывает raw один раз)
  DELETE /api/tokens/{id}      — отозвать

  GET  /api/audit              — журнал

Machine API (M4 — отдельный модуль sdk_api.py):
  GET  /api/v1/m/secret/{name} — Bearer <service-token> → {name, value, [notes], [totp]}
  GET  /api/v1/m/secrets       — список секретов в scope токена

Все API под master-session-cookie (Bearer) кроме /init и machine API.
"""
from __future__ import annotations

import json
import logging
import os
import secrets as pysecrets
import socket
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import (Body, Cookie, Depends, FastAPI, Header, HTTPException, Path as FPath,
                     Query, Request)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import crypto
import db
import metrics
import netutil
import policy
import sessions
import settings as cfgmod
import siem
from pydantic import field_validator
from state import STATE, current_master_key, hash_token, set_current_master_key
import suite as _suite_mod

logger = logging.getLogger("aps-vault")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VERSION = "0.19.0"

app = FastAPI(title="APS Vault", version=VERSION)

# CORS with credentials is a grant of the administrator's session to another origin, so the
# list is explicit and comes from VAULT_ALLOWED_ORIGINS (a browser extension is added by its
# exact ID). 0.3.x allowed every chrome-extension:// and any localhost port — too wide.
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfgmod.SETTINGS.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Vault-Session", "X-CSRF-Token"],
)


# ─── Security headers middleware (Helmet-style) ──────────────────────────────
# Tailwind is bundled (frontend/tailwind.css, built from the classes used in app.js), so
# scripts come only from 'self'. Styles keep 'unsafe-inline' for the small <style> block in
# index.html and element.style assignments.
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}


@app.middleware("http")
async def _security_headers_mw(request: Request, call_next):
    response: Response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


# ─── CSRF (double-submit cookie) ──────────────────────────────────────────────
# Логика:
#   1. /api/auth/unlock выставляет НЕ-httpOnly cookie `vault_csrf` + возвращает
#      токен в JSON-body.
#   2. Frontend читает cookie или body, и при любом POST/PATCH/DELETE кладёт
#      то же значение в заголовок `X-CSRF-Token`.
#   3. Middleware проверяет равенство cookie == header через timing-safe compare.
#   4. GET-запросы CSRF не требуют (read-only, не меняют состояние).
#   5. /api/init НЕ требует CSRF (нет ещё сессии).
#   6. Machine API /api/v1/m/* НЕ требует CSRF (Bearer-токен достаточен, не cookie).
CSRF_COOKIE = "vault_csrf"
CSRF_HEADER = "x-csrf-token"
_CSRF_EXEMPT_PATHS = {"/api/init", "/api/auth/unlock", "/api/auth/recover",
                       "/api/auth/oidc/login", "/api/auth/oidc/callback", "/api/auth/oidc/status",
                       "/api/auth/webauthn/options", "/api/auth/webauthn/unlock", "/api/auth/hsm/unlock", "/api/auth/kms/unlock"}


def _csrf_required(method: str, path: str) -> bool:
    if method in {"GET", "HEAD", "OPTIONS"}:
        return False
    if path in _CSRF_EXEMPT_PATHS:
        return False
    if path.startswith("/api/v1/m/"):     # Machine API — Bearer-only, не cookie
        return False
    if path.startswith("/api/approve/"):  # approver's decision: no session, authenticated by the approver password
        return False
    return path.startswith("/api/")


@app.middleware("http")
async def _csrf_mw(request: Request, call_next):
    # CSRF is a cookie problem: a native client (mobile app, extension background, CLI) that
    # carries the session in `Authorization: Bearer <sid>` and sends no session cookie cannot be
    # tricked by a cross-site form, so the double-submit check does not apply to it (0.12).
    bearer_only = SESSION_COOKIE not in request.cookies and (request.headers.get("authorization", "").lower().startswith("bearer "))
    if _csrf_required(request.method, request.url.path) and not bearer_only:
        cookie = request.cookies.get(CSRF_COOKIE, "")
        header = request.headers.get(CSRF_HEADER, "")
        if not cookie or not header or not secrets_compare(cookie, header):
            return JSONResponse({"detail": "CSRF token missing or mismatched"}, status_code=403)
    return await call_next(request)


def secrets_compare(a: str, b: str) -> bool:
    """Timing-safe сравнение строк."""
    import secrets as _s
    if not a or not b or len(a) != len(b):
        return False
    return _s.compare_digest(a.encode(), b.encode())


# ─── Audit ────────────────────────────────────────────────────────────────────
def audit(action: str, target: str = "", actor: str = "master",
          ip: str = "", ua: str = "", meta: dict | None = None) -> None:
    with db.get_session() as s:
        s.add(db.AuditLog(
            action=action, target=target, actor=actor,
            ip=ip[:64], user_agent=ua[:256],
            meta=json.dumps(meta, ensure_ascii=False) if meta else "",
        ))
        s.commit()
    # the same event goes to the SIEM and into the metrics — one call site, no drift
    siem.send(action, actor=actor, target=target, ip=ip, ua=ua, meta=meta, version=VERSION)
    metrics.record(action)


def _ui_policy_check(request: Request) -> None:
    """PAM-style gate for the human UI: VAULT_UI_ALLOWED_CIDRS / VAULT_UI_ALLOWED_HOURS.
    Applied at unlock, at OIDC login and on every authenticated request, so an existing
    session stops working the moment the policy no longer matches."""
    cfg = cfgmod.SETTINGS
    if not cfg.ui_allowed_cidrs and not cfg.ui_allowed_hours:
        return
    ip = _client_ip(request)
    reason = policy.check(cfg.ui_allowed_cidrs, cfg.ui_allowed_hours, ip)
    if reason:
        audit("auth:policy_denied", ip=ip, ua=request.headers.get("user-agent", ""), meta={"reason": reason})
        siem.security_log("policy", ip, "scope=ui")
        raise HTTPException(403, f"access policy: {reason}")


# ─── Auth dependency ──────────────────────────────────────────────────────────
SESSION_COOKIE = "vault_session"


async def require_unlocked(
    request: Request,
    vault_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> str:
    """Resolve the session row (shared by all replicas) and make its master key available to
    the request via `current_master_key()`. Async on purpose: the contextvar must be set in
    the request's own context, not in a worker thread."""
    sid = vault_session
    if not sid and authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            sid = parts[1]
    found = sessions.resolve(sid) if sid else None
    if not found:
        set_current_master_key(None)
        raise HTTPException(401, "vault is locked or the session is invalid — unlock first")
    row, key = found
    set_current_master_key(key)
    request.state.master_key = key
    request.state.session_row = row
    _ui_policy_check(request)
    return sid


def _client_ip(request: Request) -> str:
    # Forwarding headers are honoured only from trusted proxies — see netutil.
    return netutil.client_ip(request)


def _check_url(v: str) -> str:
    """A secret's URL is rendered as a link in the UI; anything but http(s) is refused so a
    token with write access cannot plant a javascript: link for the administrator to click."""
    v = (v or "").strip()
    if v and not (v.startswith("https://") or v.startswith("http://")):
        raise ValueError("url must start with http:// or https://")
    return v


# ─── Crypto helpers ───────────────────────────────────────────────────────────
def archive_value(session, sec, changed_by: str = "master") -> None:
    """Move the current value into history under its version number and advance the counter.
    One place for the human PATCH, the machine PUT and the KV facade, so numbering never drifts."""
    session.add(db.SecretHistory(secret_id=sec.id, folder_id=sec.folder_id, value_enc=sec.value_enc,
                                 value_nonce=sec.value_nonce, changed_by=changed_by, version=sec.version or 1))
    sec.version = (sec.version or 1) + 1


def _get_or_create_folder_key(session, folder_id: int) -> bytes:
    """Возвращает расшифрованный scope-key для папки. Требует сессию с master-ключом."""
    master_key = current_master_key()
    folder = session.get(db.Folder, folder_id)
    if not folder:
        raise HTTPException(404, "folder not found")
    return crypto.decrypt(master_key, folder.scope_key_enc, folder.scope_key_nonce)


def _enc_with_folder(session, folder_id: int, plaintext: bytes) -> tuple[bytes, bytes]:
    key = _get_or_create_folder_key(session, folder_id)
    try:
        return crypto.encrypt(key, plaintext)
    finally:
        # nothing to zeroize here — bytes immutable
        pass


def _dec_with_folder(session, folder_id: int, ct: bytes, nonce: bytes) -> bytes:
    if not ct:
        return b""
    key = _get_or_create_folder_key(session, folder_id)
    return crypto.decrypt(key, ct, nonce)


# ─── Models (Pydantic) ────────────────────────────────────────────────────────
class InitRequest(BaseModel):
    master_password: str = Field(min_length=12, max_length=256)
    init_token: str = ""   # must equal VAULT_INIT_TOKEN (unless VAULT_DEV)


class InitResponse(BaseModel):
    ok: bool
    recovery_code: str
    note: str


class UnlockResponse(BaseModel):
    ok: bool
    session_ttl_sec: int


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)


def _parse_expires(v):
    """ISO date or datetime (UTC) → naive UTC datetime; '' → None. 422 on garbage."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.replace(tzinfo=None)
    v = str(v).strip()
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("expires_at must be an ISO date (YYYY-MM-DD) or datetime")
    if d.tzinfo is not None:
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    return d


_GEN_ALPHABETS = {"alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}


def generate_value(spec: str) -> str:
    """Server-side random value: 'base64:32' (32 random bytes, urlsafe base64), 'hex:32',
    'alnum:40' (40 chars). The administrator never sees it — that is the point for
    machine-only key material."""
    import base64
    try:
        kind, n = spec.split(":"); n = int(n)
    except ValueError:
        raise ValueError("generate must be like base64:32, hex:32 or alnum:40")
    if not 8 <= n <= 512:
        raise ValueError("generate size must be 8..512")
    if kind == "base64":
        return base64.urlsafe_b64encode(pysecrets.token_bytes(n)).decode().rstrip("=")
    if kind == "hex":
        return pysecrets.token_hex(n)
    if kind in _GEN_ALPHABETS:
        a = _GEN_ALPHABETS[kind]; return "".join(pysecrets.choice(a) for _ in range(n))
    raise ValueError("generate kind must be base64, hex or alnum")


class SecretCreate(BaseModel):
    folder_id: int
    name: str = Field(min_length=1, max_length=256)
    value: str = ""
    login: str = ""
    notes: str = ""
    totp_seed: str = ""
    tags: str = ""
    url: str = ""
    expires_at: str | None = None      # v0.7: rotation deadline, ISO date
    machine_only: bool = False         # v0.9: never shown to humans
    generate: str | None = None        # v0.9: "base64:32" | "hex:32" | "alnum:40" — server makes the value
    require_approval: bool = False     # v0.12: a person reads it only after the approver confirms

    @field_validator("generate")
    @classmethod
    def _gen(cls, v):
        if v:
            generate_value(v)   # ValueError → 422
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _check_url(v)

    @field_validator("expires_at")
    @classmethod
    def _exp(cls, v):
        _parse_expires(v)
        return v


class SecretUpdate(BaseModel):
    name: str | None = None
    value: str | None = None
    login: str | None = None
    notes: str | None = None
    totp_seed: str | None = None
    tags: str | None = None
    url: str | None = None
    folder_id: int | None = None       # v0.7: move to another folder (re-encrypted under its key)
    expires_at: str | None = None      # v0.7: "" clears the deadline
    clear_expires: bool = False
    machine_only: bool | None = None   # v0.9: hide from humans / (audited) show again
    require_approval: bool | None = None   # v0.12

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return None if v is None else _check_url(v)

    @field_validator("expires_at")
    @classmethod
    def _exp(cls, v):
        _parse_expires(v)
        return v


class SecretListItem(BaseModel):
    id: int
    folder_id: int
    folder_name: str
    name: str
    tags: str
    url: str
    has_login: bool
    has_totp: bool
    has_notes: bool
    created_at: str
    updated_at: str
    last_accessed: str | None
    access_count: int
    expires_at: str | None = None


class SecretFull(SecretListItem):
    value: str
    login: str = ""
    notes: str = ""
    totp: str | None = None       # текущий 6-значный код


# ─── Endpoints: health + init + auth ──────────────────────────────────────────
NODE = os.environ.get("VAULT_NODE_NAME") or socket.gethostname()


@app.get("/api/health")
async def health(vault_session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    """`unlocked` is a property of the caller's session, not of the server: since 0.6 the
    master key travels with the session row, so one client unlocking never unlocks the UI for
    another (bug 2026-06-08), and any replica answers the same for the same cookie."""
    db_ok = db.ping()
    return {
        "status": "ok" if db_ok else "degraded",
        "version": VERSION,
        "node": NODE,
        "db": "ok" if db_ok else "error",
        "initialized": crypto.config_exists() if db_ok else None,
        "unlocked": bool(vault_session and db_ok and sessions.resolve(vault_session)),
        "cipher": _suite_mod.active(), "cipher_label": _suite_mod.label(),
        "server_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.get("/api/ready")
async def ready():
    """Readiness for a load balancer: 200 when this replica can reach the shared database
    (an uninitialised or locked vault is still *ready* — it can be initialised/unlocked)."""
    if not db.ping():
        return JSONResponse({"ready": False, "node": NODE, "db": "error"}, status_code=503)
    return {"ready": True, "node": NODE, "db": "ok"}


@app.post("/api/init", response_model=InitResponse)
async def init_vault(req: InitRequest, request: Request):
    if crypto.config_exists():
        raise HTTPException(409, "vault is already initialised")
    # A fresh instance exposed to the network must not be claimable by whoever arrives first.
    st = cfgmod.SETTINGS
    if st.init_token:
        if not secrets_compare(req.init_token, st.init_token):
            audit("vault:init_denied", ip=_client_ip(request))
            raise HTTPException(403, "init token mismatch")
    elif not st.dev:
        raise HTTPException(403, "VAULT_INIT_TOKEN is not set — set it in the environment to allow initialisation")
    if len(req.master_password) < 12:
        raise HTTPException(400, "master password must be at least 12 characters")
    cfg, recovery_code = crypto.init_vault(req.master_password)
    # Сразу инициализируем БД
    db.get_engine()
    audit("vault:init", ip=_client_ip(request))
    return InitResponse(
        ok=True,
        recovery_code=recovery_code,
        note="SAVE THIS CODE — it is shown only once. Without it and the master password there is no recovery.",
    )


class UnlockRequest(BaseModel):
    master_password: str
    totp_code: str | None = None     # если 2FA включена — требуется 6-значный код
    webauthn: dict | None = None     # v0.13: assertion when the security key is a second factor


@app.post("/api/auth/unlock", response_model=UnlockResponse)
async def unlock(req: UnlockRequest, request: Request):
    if not crypto.config_exists():
        raise HTTPException(412, "vault is not initialised — call /api/init first")
    ip = _client_ip(request)
    # Brute-force budget: per IP and global, persisted in the DB (netutil) — a spoofed
    # X-Forwarded-For or a restart no longer resets it. Checked before Argon2 so a locked
    # client cannot even burn CPU.
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)
    cfg = crypto.load_config()
    key = crypto.verify_master_password(req.master_password, cfg)
    if not key:
        fails = netutil.record_fail(ip)
        audit("auth:fail", ip=ip, ua=request.headers.get("user-agent", ""),
              meta={"attempts": fails})
        siem.security_log("master", ip)
        if fails == cfgmod.SETTINGS.fail_limit_per_ip:
            audit("auth:lockdown", ip=ip, meta={"attempts": fails})
        logger.warning("auth fail from %s (attempts=%d)", ip, fails)
        raise HTTPException(401, "wrong master password")

    # 2FA проверка: если включена, требуем код
    totp_secret = _read_2fa_secret(key, cfg)
    if totp_secret:
        if not req.totp_code:
            raise HTTPException(401, "2FA is enabled: totp_code is required")
        if not pyotp.TOTP(totp_secret).verify(req.totp_code, valid_window=1):
            netutil.record_fail(ip)
            audit("auth:totp_fail", ip=ip)
            raise HTTPException(401, "wrong TOTP code")

    # v0.13: security key as a second factor on top of the password
    if cfg.webauthn_second_factor and _webauthn_registered():
        if not req.webauthn:
            raise HTTPException(401, "security key required: present a WebAuthn assertion", headers={"X-WebAuthn-Required": "1"})
        try:
            webauthn_auth.verify_assertion(req.webauthn, "second_factor")
        except Exception as e:
            netutil.record_fail(ip); audit("auth:webauthn_fail", ip=ip, meta={"stage": "second_factor"})
            raise HTTPException(401, f"security key assertion rejected: {e.__class__.__name__}")
    netutil.clear_fails(ip)
    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(key, csrf_token, ip=ip)
    import oidc as _oidc
    if _oidc.is_enabled():
        STATE.node_master_key = key      # lets SSO logins on this node mint sessions (state.py)
    audit("auth:unlock", ip=ip, ua=request.headers.get("user-agent", ""), meta={"node": NODE})
    resp = JSONResponse({**UnlockResponse(ok=True, session_ttl_sec=8 * 3600).model_dump(),
                         "csrf_token": csrf_token})
    resp.set_cookie(SESSION_COOKIE, sid, max_age=8 * 3600, httponly=True,
                    samesite="lax", secure=True, path="/")
    # CSRF cookie — НЕ httpOnly, чтобы JS мог прочитать и положить в header
    resp.set_cookie(CSRF_COOKIE, csrf_token, max_age=8 * 3600, httponly=False,
                    samesite="lax", secure=True, path="/")
    return resp


# ─── PKCS#11 / HSM master-key provider (v0.15) ───────────────────────────────
import hsm


def _hsm_rewrap(cfg, old_master_key: bytes, new_master_key: bytes, ip: str) -> None:
    """Password change / recovery: re-wrap the HSM cell when the server may use the token by
    itself (VAULT_PKCS11_PIN), otherwise drop it — the administrator re-enables with the PIN."""
    if not cfg.hsm_master_enc:
        return
    if hsm.configured() and cfgmod.SETTINGS.pkcs11_pin:
        try:
            cfg.hsm_master_enc, cfg.hsm_master_iv = hsm.wrap(new_master_key, cfgmod.SETTINGS.pkcs11_pin)
            return
        except hsm.HsmError as e:
            logger.warning("hsm re-wrap failed: %s", e)
    cfg.hsm_master_enc, cfg.hsm_master_iv, cfg.hsm_key_label = b"", b"", ""
    audit("auth:hsm_cell_dropped", ip=ip)


class HsmEnable(BaseModel):
    master_password: str
    pin: str = Field(min_length=1, max_length=256)


class HsmUnlock(BaseModel):
    pin: str | None = None       # None → VAULT_PKCS11_PIN (auto mode)


@app.get("/api/auth/hsm/status")
async def hsm_status():
    """Public: whether PIN unlock is offered."""
    cfg = crypto.load_config_or_none()
    out = {"configured": hsm.configured(), "enabled": bool(cfg and cfg.hsm_master_enc), "auto": bool(cfgmod.SETTINGS.pkcs11_pin),
           "token_label": cfgmod.SETTINGS.pkcs11_token_label if hsm.configured() else None, "key_label": (cfg.hsm_key_label if cfg and cfg.hsm_key_label else None)}
    if hsm.configured():
        try:
            out["token"] = hsm.info()
        except Exception as e:                     # never 500 on a status probe: the login screen calls it
            out["token_error"] = str(e)[:160]
    return out


@app.post("/api/auth/hsm/enable")
async def hsm_enable(req: HsmEnable, request: Request, _: str = Depends(require_unlocked)):
    """Wrap the master key inside the token (creates the AES key on first use). Needs the master
    password — a stolen session must not be able to bind the vault to an attacker's token."""
    if not hsm.configured():
        raise HTTPException(409, "VAULT_PKCS11_MODULE is not set on this replica")
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    key = crypto.verify_master_password(req.master_password, cfg)
    if not key:
        netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "hsm-enable"})
        raise HTTPException(401, "wrong master password")
    try:
        enc, iv = hsm.wrap(key, req.pin)
    except hsm.HsmError as e:
        netutil.record_fail(ip); audit("auth:hsm_fail", ip=ip, meta={"stage": "enable", "error": str(e)[:80]})
        raise HTTPException(400, f"token refused: {e}")
    cfg.hsm_master_enc, cfg.hsm_master_iv, cfg.hsm_key_label = enc, iv, cfgmod.SETTINGS.pkcs11_key_label
    crypto.save_config(cfg)
    netutil.clear_fails(ip)
    audit("auth:hsm_enabled", ip=ip, meta={"token": cfgmod.SETTINGS.pkcs11_token_label, "key": cfgmod.SETTINGS.pkcs11_key_label})
    return {"ok": True, "enabled": True, "key_label": cfg.hsm_key_label}


@app.post("/api/auth/hsm/disable")
async def hsm_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.hsm_master_enc, cfg.hsm_master_iv, cfg.hsm_key_label = b"", b"", ""
    crypto.save_config(cfg)
    audit("auth:hsm_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@app.post("/api/auth/hsm/unlock")
async def hsm_unlock(req: HsmUnlock, request: Request):
    """Unlock with the token's PIN: the token decrypts the cell, the master key opens a session.
    The PIN is used for one PKCS#11 session and not kept."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)
    cfg = crypto.load_config_or_none()
    if not cfg or not cfg.hsm_master_enc:
        raise HTTPException(409, "HSM unlock is not enabled")
    pin = req.pin if req.pin is not None else cfgmod.SETTINGS.pkcs11_pin
    if not pin:
        raise HTTPException(400, "PIN required")
    try:
        key = hsm.unwrap(cfg.hsm_master_enc, cfg.hsm_master_iv, pin)
    except hsm.HsmError as e:
        fails = netutil.record_fail(ip)
        audit("auth:hsm_fail", ip=ip, meta={"stage": "unlock", "attempts": fails, "error": str(e)[:80]})
        siem.security_log("hsm", ip)
        raise HTTPException(401, f"token refused: {e}")
    if not crypto.verify_master_key(key, cfg):
        netutil.record_fail(ip); audit("auth:hsm_fail", ip=ip, meta={"stage": "unlock", "error": "verifier"})
        raise HTTPException(401, "cell opened but does not match this vault (re-enable HSM unlock)")
    netutil.clear_fails(ip)
    return _issue_session_response(key, ip, request, how="hsm")


# ─── Cloud KMS master-key provider (v0.16) ───────────────────────────────────
import kms


def _kms_rewrap(cfg, new_master_key: bytes, ip: str) -> None:
    """Password change / recovery: a cell without a PIN context is re-encrypted by the server;
    a PIN-bound one cannot be (the PIN is not at hand) and is dropped."""
    if not cfg.kms_master_enc:
        return
    if kms.configured() and not cfg.kms_pin_bound:
        try:
            cfg.kms_master_enc = kms.encrypt(new_master_key, None); return
        except kms.KmsError as e:
            logger.warning("kms re-wrap failed: %s", e)
    cfg.kms_master_enc, cfg.kms_provider, cfg.kms_key_id, cfg.kms_pin_bound = b"", "", "", False
    audit("auth:kms_cell_dropped", ip=ip)


class KmsEnable(BaseModel):
    master_password: str
    pin: str | None = Field(default=None, max_length=256)     # optional: binds decryption to the PIN (encryption context)


class KmsUnlock(BaseModel):
    pin: str | None = None


@app.get("/api/auth/kms/status")
async def kms_status():
    cfg = crypto.load_config_or_none()
    out = {"configured": kms.configured(), "enabled": bool(cfg and cfg.kms_master_enc), "pin_bound": bool(cfg and cfg.kms_pin_bound),
           "provider": cfg.kms_provider if cfg and cfg.kms_provider else (cfgmod.SETTINGS.kms_provider or None), "key_id": cfg.kms_key_id if cfg and cfg.kms_key_id else None}
    if kms.configured():
        out["kms"] = kms.info()
    return out


@app.post("/api/auth/kms/enable")
async def kms_enable(req: KmsEnable, request: Request, _: str = Depends(require_unlocked)):
    """Encrypt the master key with the KMS key. With a PIN the KMS refuses to decrypt without
    the PIN-derived context — the cloud identity alone is not enough; without a PIN the server
    can open the cell itself (auto mode: SSO hand-over, re-wrap)."""
    if not kms.configured():
        raise HTTPException(409, "VAULT_KMS_PROVIDER / VAULT_KMS_KEY_ID are not set on this replica")
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    key = crypto.verify_master_password(req.master_password, cfg)
    if not key:
        netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "kms-enable"})
        raise HTTPException(401, "wrong master password")
    if req.pin is not None and len(req.pin) < 4:
        raise HTTPException(400, "PIN must be at least 4 characters")
    try:
        cfg.kms_master_enc = kms.encrypt(key, req.pin or None)
    except kms.KmsError as e:
        audit("auth:kms_fail", ip=ip, meta={"stage": "enable", "error": str(e)[:120]})
        raise HTTPException(502, f"KMS refused: {e}")
    cfg.kms_provider, cfg.kms_key_id, cfg.kms_pin_bound = cfgmod.SETTINGS.kms_provider, cfgmod.SETTINGS.kms_key_id, bool(req.pin)
    crypto.save_config(cfg)
    audit("auth:kms_enabled", ip=ip, meta={"provider": cfg.kms_provider, "key_id": cfg.kms_key_id, "pin_bound": cfg.kms_pin_bound})
    return {"ok": True, "enabled": True, "pin_bound": cfg.kms_pin_bound}


@app.post("/api/auth/kms/disable")
async def kms_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.kms_master_enc, cfg.kms_provider, cfg.kms_key_id, cfg.kms_pin_bound = b"", "", "", False
    crypto.save_config(cfg)
    audit("auth:kms_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@app.post("/api/auth/kms/unlock")
async def kms_unlock(req: KmsUnlock, request: Request):
    """Open a session through the KMS: PIN-bound cells need the PIN; others open for anyone who
    reaches this endpoint — so a cell without a PIN is for auto mode (SSO) and is refused here
    unless the UI policy and a PIN say otherwise."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)
    cfg = crypto.load_config_or_none()
    if not cfg or not cfg.kms_master_enc:
        raise HTTPException(409, "KMS unlock is not enabled")
    if not cfg.kms_pin_bound:
        raise HTTPException(403, "this KMS cell has no PIN: it serves SSO logins and re-wrap, not direct unlock")
    if not req.pin:
        raise HTTPException(400, "PIN required")
    try:
        key = kms.decrypt(cfg.kms_master_enc, req.pin)
    except kms.KmsError as e:
        fails = netutil.record_fail(ip)
        audit("auth:kms_fail", ip=ip, meta={"stage": "unlock", "attempts": fails, "error": str(e)[:120]})
        siem.security_log("kms", ip)
        raise HTTPException(401, "KMS refused the PIN context")
    if not crypto.verify_master_key(key, cfg):
        netutil.record_fail(ip); audit("auth:kms_fail", ip=ip, meta={"stage": "unlock", "error": "verifier"})
        raise HTTPException(401, "cell opened but does not match this vault (re-enable KMS)")
    netutil.clear_fails(ip)
    return _issue_session_response(key, ip, request, how="kms")


# ─── WebAuthn: security keys / Touch ID (v0.13) ──────────────────────────────
import webauthn_auth


def _webauthn_registered() -> bool:
    with db.get_session() as s:
        return s.query(db.WebauthnCredential).count() > 0


def _issue_session_response(key: bytes, ip: str, request: Request, how: str) -> JSONResponse:
    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(key, csrf_token, ip=ip)
    import oidc as _oidc
    if _oidc.is_enabled():
        STATE.node_master_key = key
    audit("auth:unlock", ip=ip, ua=request.headers.get("user-agent", ""), meta={"node": NODE, "how": how})
    resp = JSONResponse({**UnlockResponse(ok=True, session_ttl_sec=8 * 3600).model_dump(), "csrf_token": csrf_token})
    resp.set_cookie(SESSION_COOKIE, sid, max_age=8 * 3600, httponly=True, samesite="lax", secure=True, path="/")
    resp.set_cookie(CSRF_COOKIE, csrf_token, max_age=8 * 3600, httponly=False, samesite="lax", secure=True, path="/")
    return resp


class WebauthnRegisterOptions(BaseModel):
    name: str = Field(default="security key", max_length=64)


class WebauthnRegisterFinish(BaseModel):
    name: str = Field(default="security key", max_length=64)
    credential: dict
    prf_output: str | None = None        # base64url of the PRF extension output, when the authenticator gave one
    transports: list[str] = []
    master_password: str                 # adding a key that can open the vault needs the password, not just a session


class WebauthnAssertion(BaseModel):
    credential: dict
    prf_output: str | None = None


@app.get("/api/auth/webauthn/status")
async def webauthn_status():
    """Public: what the login screen may offer."""
    try:
        cfg = crypto.load_config_or_none()
    except Exception:
        cfg = None
    with db.get_session() as s:
        creds = s.query(db.WebauthnCredential).all()
    rp_id, _ = webauthn_auth.rp()
    return {"rp_id": rp_id, "credentials": len(creds), "prf_unlock": any(c.prf_master_enc for c in creds),
            "second_factor": bool(cfg and cfg.webauthn_second_factor and creds)}


@app.get("/api/auth/webauthn/credentials")
async def webauthn_list(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"credentials": webauthn_auth.list_credentials(), "second_factor": bool(cfg.webauthn_second_factor), "rp_id": webauthn_auth.rp()[0]}


@app.post("/api/auth/webauthn/register/options")
async def webauthn_register_options(req: WebauthnRegisterOptions, _: str = Depends(require_unlocked)):
    return webauthn_auth.registration_options(req.name)


@app.post("/api/auth/webauthn/register/finish")
async def webauthn_register_finish(req: WebauthnRegisterFinish, request: Request, _: str = Depends(require_unlocked)):
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    key = crypto.verify_master_password(req.master_password, cfg)
    if not key:
        netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "webauthn-register"})
        raise HTTPException(401, "wrong master password")
    try:
        out = webauthn_auth.registration_finish(req.credential, req.name, key, req.prf_output, req.transports)
    except Exception as e:
        raise HTTPException(400, f"registration rejected: {e}")
    audit("auth:webauthn_registered", ip=ip, meta={"name": out["name"], "prf": out["prf"]})
    return out


@app.delete("/api/auth/webauthn/credentials/{cid}")
async def webauthn_delete(cid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        c = s.get(db.WebauthnCredential, cid)
        if not c:
            raise HTTPException(404, "not found")
        name = c.name; s.delete(c); s.commit()
    if not _webauthn_registered():
        cfg = crypto.load_config()
        if cfg.webauthn_second_factor:
            cfg.webauthn_second_factor = False; crypto.save_config(cfg)   # never lock the admin out
    audit("auth:webauthn_removed", ip=_client_ip(request), meta={"name": name})
    return {"ok": True}


class WebauthnSecondFactor(BaseModel):
    enabled: bool


@app.post("/api/auth/webauthn/second-factor")
async def webauthn_second_factor(req: WebauthnSecondFactor, request: Request, _: str = Depends(require_unlocked)):
    if req.enabled and not _webauthn_registered():
        raise HTTPException(409, "register a security key first")
    cfg = crypto.load_config(); cfg.webauthn_second_factor = req.enabled; crypto.save_config(cfg)
    audit("auth:webauthn_second_factor", ip=_client_ip(request), meta={"enabled": req.enabled})
    return {"ok": True, "second_factor": req.enabled}


@app.post("/api/auth/webauthn/options")
async def webauthn_options(purpose: str = Query(default="unlock", pattern="^(unlock|second_factor)$")):
    """Public: a challenge for touch-to-unlock (PRF credentials) or for the second factor."""
    if not crypto.config_exists():
        raise HTTPException(412, "vault is not initialised")
    try:
        return webauthn_auth.authentication_options(purpose)
    except LookupError as e:
        raise HTTPException(404, str(e))


@app.post("/api/auth/webauthn/unlock")
async def webauthn_unlock(req: WebauthnAssertion, request: Request):
    """Touch-to-unlock: valid assertion + PRF output → master key → session. No password."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)
    try:
        cred = webauthn_auth.verify_assertion(req.credential, "unlock")
        key = webauthn_auth.unlock_master_key(cred, req.prf_output or "")
    except Exception as e:
        fails = netutil.record_fail(ip)
        audit("auth:webauthn_fail", ip=ip, meta={"stage": "unlock", "attempts": fails, "error": e.__class__.__name__})
        siem.security_log("webauthn", ip)
        raise HTTPException(401, f"security key rejected: {e.__class__.__name__}")
    netutil.clear_fails(ip)
    return _issue_session_response(key, ip, request, how=f"webauthn:{cred.name}")


# ─── 2FA helpers ──────────────────────────────────────────────────────────────
# TOTP-seed хранится в config.json в поле totp_secret_enc/totp_secret_nonce
# (шифр AES-GCM под master-key). Если поле есть — 2FA активирована.
def _read_2fa_secret(master_key: bytes, cfg) -> str | None:
    raw = getattr(cfg, "totp_secret_enc", None)
    nonce = getattr(cfg, "totp_secret_nonce", None)
    if not raw or not nonce:
        return None
    try:
        return crypto.decrypt(master_key, raw, nonce).decode("utf-8")
    except Exception:
        return None


def sso_unlock_source() -> str:
    """Where this replica would take the master key for an SSO login: node | cell | env | none."""
    import oidc as _oidc
    if STATE.node_master_key is not None:
        return "node"
    if cfgmod.SETTINGS.sso_unlock_key:
        cfg = crypto.load_config_or_none()
        if cfg and cfg.sso_master_enc:
            return "cell"
    if hsm.configured() and cfgmod.SETTINGS.pkcs11_pin:
        cfg = crypto.load_config_or_none()
        if cfg and cfg.hsm_master_enc:
            return "hsm"
    if kms.configured():
        cfg = crypto.load_config_or_none()
        if cfg and cfg.kms_master_enc and not cfg.kms_pin_bound:
            return "kms"
    if _oidc.auto_unlock_master_or_none():
        return "env"
    return "none"


@app.get("/api/auth/oidc/status")
async def oidc_status():
    """Включён ли OIDC — фронт показывает кнопку только тогда; и откуда эта реплика возьмёт мастер-ключ."""
    import oidc as _oidc
    return {"enabled": _oidc.is_enabled(), "sso_unlock": sso_unlock_source()}


class SsoUnlockEnable(BaseModel):
    master_password: str


@app.get("/api/auth/sso-unlock/status")
async def sso_unlock_status(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"available": bool(cfgmod.SETTINGS.sso_unlock_key), "enabled": bool(cfg.sso_master_enc), "source": sso_unlock_source()}


@app.post("/api/auth/sso-unlock/enable")
async def sso_unlock_enable(req: SsoUnlockEnable, request: Request, _: str = Depends(require_unlocked)):
    """Store the master key wrapped under HKDF(VAULT_SSO_UNLOCK_KEY) so an OIDC login on any
    replica can open a session. Needs the master password again (a stolen session must not be
    enough to make the vault SSO-openable) and the server key on this replica."""
    if not cfgmod.SETTINGS.sso_unlock_key:
        raise HTTPException(409, "VAULT_SSO_UNLOCK_KEY is not set on this replica (≥32 random bytes, hex or base64, same on all replicas)")
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    key = crypto.verify_master_password(req.master_password, cfg)
    if not key:
        netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "sso-unlock"})
        raise HTTPException(401, "wrong master password")
    crypto.sso_cell_set(cfg, key, cfgmod.SETTINGS.sso_unlock_key)
    crypto.save_config(cfg)
    audit("auth:sso_unlock_enabled", ip=ip)
    return {"ok": True, "enabled": True}


@app.post("/api/auth/sso-unlock/disable")
async def sso_unlock_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.sso_master_enc, cfg.sso_master_nonce = b"", b""
    crypto.save_config(cfg)
    STATE.lock()
    audit("auth:sso_unlock_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@app.get("/api/auth/oidc/login")
async def oidc_login():
    """Старт OIDC: ставит state+PKCE+nonce cookies, 302 на Keycloak."""
    import oidc as _oidc
    return _oidc.login_redirect()


@app.get("/api/auth/oidc/callback")
async def oidc_callback(request: Request):
    """OIDC callback: валидация → разлок (если master в env) → сессия → 302 /."""
    import oidc as _oidc
    user = _oidc.exchange_code(request)
    ip = _client_ip(request)
    _ui_policy_check(request)

    # Master key: OIDC proves identity, not the master password. This node's cache (filled by
    # a master unlock here) or VAULT_MASTER_PASSWORD (dev only — see oidc.py). In a cluster
    # either pin SSO users to one replica or set the env on all — docs/CLUSTER.md.
    key = STATE.node_master_key
    if key is None and cfgmod.SETTINGS.sso_unlock_key:
        # v0.10: the SSO unlock cell — master key wrapped under a server-side key the IdP does
        # not hold; works on every replica once enabled from Settings
        key = crypto.sso_cell_open(crypto.load_config(), cfgmod.SETTINGS.sso_unlock_key)
    if key is None and hsm.configured() and cfgmod.SETTINGS.pkcs11_pin:
        # v0.15: the token itself releases the master key for SSO logins (auto mode)
        cfg_h = crypto.load_config()
        if cfg_h.hsm_master_enc:
            try:
                key = hsm.unwrap(cfg_h.hsm_master_enc, cfg_h.hsm_master_iv, cfgmod.SETTINGS.pkcs11_pin)
            except hsm.HsmError as e:
                logger.warning("hsm auto-unlock for SSO failed: %s", e)
    if key is None and kms.configured():
        # v0.16: a KMS cell without a PIN context — the cloud identity of this replica releases the key
        cfg_k = crypto.load_config()
        if cfg_k.kms_master_enc and not cfg_k.kms_pin_bound:
            try:
                key = kms.decrypt(cfg_k.kms_master_enc, None)
            except kms.KmsError as e:
                logger.warning("kms auto-unlock for SSO failed: %s", e)
    if key is None:
        master = _oidc.auto_unlock_master_or_none()
        if not master:
            audit("oidc:no_master", ip=ip, ua=request.headers.get("user-agent", ""),
                  meta={"email": user["email"], "node": NODE})
            raise HTTPException(503, "vault is locked on this node: unlock with the master password first")
        if not crypto.config_exists():
            raise HTTPException(412, "vault is not initialised")
        cfg = crypto.load_config()
        key = crypto.verify_master_password(master, cfg)
        if not key:
            audit("oidc:bad_master_env", ip=ip)
            raise HTTPException(503, "VAULT_MASTER_PASSWORD is wrong")
        STATE.node_master_key = key

    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(key, csrf_token, oidc_user=user["email"], ip=ip)
    audit("oidc:login", ip=ip, ua=request.headers.get("user-agent", ""),
          meta={"email": user["email"], "name": user.get("name")})
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(SESSION_COOKIE, sid, max_age=8 * 3600, httponly=True,
                    samesite="lax", secure=True, path="/")
    resp.set_cookie(CSRF_COOKIE, csrf_token, max_age=8 * 3600, httponly=False,
                    samesite="lax", secure=True, path="/")
    _oidc.clear_oidc_cookies(resp)
    return resp


@app.post("/api/auth/lock")
async def lock(request: Request, sid: str = Depends(require_unlocked), all: bool = Query(default=False)):
    """Drop this session everywhere (the row is shared). `?all=1` drops every session —
    the "lock the vault" of the single-node days, now cluster-wide."""
    if all:
        n = sessions.revoke_all()
        STATE.lock()
        audit("auth:lock_all", ip=_client_ip(request), meta={"sessions": n})
    else:
        sessions.revoke(sid)
        if sessions.active_count() == 0:
            STATE.lock()
        audit("auth:lock", ip=_client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    resp.delete_cookie(CSRF_COOKIE)
    return resp


# ─── 2FA setup / disable ──────────────────────────────────────────────────────
class TwoFaSetupResponse(BaseModel):
    secret_base32: str
    otpauth_url: str
    qr_data_url: str   # data: URL с PNG (отрисует UI)
    enabled: bool = False  # реально включается через verify


class TwoFaVerifyRequest(BaseModel):
    code: str
    secret_base32: str   # тот что вернул setup; не сохраняется до verify


class TwoFaDisableRequest(BaseModel):
    totp_code: str


@app.get("/api/auth/2fa/status")
async def twofa_status(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"enabled": bool(cfg.totp_secret_enc)}


@app.post("/api/auth/2fa/setup", response_model=TwoFaSetupResponse)
async def twofa_setup(_: str = Depends(require_unlocked)):
    """Генерит новый TOTP-секрет (НЕ сохраняет — ждём подтверждение через verify).
    Возвращает otpauth-URL для QR + сам QR как data:image/png;base64,..."""
    cfg = crypto.load_config()
    if cfg.totp_secret_enc:
        raise HTTPException(409, "2FA is already enabled; disable it first")
    secret = pyotp.random_base32()
    issuer = "APS%20Vault"
    label = cfgmod.SETTINGS.public_host
    otpauth = f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}"
    # Генерим QR PNG base64
    import io
    try:
        import qrcode
        from qrcode.image.pure import PyPNGImage
        img = qrcode.make(otpauth, image_factory=PyPNGImage)
        buf = io.BytesIO()
        img.save(buf)
        import base64
        qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        # qrcode может быть не установлен — отдадим только текст
        qr_data_url = ""
    return TwoFaSetupResponse(
        secret_base32=secret, otpauth_url=otpauth, qr_data_url=qr_data_url, enabled=False,
    )


@app.post("/api/auth/2fa/verify")
async def twofa_verify(req: TwoFaVerifyRequest, request: Request, _: str = Depends(require_unlocked)):
    """Подтверждение TOTP кода и активация 2FA. Сохраняет секрет в config (шифрован под master-key)."""
    if not pyotp.TOTP(req.secret_base32).verify(req.code, valid_window=1):
        raise HTTPException(400, "wrong code — try again in 30 seconds")
    cfg = crypto.load_config()
    if cfg.totp_secret_enc:
        raise HTTPException(409, "2FA is already enabled")
    enc, nonce = crypto.encrypt(current_master_key(), req.secret_base32.encode("utf-8"))
    cfg.totp_secret_enc = enc
    cfg.totp_secret_nonce = nonce
    crypto.save_config(cfg)
    audit("auth:2fa_enabled", ip=_client_ip(request))
    return {"ok": True, "enabled": True}


@app.post("/api/auth/2fa/disable")
async def twofa_disable(req: TwoFaDisableRequest, request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    if not cfg.totp_secret_enc:
        raise HTTPException(409, "2FA is not enabled")
    secret = _read_2fa_secret(current_master_key(), cfg)
    if not secret or not pyotp.TOTP(secret).verify(req.totp_code, valid_window=1):
        raise HTTPException(401, "wrong TOTP code")
    cfg.totp_secret_enc = b""
    cfg.totp_secret_nonce = b""
    crypto.save_config(cfg)
    audit("auth:2fa_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


# ─── Recovery (потеря master-password) ────────────────────────────────────────
class RecoverRequest(BaseModel):
    recovery_code: str
    new_master_password: str = Field(min_length=12, max_length=256)


@app.post("/api/auth/recover")
async def recover(req: RecoverRequest, request: Request):
    """
    Сброс master-password через одноразовый recovery code (получен при init).

    Логика: recovery_code дешифрует сохранённую копию master_key. master_key
    остаётся ТЕМ ЖЕ — поэтому все scope-keys и зашифрованные значения остаются
    рабочими. Меняется только пароль которым master_key защищён.

    После успеха старый recovery_code инвалидируется, выдаётся новый
    (показать ОДИН РАЗ как при init).
    """
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    master_key = crypto.verify_recovery_code(req.recovery_code, cfg)
    if not master_key:
        netutil.record_fail(ip)
        audit("auth:recover_fail", ip=ip)
        siem.security_log("recovery", ip)
        raise HTTPException(401, "wrong recovery code")

    # rewrap: новый salt для пароля + новый recovery_code, но тот же master_key
    new_salt = pysecrets.token_bytes(32)
    # ВАЖНО: scope-keys в БД зашифрованы под СТАРЫЙ master_key. Поэтому новый
    # «пароль-производный ключ» должен дешифровать verifier — а сам scope-keys
    # остаются нетронуты потому что master_key = derive(password, salt) тот же.
    # Чтобы это работало: новый derive(new_password, new_salt) ДОЛЖЕН РАВНЯТЬСЯ
    # master_key. Это невозможно без brute-force. Поэтому используем другой
    # подход: храним master_key как ОТДЕЛЬНЫЙ объект, зашифрованный под
    # password-derived key. Сейчас архитектура другая — derive(pwd, salt) ЭТО
    # master_key напрямую. Для recovery меняем подход: после recover'а
    # master_key будет НОВЫМ (derive(new_password, new_salt)), и нам нужно
    # перешифровать ВСЕ scope-keys папок и recovery_master_enc под него.

    # Перешифровка scope-keys:
    new_master_key = crypto.derive_key(req.new_master_password, new_salt)
    with db.get_session() as s:
        for folder in s.query(db.Folder).all():
            old_scope = crypto.decrypt(master_key, folder.scope_key_enc, folder.scope_key_nonce)
            # The folder nonce is KEPT: service tokens derive their key with a salt taken from
            # it (sdk_api._validate_token), so a fresh nonce would silently kill every token of
            # every folder — which is exactly what happened before 0.6. Reusing a nonce under a
            # *different* key is safe for AES-GCM.
            folder.scope_key_enc, _ = crypto.encrypt(new_master_key, old_scope, nonce=folder.scope_key_nonce)
        s.commit()

    # Новый verifier и recovery cell
    verifier_enc, verifier_nonce = crypto.encrypt(new_master_key, crypto.VERIFIER_PLAINTEXT)
    new_recovery = pysecrets.token_hex(12).upper()
    ph = PasswordHasher()
    new_rec_hash = ph.hash(new_recovery)
    new_rec_salt = pysecrets.token_bytes(32)
    new_rec_key = crypto.derive_key(new_recovery, new_rec_salt)
    new_rec_master_enc, new_rec_master_nonce = crypto.encrypt(new_rec_key, new_master_key)

    # 2FA-секрет тоже перешифровать (был под старым master_key)
    new_totp_enc, new_totp_nonce = b"", b""
    if cfg.totp_secret_enc:
        totp = crypto.decrypt(master_key, cfg.totp_secret_enc, cfg.totp_secret_nonce)
        new_totp_enc, new_totp_nonce = crypto.encrypt(new_master_key, totp)

    cfg.salt = new_salt
    cfg.verifier_enc = verifier_enc
    cfg.verifier_nonce = verifier_nonce
    cfg.recovery_code_hash = new_rec_hash
    cfg.recovery_master_enc = new_rec_master_enc
    cfg.recovery_master_nonce = new_rec_master_nonce
    cfg.recovery_salt = new_rec_salt
    cfg.totp_secret_enc = new_totp_enc
    cfg.totp_secret_nonce = new_totp_nonce
    # v0.10: the SSO unlock cell wrapped the OLD master key — re-wrap, or drop it if this
    # replica has no server key (the administrator re-enables it from Settings)
    if cfg.sso_master_enc:
        if cfgmod.SETTINGS.sso_unlock_key:
            crypto.sso_cell_set(cfg, new_master_key, cfgmod.SETTINGS.sso_unlock_key)
        else:
            cfg.sso_master_enc, cfg.sso_master_nonce = b"", b""
    _hsm_rewrap(cfg, master_key, new_master_key, ip)
    _kms_rewrap(cfg, new_master_key, ip)
    crypto.save_config(cfg)
    webauthn_auth.rewrap_all(master_key, new_master_key)

    # Снимаем все активные сессии на всех репликах (старая авторизация недействительна)
    sessions.revoke_all()
    STATE.lock()
    netutil.clear_fails(ip)
    audit("auth:recover", ip=ip)
    return {
        "ok": True,
        "new_recovery_code": new_recovery,
        "note": "New recovery code — save it NOW. The old one is void. All sessions were dropped — unlock again.",
    }


# ─── Endpoints: folders ───────────────────────────────────────────────────────
@app.get("/api/folders")
async def list_folders(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.Folder).order_by(db.Folder.name).all()
        return [{"id": f.id, "name": f.name, "description": f.description,
                 "created_at": f.created_at.isoformat() if f.created_at else ""}
                for f in rows]


@app.post("/api/folders")
async def create_folder(req: FolderCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        exist = s.query(db.Folder).filter_by(name=req.name).first()
        if exist:
            raise HTTPException(409, "a folder with this name already exists")
        scope_key = pysecrets.token_bytes(32)
        scope_enc, scope_nonce = crypto.encrypt(current_master_key(), scope_key)
        f = db.Folder(name=req.name, description=req.description,
                      scope_key_enc=scope_enc, scope_key_nonce=scope_nonce)
        s.add(f)
        s.commit()
        s.refresh(f)
        audit("folder:create", target=req.name, ip=_client_ip(request))
        return {"id": f.id, "name": f.name, "description": f.description}


@app.delete("/api/folders/{fid}")
async def delete_folder(fid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        f = s.get(db.Folder, fid)
        if not f:
            raise HTTPException(404, "folder not found")
        n = s.query(db.Secret).filter_by(folder_id=fid).count()
        if n > 0:
            raise HTTPException(400, f"folder still has {n} secrets — delete them first")
        # Также удалим service-токены этого scope (отозвём)
        s.query(db.ServiceToken).filter_by(folder_id=fid).update({"revoked": True})
        s.delete(f)
        s.commit()
        audit("folder:delete", target=f.name, ip=_client_ip(request))
        return {"ok": True}


# ─── Endpoints: secrets ───────────────────────────────────────────────────────
def _secret_to_list_item(sec: db.Secret, folder_name: str) -> dict:
    return {
        "id": sec.id, "folder_id": sec.folder_id, "folder_name": folder_name,
        "name": sec.name, "tags": sec.tags or "", "url": sec.url or "",
        "is_favorite": bool(getattr(sec, "is_favorite", False)),
        "has_login": bool(getattr(sec, "login_enc", None)),
        "has_totp": bool(sec.totp_seed_enc),
        "has_notes": bool(sec.notes_enc),
        "created_at": sec.created_at.isoformat() if sec.created_at else "",
        "updated_at": sec.updated_at.isoformat() if sec.updated_at else "",
        "last_accessed": sec.last_accessed.isoformat() if sec.last_accessed else None,
        "access_count": sec.access_count or 0,
        "expires_at": sec.expires_at.isoformat() if sec.expires_at else None,
        "version": sec.version or 1,
        "machine_only": bool(getattr(sec, "machine_only", False)),
        "require_approval": bool(getattr(sec, "require_approval", False)),
    }


@app.get("/api/secrets")
async def list_secrets(
    folder_id: int | None = Query(default=None),
    q: str | None = Query(default=None),
    _: str = Depends(require_unlocked),
):
    with db.get_session() as s:
        query = s.query(db.Secret, db.Folder).join(db.Folder)
        if folder_id is not None:
            query = query.filter(db.Secret.folder_id == folder_id)
        if q:
            like = f"%{q}%"
            query = query.filter((db.Secret.name.ilike(like)) | (db.Secret.tags.ilike(like)) | (db.Secret.url.ilike(like)))
        rows = query.order_by(db.Folder.name, db.Secret.name).all()
        return [_secret_to_list_item(sec, f.name) for sec, f in rows]


@app.post("/api/secrets")
async def create_secret(req: SecretCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        f = s.get(db.Folder, req.folder_id)
        if not f:
            raise HTTPException(404, "folder not found")
        value = generate_value(req.generate) if req.generate else req.value
        if value == "":
            raise HTTPException(400, "value is empty (or pass generate, e.g. base64:32)")
        value_enc, value_nonce = _enc_with_folder(s, req.folder_id, value.encode("utf-8"))
        notes_enc, notes_nonce = (b"", b"")
        if req.notes:
            notes_enc, notes_nonce = _enc_with_folder(s, req.folder_id, req.notes.encode("utf-8"))
        login_enc, login_nonce = (b"", b"")
        if req.login:
            login_enc, login_nonce = _enc_with_folder(s, req.folder_id, req.login.encode("utf-8"))
        totp_enc, totp_nonce = (b"", b"")
        if req.totp_seed:
            totp_enc, totp_nonce = _enc_with_folder(s, req.folder_id, req.totp_seed.encode("utf-8"))
        sec = db.Secret(
            folder_id=req.folder_id, name=req.name,
            value_enc=value_enc, value_nonce=value_nonce,
            notes_enc=notes_enc, notes_nonce=notes_nonce,
            login_enc=login_enc, login_nonce=login_nonce,
            totp_seed_enc=totp_enc, totp_seed_nonce=totp_nonce,
            tags=req.tags, url=req.url, expires_at=_parse_expires(req.expires_at),
            machine_only=req.machine_only, require_approval=req.require_approval,
        )
        s.add(sec)
        s.commit()
        s.refresh(sec)
        audit("secret:create", target=f"{f.name}/{req.name}", ip=_client_ip(request),
              meta={"machine_only": True, "generated": req.generate} if req.machine_only or req.generate else None)
        _emit("secret:create", {"folder": f.name, "name": req.name, "id": sec.id})
        return {"id": sec.id, "machine_only": req.machine_only, "generated": bool(req.generate)}


@app.get("/api/secrets/{sid}")
async def get_secret(sid: int, request: Request, approval: int | None = Query(default=None), sid_cookie: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        f = s.get(db.Folder, sec.folder_id)
        if getattr(sec, "require_approval", False) and not getattr(sec, "machine_only", False):
            _approval_gate(s, sec, approval, sid_cookie)
        hidden = bool(getattr(sec, "machine_only", False))
        value = b"" if hidden else _dec_with_folder(s, sec.folder_id, sec.value_enc, sec.value_nonce)
        notes = _dec_with_folder(s, sec.folder_id, sec.notes_enc, sec.notes_nonce) if sec.notes_enc else b""
        login = _dec_with_folder(s, sec.folder_id, sec.login_enc, sec.login_nonce) if sec.login_enc else b""
        totp_code = None
        if sec.totp_seed_enc:
            seed = _dec_with_folder(s, sec.folder_id, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
            try:
                totp_code = pyotp.TOTP(seed.replace(" ", "")).now()
            except Exception:
                totp_code = None
        # Бамп статистики доступа — только когда значение действительно выдано
        if not hidden:
            sec.last_accessed = db.utcnow()
            sec.access_count = (sec.access_count or 0) + 1
            s.commit()
        audit("secret:view" if hidden else "secret:read", target=f"{f.name}/{sec.name}", ip=_client_ip(request))
        item = _secret_to_list_item(sec, f.name)
        item.update({
            "value": value.decode("utf-8"), "value_hidden": hidden,
            "login": login.decode("utf-8") if login else "",
            "notes": notes.decode("utf-8") if notes else "",
            "totp": totp_code,
        })
        return item


@app.patch("/api/secrets/{sid}")
async def update_secret(sid: int, req: SecretUpdate, request: Request,
                        _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        if req.name is not None:
            sec.name = req.name
        if req.value is not None:
            # history — the previous value is kept (encrypted under the same folder key), numbered
            archive_value(s, sec, "master")
            sec.value_enc, sec.value_nonce = _enc_with_folder(s, sec.folder_id, req.value.encode("utf-8"))
        if req.notes is not None:
            if req.notes:
                sec.notes_enc, sec.notes_nonce = _enc_with_folder(s, sec.folder_id, req.notes.encode("utf-8"))
            else:
                sec.notes_enc, sec.notes_nonce = b"", b""
        if req.login is not None:
            if req.login:
                sec.login_enc, sec.login_nonce = _enc_with_folder(s, sec.folder_id, req.login.encode("utf-8"))
            else:
                sec.login_enc, sec.login_nonce = b"", b""
        if req.totp_seed is not None:
            if req.totp_seed:
                sec.totp_seed_enc, sec.totp_seed_nonce = _enc_with_folder(
                    s, sec.folder_id, req.totp_seed.encode("utf-8"))
            else:
                sec.totp_seed_enc, sec.totp_seed_nonce = b"", b""
        if req.tags is not None:
            sec.tags = req.tags
        if req.url is not None:
            sec.url = req.url
        hide_action = None
        if req.require_approval is not None and req.require_approval != bool(getattr(sec, "require_approval", False)):
            sec.require_approval = req.require_approval
        if req.machine_only is not None and req.machine_only != bool(sec.machine_only):
            sec.machine_only = req.machine_only
            hide_action = "secret:hide" if req.machine_only else "secret:unhide"   # audited after commit (SQLite: one writer)
        if req.clear_expires:
            sec.expires_at = None
        elif req.expires_at is not None:
            sec.expires_at = _parse_expires(req.expires_at)
        moved_from = None
        if req.folder_id is not None and req.folder_id != sec.folder_id:
            # move: every encrypted field is re-wrapped under the target folder's key; the
            # history rows keep their own folder_id and stay readable
            if not s.get(db.Folder, req.folder_id):
                raise HTTPException(404, "target folder not found")
            moved_from = s.get(db.Folder, sec.folder_id).name
            for enc_attr, nonce_attr in (("value_enc", "value_nonce"), ("notes_enc", "notes_nonce"),
                                         ("login_enc", "login_nonce"), ("totp_seed_enc", "totp_seed_nonce")):
                ct = getattr(sec, enc_attr)
                if ct:
                    plain = _dec_with_folder(s, sec.folder_id, ct, getattr(sec, nonce_attr))
                    new_ct, new_nonce = _enc_with_folder(s, req.folder_id, plain)
                    setattr(sec, enc_attr, new_ct); setattr(sec, nonce_attr, new_nonce)
            # v0.8: history travels with the secret, so `?version=N` keeps working for the new folder's tokens
            for h in s.query(db.SecretHistory).filter_by(secret_id=sec.id).all():
                try:
                    plain = _dec_with_folder(s, h.folder_id, h.value_enc, h.value_nonce)
                except Exception:
                    continue
                h.value_enc, h.value_nonce = _enc_with_folder(s, req.folder_id, plain)
                h.folder_id = req.folder_id
            sec.folder_id = req.folder_id
        sec.updated_at = db.utcnow()
        s.commit()
        f = s.get(db.Folder, sec.folder_id)
        if hide_action:
            audit(hide_action, target=f"{f.name}/{sec.name}", ip=_client_ip(request))
        if moved_from:
            audit("secret:move", target=f"{moved_from}/{sec.name} → {f.name}/{sec.name}", ip=_client_ip(request))
        audit("secret:update", target=f"{f.name}/{sec.name}", ip=_client_ip(request))
        _emit("secret:update", {"folder": f.name, "name": sec.name, "id": sec.id})
        return {"ok": True}


@app.delete("/api/secrets/{sid}")
async def delete_secret(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        f = s.get(db.Folder, sec.folder_id)
        name = sec.name
        s.delete(sec)
        s.commit()
        audit("secret:delete", target=f"{f.name}/{name}", ip=_client_ip(request))
        _emit("secret:delete", {"folder": f.name, "name": name, "id": sid})
        return {"ok": True}


class RotateRequest(BaseModel):
    generate: str = "base64:32"

    @field_validator("generate")
    @classmethod
    def _gen(cls, v):
        generate_value(v); return v


@app.post("/api/secrets/{sid}/rotate")
async def rotate_secret(sid: int, req: RotateRequest, request: Request, _: str = Depends(require_unlocked)):
    """Replace the value with a fresh server-generated one; the old value becomes the previous
    version (readable by machines through `?version=N` while they re-wrap their data). The
    administrator never sees either value — made for machine-only key material."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        archive_value(s, sec, "master:rotate")
        sec.value_enc, sec.value_nonce = _enc_with_folder(s, sec.folder_id, generate_value(req.generate).encode("utf-8"))
        sec.updated_at = db.utcnow()
        s.commit()
        f = s.get(db.Folder, sec.folder_id)
        audit("secret:rotate", target=f"{f.name}/{sec.name}", ip=_client_ip(request), meta={"version": sec.version, "generate": req.generate})
        _emit("secret:update", {"folder": f.name, "name": sec.name, "id": sec.id, "rotated": True})
        return {"ok": True, "version": sec.version, "previous_version": sec.version - 1}


@app.get("/api/secrets/{sid}/totp")
async def secret_totp(sid: int, _: str = Depends(require_unlocked)):
    """Current TOTP code with its remaining lifetime — for the live countdown in the UI.
    Deliberately does not bump access_count or write a `secret:read` audit row: the read was
    audited when the secret was opened; refreshing the code every 30 s is not a new access."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        if not sec.totp_seed_enc:
            raise HTTPException(404, "secret has no TOTP seed")
        seed = _dec_with_folder(s, sec.folder_id, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
    try:
        t = pyotp.TOTP(seed.replace(" ", ""))
        now = time.time()
        import math
        return {"code": t.now(), "period": t.interval, "remaining": max(1, math.ceil(t.interval - (now % t.interval)))}
    except Exception:
        raise HTTPException(422, "TOTP seed is not valid base32")


@app.get("/api/tools/hibp/{prefix}")
async def hibp_range(prefix: str = FPath(min_length=5, max_length=5, pattern=r"^[0-9A-Fa-f]{5}$"),
                     _: str = Depends(require_unlocked)):
    """k-anonymity leak check (Have I Been Pwned range API). The browser hashes the password,
    sends the first 5 hex chars here, we forward them and return the suffix list; the browser
    looks up the rest locally. The password never leaves the browser, the prefix identifies
    one of 16^5 buckets. Disabled with VAULT_HIBP=0 → 404; upstream unreachable → 503."""
    if not cfgmod.SETTINGS.hibp_enabled:
        raise HTTPException(404, "leak check disabled (VAULT_HIBP=0)")
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix.upper()}",
                                 headers={"User-Agent": f"aps-vault/{VERSION}", "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception as e:
        raise HTTPException(503, f"leak database unreachable: {e.__class__.__name__}")
    return Response(body, media_type="text/plain")


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = None


@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordRequest, request: Request, sid: str = Depends(require_unlocked)):
    """Change the master password from a live session. Same rewrap as /auth/recover (folder
    keys re-wrapped under the new key, nonces kept so service tokens survive), a new recovery
    code is issued (the old cell wrapped the old key), every session is dropped cluster-wide."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    master_key = crypto.verify_master_password(req.current_password, cfg)
    if not master_key:
        netutil.record_fail(ip)
        audit("auth:password_change_fail", ip=ip)
        siem.security_log("master", ip, "scope=change-password")
        raise HTTPException(401, "current master password is wrong")
    totp_secret = _read_2fa_secret(master_key, cfg)
    if totp_secret and not (req.totp_code and pyotp.TOTP(totp_secret).verify(req.totp_code, valid_window=1)):
        netutil.record_fail(ip)
        raise HTTPException(401, "2FA is enabled: a valid totp_code is required")
    if req.new_password == req.current_password:
        raise HTTPException(400, "the new password must differ from the current one")
    new_salt = pysecrets.token_bytes(32)
    new_master_key = crypto.derive_key(req.new_password, new_salt)
    with db.get_session() as s:
        for folder in s.query(db.Folder).all():
            scope = crypto.decrypt(master_key, folder.scope_key_enc, folder.scope_key_nonce)
            folder.scope_key_enc, _ = crypto.encrypt(new_master_key, scope, nonce=folder.scope_key_nonce)
        s.commit()
    verifier_enc, verifier_nonce = crypto.encrypt(new_master_key, crypto.VERIFIER_PLAINTEXT)
    new_recovery = pysecrets.token_hex(12).upper()
    rec_salt = pysecrets.token_bytes(32)
    rec_key = crypto.derive_key(new_recovery, rec_salt)
    rec_enc, rec_nonce = crypto.encrypt(rec_key, new_master_key)
    totp_enc, totp_nonce = b"", b""
    if totp_secret:
        totp_enc, totp_nonce = crypto.encrypt(new_master_key, totp_secret.encode("utf-8"))
    cfg.salt = new_salt; cfg.verifier_enc = verifier_enc; cfg.verifier_nonce = verifier_nonce
    cfg.recovery_code_hash = PasswordHasher().hash(new_recovery)
    cfg.recovery_master_enc = rec_enc; cfg.recovery_master_nonce = rec_nonce; cfg.recovery_salt = rec_salt
    cfg.totp_secret_enc = totp_enc; cfg.totp_secret_nonce = totp_nonce
    if cfg.sso_master_enc:
        if cfgmod.SETTINGS.sso_unlock_key:
            crypto.sso_cell_set(cfg, new_master_key, cfgmod.SETTINGS.sso_unlock_key)
        else:
            cfg.sso_master_enc, cfg.sso_master_nonce = b"", b""
    _hsm_rewrap(cfg, master_key, new_master_key, ip)
    _kms_rewrap(cfg, new_master_key, ip)
    crypto.save_config(cfg)
    webauthn_auth.rewrap_all(master_key, new_master_key)   # PRF cells cannot follow: keys are re-registered
    n = sessions.revoke_all()
    STATE.lock()
    netutil.clear_fails(ip)
    audit("auth:password_change", ip=ip, meta={"sessions_dropped": n})
    resp = JSONResponse({"ok": True, "new_recovery_code": new_recovery,
                         "note": "All sessions were closed. Save the new recovery code — the old one is void."})
    resp.delete_cookie(SESSION_COOKIE); resp.delete_cookie(CSRF_COOKIE)
    return resp


# ─── Endpoints: service tokens (machine API M4) ───────────────────────────────
class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    folder_id: int
    expires_days: int | None = None
    can_read_notes: bool = False
    can_read_totp: bool = False
    can_write: bool = False
    # PAM-style policy (policy.py): "10.0.0.0/8 203.0.113.7", "Mon-Fri 08:00-20:00; Sat 10:00-14:00"
    allowed_cidrs: str = Field(default="", max_length=512)
    allowed_hours: str = Field(default="", max_length=256)
    # mTLS binding (0.11): hex fingerprints of client certificates (SHA-1 or SHA-256)
    allowed_cert_fingerprints: str = Field(default="", max_length=1024)
    # sealed delivery (0.17): raw X25519 public key (base64) — values leave encrypted to it, never in plaintext
    client_public_key: str = Field(default="", max_length=128)

    @field_validator("client_public_key")
    @classmethod
    def _cpk(cls, v: str) -> str:
        import sealed
        return sealed.normalize_public_key(v) if (v or "").strip() else ""

    @field_validator("allowed_cert_fingerprints")
    @classmethod
    def _fps(cls, v: str) -> str:
        return " ".join(policy.parse_fingerprints(v))

    @field_validator("allowed_cidrs")
    @classmethod
    def _cidrs(cls, v: str) -> str:
        policy.parse_cidrs(v)      # ValueError → 422 with the offending token
        return " ".join(v.replace(",", " ").split())

    @field_validator("allowed_hours")
    @classmethod
    def _hours(cls, v: str) -> str:
        policy.parse_hours(v)
        return v.strip()


@app.get("/api/tokens")
async def list_tokens(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.ServiceToken, db.Folder).join(db.Folder).order_by(db.ServiceToken.name).all()
        return [{
            "id": t.id, "name": t.name, "folder_id": t.folder_id, "folder_name": f.name,
            "can_read_notes": t.can_read_notes, "can_read_totp": t.can_read_totp,
            "can_write": bool(getattr(t, "can_write", False)),
            "allowed_cidrs": getattr(t, "allowed_cidrs", "") or "",
            "allowed_hours": getattr(t, "allowed_hours", "") or "",
            "allowed_cert_fingerprints": getattr(t, "allowed_cert_fingerprints", "") or "",
            "client_public_key": getattr(t, "client_public_key", "") or "",
            "sealed": bool(getattr(t, "client_public_key", "")),
            "created_at": t.created_at.isoformat() if t.created_at else "",
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
            "last_used": t.last_used.isoformat() if t.last_used else None,
            "revoked": t.revoked,
        } for t, f in rows]


@app.post("/api/tokens")
async def create_token(req: TokenCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        f = s.get(db.Folder, req.folder_id)
        if not f:
            raise HTTPException(404, "folder not found")
        raw = crypto.gen_service_token()
        # Шифруем folder_key под Argon2(raw_token).
        # Чтобы не KDF'ить каждый запрос — derive один раз, и сохраняем encrypted folder_key.
        # Trade-off: KDF при каждом запросе будет ~0.5с задержки. Поэтому ускоренный
        # KDF параметр: меньше итераций (Argon2id m=8MiB t=2 p=2) — sufficient для длинного
        # 32-байтного random token (96 бит энтропии уже).
        import suite as _suite
        token_key = _suite.token_kdf(raw.encode("utf-8"), f.scope_key_nonce[:16] + b"\x00" * (16 - min(16, len(f.scope_key_nonce))))
        folder_key = crypto.decrypt(current_master_key(), f.scope_key_enc, f.scope_key_nonce)
        fk_enc, fk_nonce = crypto.encrypt(token_key, folder_key)
        expires_at = None
        if req.expires_days:
            expires_at = db.utcnow() + timedelta(days=req.expires_days)
        t = db.ServiceToken(
            name=req.name, token_hash=hash_token(raw),
            folder_id=req.folder_id, folder_key_enc=fk_enc, folder_key_nonce=fk_nonce,
            can_read_notes=req.can_read_notes, can_read_totp=req.can_read_totp,
            can_write=req.can_write,
            allowed_cidrs=req.allowed_cidrs, allowed_hours=req.allowed_hours, allowed_cert_fingerprints=req.allowed_cert_fingerprints,
            client_public_key=req.client_public_key,
            expires_at=expires_at,
        )
        s.add(t)
        s.commit()
        s.refresh(t)
        audit("token:create", target=f"{f.name}:{req.name}", ip=_client_ip(request), meta={"sealed": True} if req.client_public_key else None)
        _emit("token:create", {"folder": f.name, "name": req.name, "id": t.id})
        return {
            "id": t.id, "name": t.name, "folder_name": f.name,
            "raw_token": raw, "sealed": bool(req.client_public_key),
            "note": "SAVE THIS TOKEN NOW — it is not shown again.",
        }


@app.delete("/api/tokens/{tid}")
async def revoke_token(tid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        t = s.get(db.ServiceToken, tid)
        if not t:
            raise HTTPException(404, "token not found")
        t.revoked = True
        s.commit()
        audit("token:revoke", target=t.name, ip=_client_ip(request))
        _emit("token:revoke", {"name": t.name, "id": t.id})
        return {"ok": True}


# ─── Endpoints: audit ─────────────────────────────────────────────────────────
@app.get("/api/audit")
async def get_audit(limit: int = Query(default=100, ge=1, le=1000),
                    _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.AuditLog).order_by(db.AuditLog.ts.desc()).limit(limit).all()
        return [{
            "id": r.id, "ts": r.ts.isoformat() if r.ts else "",
            "actor": r.actor, "action": r.action, "target": r.target,
            "ip": r.ip, "user_agent": r.user_agent,
            "meta": json.loads(r.meta) if r.meta else {},
        } for r in rows]


# ─── Endpoints: favorites (v0.3) ──────────────────────────────────────────────
@app.post("/api/secrets/{sid}/favorite")
async def toggle_favorite(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "not found")
        sec.is_favorite = not bool(getattr(sec, "is_favorite", False))
        s.commit()
        return {"id": sec.id, "is_favorite": sec.is_favorite}


# ─── Endpoints: secret history (v0.3) ────────────────────────────────────────
@app.get("/api/secrets/{sid}/history")
async def get_secret_history(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "not found")
        rows = s.query(db.SecretHistory).filter_by(secret_id=sid).order_by(db.SecretHistory.version.desc(), db.SecretHistory.changed_at.desc()).limit(50).all()
        result = []
        hidden = bool(getattr(sec, "machine_only", False)) or bool(getattr(sec, "require_approval", False))
        for r in rows:
            try:
                v = b"" if hidden else _dec_with_folder(s, r.folder_id, r.value_enc, r.value_nonce)
                result.append({
                    "id": r.id, "version": r.version, "hidden": hidden,
                    "value": v.decode("utf-8"),
                    "changed_at": r.changed_at.isoformat() if r.changed_at else "",
                    "changed_by": r.changed_by,
                })
            except Exception as e:
                result.append({"id": r.id, "version": r.version, "error": str(e)[:100]})
        f = s.get(db.Folder, sec.folder_id)
        audit("secret:history:read", target=f"{f.name}/{sec.name}", ip=_client_ip(request))
        return {"history": result, "count": len(result), "current_version": sec.version or 1, "hidden": hidden}


# ─── Approval workflow (v0.12) ───────────────────────────────────────────────
APPROVAL_REQUEST_TTL_MIN = 15
APPROVAL_TICKET_MIN = 10


def _approval_gate(s, sec, approval_id: int | None, sid: str) -> None:
    """A person reads an approval-required secret only with an approved, unexpired request of
    their own session. No approver configured → 409 (set one or clear the flag)."""
    cfg = crypto.load_config()
    if not cfg.approver_hash:
        raise HTTPException(409, "approval required but no approver is configured (Settings → Approvals)")
    hdr = {"X-Approval-Required": "1"}
    if approval_id is None:
        raise HTTPException(403, "approval required: a second person must approve this read", headers=hdr)
    a = s.get(db.Approval, approval_id)
    now = db.utcnow().replace(tzinfo=None)
    if not a or a.secret_id != sec.id or a.requester_sid_hash != hash_token(sid):
        raise HTTPException(403, "approval required: this approval does not belong to this session or secret", headers=hdr)
    if a.status != "approved" or not a.ticket_until or a.ticket_until < now:
        raise HTTPException(403, f"approval required: request is {a.status}" + (" (ticket expired)" if a.status == "approved" else ""), headers=hdr)


def _approval_item(a, sec_name: str) -> dict:
    now = db.utcnow().replace(tzinfo=None)
    status = a.status
    if status == "pending" and a.expires_at < now:
        status = "expired"
    return {"id": a.id, "secret_id": a.secret_id, "secret": sec_name, "status": status, "reason": a.reason or "",
            "requester_ip": a.requester_ip or "", "created_at": a.created_at.isoformat() if a.created_at else "",
            "expires_at": a.expires_at.isoformat() if a.expires_at else "", "decided_at": a.decided_at.isoformat() if a.decided_at else None,
            "ticket_until": a.ticket_until.isoformat() if a.ticket_until else None, "notified": bool(a.notified)}


def _notify_approver(text: str, url: str, secret: str, reason: str, requester_ip: str) -> bool:
    """Send the approver's link through the configured HTTP receiver. Returns True on 2xx."""
    st = cfgmod.SETTINGS
    if not st.approval_notify_url:
        return False
    if not (st.approval_notify_url.startswith("https://") or st.approval_notify_url.startswith("http://")) or not _webhook_target_allowed(st.approval_notify_url):
        logger.warning("approval notify: URL not allowed (private target without VAULT_WEBHOOK_ALLOW_PRIVATE?)")
        return False
    def q(v: str) -> str:   # placeholders are substituted as JSON-safe strings
        return json.dumps(v, ensure_ascii=False)[1:-1]
    body = st.approval_notify_body
    for k, v in (("text", text), ("url", url), ("secret", secret), ("reason", reason), ("requester_ip", requester_ip)):
        body = body.replace("{" + k + "}", q(v))
    headers = {"Content-Type": "application/json", **st.approval_notify_headers}
    try:
        req = urllib.request.Request(st.approval_notify_url, data=body.encode("utf-8"), method=st.approval_notify_method, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            return 200 <= r.status < 300
    except Exception as e:
        logger.warning("approval notify failed: %s", e.__class__.__name__)
        return False


class ApproverSet(BaseModel):
    master_password: str
    approver_password: str = Field(min_length=12, max_length=256)


class ApprovalRequest(BaseModel):
    reason: str = Field(default="", max_length=512)


class ApprovalDecision(BaseModel):
    approver_password: str
    decision: str = Field(pattern="^(approve|deny)$")


@app.get("/api/approvals/settings")
async def approvals_settings(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"approver_set": bool(cfg.approver_hash), "notify_configured": bool(cfgmod.SETTINGS.approval_notify_url),
            "request_ttl_min": APPROVAL_REQUEST_TTL_MIN, "ticket_min": APPROVAL_TICKET_MIN}


@app.post("/api/approvals/approver")
async def approvals_set_approver(req: ApproverSet, request: Request, _: str = Depends(require_unlocked)):
    """Set (or replace) the approver's password. Needs the master password: a stolen session
    must not be able to appoint its own approver. The approver password must differ from it."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    if not crypto.verify_master_password(req.master_password, cfg):
        netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "approver-set"})
        raise HTTPException(401, "wrong master password")
    if req.approver_password == req.master_password:
        raise HTTPException(400, "the approver password must differ from the master password")
    cfg.approver_hash = PasswordHasher().hash(req.approver_password)
    crypto.save_config(cfg)
    audit("approval:approver_set", ip=ip)
    return {"ok": True, "approver_set": True}


@app.delete("/api/approvals/approver")
async def approvals_clear_approver(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.approver_hash = ""
    crypto.save_config(cfg)
    audit("approval:approver_cleared", ip=_client_ip(request))
    return {"ok": True, "approver_set": False}


@app.get("/api/approvals")
async def approvals_list(limit: int = Query(default=50, le=200), _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.Approval, db.Secret, db.Folder).join(db.Secret, db.Approval.secret_id == db.Secret.id).join(db.Folder, db.Secret.folder_id == db.Folder.id)\
            .order_by(db.Approval.created_at.desc()).limit(limit).all()
        return [_approval_item(a, f"{f.name}/{sec.name}") for a, sec, f in rows]


@app.post("/api/secrets/{sid}/approvals")
async def approval_request(sid: int, req: ApprovalRequest, request: Request, session_id: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    if not cfg.approver_hash:
        raise HTTPException(409, "no approver is configured (Settings → Approvals)")
    ip = _client_ip(request)
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        f = s.get(db.Folder, sec.folder_id)
        raw = pysecrets.token_urlsafe(24)
        a = db.Approval(secret_id=sec.id, requester_sid_hash=hash_token(session_id), token_hash=hash_token(raw), status="pending",
                        reason=req.reason.strip(), requester_ip=ip[:64],
                        expires_at=db.utcnow().replace(tzinfo=None) + timedelta(minutes=APPROVAL_REQUEST_TTL_MIN))
        s.add(a); s.commit(); s.refresh(a)
        base = cfgmod.SETTINGS.public_url or f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"
        url = f"{base}/approve/{raw}"
        secret_label = f"{f.name}/{sec.name}"
        text = (f"APS Vault: approval requested to read «{secret_label}» from {ip}"
                + (f" — reason: {req.reason.strip()}" if req.reason.strip() else "")
                + f". Approve or deny within {APPROVAL_REQUEST_TTL_MIN} min: {url}")
        notified = _notify_approver(text, url, secret_label, req.reason.strip(), ip)
        a.notified = notified; s.commit()
        audit("approval:requested", target=secret_label, ip=ip, meta={"approval": a.id, "notified": notified, "reason": req.reason.strip()[:120] or None})
        _emit("approval:requested", {"folder": f.name, "name": sec.name, "id": sec.id, "approval": a.id})
        item = _approval_item(a, secret_label); item["approve_url"] = url
        return item


@app.get("/api/approvals/{aid}")
async def approval_status(aid: int, session_id: str = Depends(require_unlocked)):
    with db.get_session() as s:
        a = s.get(db.Approval, aid)
        if not a or a.requester_sid_hash != hash_token(session_id):
            raise HTTPException(404, "approval not found")
        sec = s.get(db.Secret, a.secret_id); f = s.get(db.Folder, sec.folder_id) if sec else None
        return _approval_item(a, f"{f.name}/{sec.name}" if sec and f else "?")


@app.get("/api/approve/{token}")
async def approve_info(token: str):
    """Public (the approver has no session): what is being asked, nothing about the value."""
    with db.get_session() as s:
        a = s.query(db.Approval).filter_by(token_hash=hash_token(token)).first()
        if not a:
            raise HTTPException(404, "approval link not found")
        sec = s.get(db.Secret, a.secret_id); f = s.get(db.Folder, sec.folder_id) if sec else None
        item = _approval_item(a, f"{f.name}/{sec.name}" if sec and f else "(deleted)")
        return {k: item[k] for k in ("secret", "status", "reason", "requester_ip", "created_at", "expires_at", "decided_at")}


@app.post("/api/approve/{token}")
async def approve_decide(token: str, req: ApprovalDecision, request: Request):
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    cfg = crypto.load_config()
    if not cfg.approver_hash:
        raise HTTPException(409, "no approver is configured")
    try:
        PasswordHasher().verify(cfg.approver_hash, req.approver_password)
    except VerifyMismatchError:
        fails = netutil.record_fail(ip)
        audit("approval:auth_fail", ip=ip, actor="approver", meta={"attempts": fails})
        siem.security_log("approver", ip)
        raise HTTPException(401, "wrong approver password")
    with db.get_session() as s:
        a = s.query(db.Approval).filter_by(token_hash=hash_token(token)).first()
        if not a:
            raise HTTPException(404, "approval link not found")
        now = db.utcnow().replace(tzinfo=None)
        if a.status != "pending":
            raise HTTPException(409, f"already {a.status}")
        if a.expires_at < now:
            a.status = "expired"; s.commit()
            raise HTTPException(410, "the request has expired")
        a.status = "approved" if req.decision == "approve" else "denied"
        a.decided_at = now; a.decided_ip = ip[:64]
        if a.status == "approved":
            a.ticket_until = now + timedelta(minutes=APPROVAL_TICKET_MIN)
        s.commit()
        sec = s.get(db.Secret, a.secret_id); f = s.get(db.Folder, sec.folder_id) if sec else None
        label = f"{f.name}/{sec.name}" if sec and f else "?"
        netutil.clear_fails(ip)
        audit(f"approval:{a.status}", target=label, ip=ip, actor="approver", meta={"approval": a.id, "requester_ip": a.requester_ip})
        _emit(f"approval:{a.status}", {"folder": f.name if f else "", "name": sec.name if sec else "", "approval": a.id})
        return {"ok": True, "status": a.status, "secret": label}


# ─── Endpoints: one-time sharing (v0.3) ──────────────────────────────────────
def _share_key(raw_token: str) -> bytes:
    """Link token → wrap key: salt = hash(token)[:16] (deterministic, nothing to store), then the suite's token KDF."""
    import suite as _suite
    return _suite.token_kdf(raw_token.encode("utf-8"), _suite.digest(raw_token.encode("utf-8"))[:16])


class NoteShareCreate(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    title: str = Field(default="", max_length=128)
    ttl_minutes: int = Field(default=60, ge=1, le=10080)
    max_uses: int = Field(default=1, ge=1, le=100)
    note: str = Field(default="", max_length=256)


@app.post("/api/share/note")
async def create_note_share(req: NoteShareCreate, request: Request, _: str = Depends(require_unlocked)):
    """v0.14: share a piece of text that is not a stored secret. Same link model as secrets
    (TTL, max uses, person/machine URL), the text is encrypted under the link token and is never
    stored anywhere else."""
    raw_token = pysecrets.token_urlsafe(24)
    enc, nonce = crypto.encrypt(_share_key(raw_token), req.text.encode("utf-8"))
    with db.get_session() as s:
        n = db.NoteShare(token_hash=hash_token(raw_token), title=req.title.strip(), payload_enc=enc, payload_nonce=nonce,
                         expires_at=db.utcnow().replace(tzinfo=None) + timedelta(minutes=req.ttl_minutes), max_uses=req.max_uses, note=req.note)
        s.add(n); s.commit(); s.refresh(n)
        audit("share:create", target=f"note:{n.title or n.id}", ip=_client_ip(request), meta={"kind": "note", "ttl_min": req.ttl_minutes, "max_uses": req.max_uses})
        return {"id": n.id, "kind": "note", "url": f"/share/{raw_token}", "expires_at": n.expires_at.isoformat(), "max_uses": n.max_uses}


def _open_note_share(token: str, request: Request):
    th = hash_token(token)
    with db.get_session() as s:
        n = s.query(db.NoteShare).filter_by(token_hash=th).first()
        if not n:
            return None
        if n.revoked:
            raise HTTPException(404, "share link not found or revoked")
        now = db.utcnow().replace(tzinfo=None)
        if n.expires_at < now:
            raise HTTPException(410, "share link has expired")
        if n.used_count >= n.max_uses:
            raise HTTPException(410, "share link has no uses left")
        try:
            text = crypto.decrypt(_share_key(token), n.payload_enc, n.payload_nonce).decode("utf-8")
        except Exception:
            raise HTTPException(500, "cannot decrypt (corrupted share link)")
        from sqlalchemy import text as _text
        consumed = s.execute(_text("UPDATE note_shares SET used_count = used_count + 1 WHERE id = :id AND used_count < max_uses AND NOT revoked"), {"id": n.id}).rowcount
        s.commit()
        if consumed != 1:
            raise HTTPException(410, "share link has no uses left")
        s.refresh(n)
        audit("share:read", target=f"note:{n.title or n.id}", actor="unauth", ip=_client_ip(request))
        return {"kind": "note", "name": n.title or "note", "value": text, "login": "", "uses_left": n.max_uses - n.used_count,
                "expires_at": n.expires_at.isoformat(), "note": n.note}

class ShareCreate(BaseModel):
    secret_id: int
    ttl_minutes: int = Field(default=60, ge=1, le=10080)   # max 7 days
    max_uses: int = Field(default=1, ge=1, le=100)
    note: str = ""


@app.post("/api/share")
async def create_share(req: ShareCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, req.secret_id)
        if not sec:
            raise HTTPException(404, "secret not found")
        if getattr(sec, "machine_only", False):
            raise HTTPException(403, "machine-only secrets cannot be shared with people")
        if getattr(sec, "require_approval", False):
            raise HTTPException(403, "approval-required secrets cannot be shared")
        folder_key = _get_or_create_folder_key(s, sec.folder_id)
        # Генерим публичный токен (URL-safe). Сохраняем sha256.
        raw_token = pysecrets.token_urlsafe(24)
        # deterministic salt = hash(raw_token)[:16] — nothing to store, the opener derives the same (24 random bytes = 192 bits)
        share_key = _share_key(raw_token)
        fk_enc, fk_nonce = crypto.encrypt(share_key, folder_key)
        link = db.ShareLink(
            token_hash=hash_token(raw_token),
            secret_id=req.secret_id, folder_id=sec.folder_id,
            folder_key_enc=fk_enc, folder_key_nonce=fk_nonce,
            expires_at=db.utcnow() + timedelta(minutes=req.ttl_minutes),
            max_uses=req.max_uses, note=req.note[:256],
        )
        s.add(link); s.commit(); s.refresh(link)
        f = s.get(db.Folder, sec.folder_id)
        audit("share:create", target=f"{f.name}/{sec.name}",
              ip=_client_ip(request),
              meta={"ttl_min": req.ttl_minutes, "max_uses": req.max_uses})
        # Возвращаем raw_token — повторно не показывается
        return {
            "id": link.id,
            "url": f"/share/{raw_token}",
            "expires_at": link.expires_at.isoformat(),
            "max_uses": link.max_uses,
            "note": "Save the link — it is not shown again; dead after max_uses opens.",
        }


@app.get("/api/share/{token}")
async def open_share(token: str, request: Request):
    """Публичный endpoint (без auth) для открытия share-link (секрет или заметка)."""
    th = hash_token(token)
    with db.get_session() as s:
        link = s.query(db.ShareLink).filter_by(token_hash=th).first()
        if not link:
            note = _open_note_share(token, request)
            if note is not None:
                return note
        if not link or link.revoked:
            raise HTTPException(404, "share link not found or revoked")
        # SQLite возвращает naive datetimes, db.utcnow() — aware. Сравниваем как наивные.
        now_naive = db.utcnow().replace(tzinfo=None)
        if link.expires_at < now_naive:
            raise HTTPException(410, "share link has expired")
        if link.used_count >= link.max_uses:
            raise HTTPException(410, "share link has no uses left")
        sec = s.get(db.Secret, link.secret_id)
        if not sec:
            raise HTTPException(404, "the secret has been deleted")
        # Decrypt: share_key только в момент создания — потеряли. Сейчас вытащим
        # значение по folder_key из vault — но vault может быть locked. Поэтому
        # храним folder_key_enc как простое envelope под share_key derived из token.
        # Здесь повторно derive share_key из raw token + 16-байт salt из nonce[0:16].
        share_key = _share_key(token)
        try:
            folder_key = crypto.decrypt(share_key, link.folder_key_enc, link.folder_key_nonce)
            value = crypto.decrypt(folder_key, sec.value_enc, sec.value_nonce)
            # v0.7.1: the login goes with the value — a human recipient needs both
            login = crypto.decrypt(folder_key, sec.login_enc, sec.login_nonce) if sec.login_enc else b""
        except Exception:
            raise HTTPException(500, "cannot decrypt (corrupted share link)")
        # Atomic consume: two parallel opens must not both pass a max_uses=1 link. The
        # conditional UPDATE is the arbiter; the loser gets 410 like any exhausted link.
        from sqlalchemy import text as _text
        consumed = s.execute(
            _text("UPDATE share_links SET used_count = used_count + 1 "
                  "WHERE id = :id AND used_count < max_uses AND NOT revoked"),
            {"id": link.id}).rowcount
        s.commit()
        if consumed != 1:
            raise HTTPException(410, "share link has no uses left")
        s.refresh(link)
        audit("share:read", target=f"share:{sec.name}", actor="unauth", ip=_client_ip(request))
        return {
            "name": sec.name, "value": value.decode("utf-8"), "login": login.decode("utf-8"),
            "uses_left": link.max_uses - link.used_count,
            "expires_at": link.expires_at.isoformat(),
            "note": link.note,
        }


@app.get("/api/shares")
async def list_shares(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.ShareLink, db.Secret).join(db.Secret).order_by(db.ShareLink.created_at.desc()).limit(100).all()
        out = [{
            "id": l.id, "kind": "secret", "secret_name": sec.name, "secret_id": sec.id,
            "created_at": l.created_at.isoformat() if l.created_at else "",
            "expires_at": l.expires_at.isoformat() if l.expires_at else "",
            "max_uses": l.max_uses, "used_count": l.used_count,
            "revoked": l.revoked, "note": l.note,
        } for l, sec in rows]
        for n in s.query(db.NoteShare).order_by(db.NoteShare.created_at.desc()).limit(100).all():
            out.append({"id": n.id, "kind": "note", "secret_name": n.title or "note", "secret_id": None,
                        "created_at": n.created_at.isoformat() if n.created_at else "", "expires_at": n.expires_at.isoformat() if n.expires_at else "",
                        "max_uses": n.max_uses, "used_count": n.used_count, "revoked": n.revoked, "note": n.note})
        out.sort(key=lambda x: x["created_at"], reverse=True)
        return out[:100]


@app.delete("/api/shares/note/{nid}")
async def revoke_note_share(nid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        n = s.get(db.NoteShare, nid)
        if not n:
            raise HTTPException(404, "not found")
        n.revoked = True; s.commit()
        audit("share:revoke", target=f"note:{n.title or n.id}", ip=_client_ip(request))
        return {"ok": True}


@app.delete("/api/shares/{sid}")
async def revoke_share(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        l = s.get(db.ShareLink, sid)
        if not l:
            raise HTTPException(404, "not found")
        l.revoked = True
        s.commit()
        audit("share:revoke", target=f"share:{l.id}", ip=_client_ip(request))
        return {"ok": True}


# ─── Endpoints: stats (v0.3) ──────────────────────────────────────────────────
@app.get("/api/stats")
async def stats(_: str = Depends(require_unlocked)):
    """Сводка по vault: счётчики, stale-секреты, активные токены."""
    from datetime import timedelta
    with db.get_session() as s:
        cutoff_90 = db.utcnow() - timedelta(days=90)
        total_secrets = s.query(db.Secret).count()
        total_folders = s.query(db.Folder).count()
        # stale: last_accessed либо null, либо старее 90 дней
        stale = s.query(db.Secret).filter(
            (db.Secret.last_accessed.is_(None)) | (db.Secret.last_accessed < cutoff_90)
        ).count()
        # Token usage: количество secret:read и m:secret:read per actor за 30 дней
        cutoff_30 = db.utcnow() - timedelta(days=30)
        tokens = []
        for t in s.query(db.ServiceToken).filter_by(revoked=False).all():
            cnt = s.query(db.AuditLog).filter(
                db.AuditLog.actor == f"token:{t.id}",
                db.AuditLog.ts >= cutoff_30,
                db.AuditLog.action == "m:secret:read",
            ).count()
            tokens.append({"id": t.id, "name": t.name, "folder_id": t.folder_id,
                          "reads_30d": cnt,
                          "last_used": t.last_used.isoformat() if t.last_used else None})
        tokens.sort(key=lambda x: x["reads_30d"], reverse=True)
        now = db.utcnow().replace(tzinfo=None)
        expired = s.query(db.Secret).filter(db.Secret.expires_at.isnot(None), db.Secret.expires_at < now).count()
        expiring_30d = s.query(db.Secret).filter(db.Secret.expires_at.isnot(None), db.Secret.expires_at >= now,
                                                 db.Secret.expires_at < now + timedelta(days=30)).count()
        return {
            "totals": {"secrets": total_secrets, "folders": total_folders, "stale": stale,
                       "expired": expired, "expiring_30d": expiring_30d},
            "tokens_usage": tokens,
        }


# ─── Endpoints: JSON export/import (v0.3) ────────────────────────────────────
@app.get("/api/export")
async def export_json(request: Request, _: str = Depends(require_unlocked)):
    """Полный экспорт vault в JSON (плейн-значения!). Только под master.
    Использовать для бэкапа / миграции в другой vault."""
    with db.get_session() as s:
        folders = []
        for f in s.query(db.Folder).order_by(db.Folder.name).all():
            secs = []
            for sec in s.query(db.Secret).filter_by(folder_id=f.id).all():
                if getattr(sec, "machine_only", False) or getattr(sec, "require_approval", False):
                    val = None          # never leaves the vault through a human path
                else:
                    try:
                        val = _dec_with_folder(s, sec.folder_id, sec.value_enc, sec.value_nonce).decode("utf-8")
                    except Exception:
                        val = ""
                notes = ""
                if sec.notes_enc:
                    try:
                        notes = _dec_with_folder(s, sec.folder_id, sec.notes_enc, sec.notes_nonce).decode("utf-8")
                    except Exception:
                        pass
                totp = ""
                if sec.totp_seed_enc:
                    try:
                        totp = _dec_with_folder(s, sec.folder_id, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
                    except Exception:
                        pass
                login = ""
                if getattr(sec, "login_enc", None):
                    try:
                        login = _dec_with_folder(s, sec.folder_id, sec.login_enc, sec.login_nonce).decode("utf-8")
                    except Exception:
                        pass
                secs.append({
                    "name": sec.name, "value": val, "machine_only": bool(getattr(sec, "machine_only", False)), "require_approval": bool(getattr(sec, "require_approval", False)), "login": login, "notes": notes, "totp_seed": totp,
                    "tags": sec.tags or "", "url": sec.url or "",
                    "is_favorite": bool(getattr(sec, "is_favorite", False)),
                })
            folders.append({"name": f.name, "description": f.description, "secrets": secs})
        audit("export:json", target=f"{sum(len(fld['secrets']) for fld in folders)} secrets",
              ip=_client_ip(request))
        return {"version": "0.3.0", "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "folders": folders}


class ImportPayload(BaseModel):
    folders: list[dict]
    create_missing_folders: bool = True
    skip_existing: bool = True


@app.post("/api/import")
async def import_json(payload: ImportPayload, request: Request, _: str = Depends(require_unlocked)):
    n_secrets = 0; n_folders = 0; n_skip = 0
    with db.get_session() as s:
        for fld in payload.folders:
            fname = fld.get("name") or ""
            if not fname: continue
            folder = s.query(db.Folder).filter_by(name=fname).first()
            if not folder:
                if not payload.create_missing_folders: continue
                scope_key = pysecrets.token_bytes(32)
                enc, nonce = crypto.encrypt(current_master_key(), scope_key)
                folder = db.Folder(name=fname, description=fld.get("description", ""),
                                   scope_key_enc=enc, scope_key_nonce=nonce)
                s.add(folder); s.flush(); n_folders += 1
            existing_names = {sec.name for sec in s.query(db.Secret).filter_by(folder_id=folder.id)}
            for sd in fld.get("secrets", []):
                name = sd.get("name", "")
                if not name: continue
                if payload.skip_existing and name in existing_names:
                    n_skip += 1; continue
                if sd.get("value") is None:
                    n_skip += 1; continue      # a machine-only secret exported without its value
                val_enc, val_nonce = _enc_with_folder(s, folder.id, (sd.get("value", "") or "").encode("utf-8"))
                notes_enc, notes_nonce = b"", b""
                if sd.get("notes"):
                    notes_enc, notes_nonce = _enc_with_folder(s, folder.id, sd["notes"].encode("utf-8"))
                totp_enc, totp_nonce = b"", b""
                if sd.get("totp_seed"):
                    totp_enc, totp_nonce = _enc_with_folder(s, folder.id, sd["totp_seed"].encode("utf-8"))
                login_enc, login_nonce = b"", b""
                if sd.get("login"):
                    login_enc, login_nonce = _enc_with_folder(s, folder.id, sd["login"].encode("utf-8"))
                s.add(db.Secret(
                    folder_id=folder.id, name=name,
                    value_enc=val_enc, value_nonce=val_nonce,
                    notes_enc=notes_enc, notes_nonce=notes_nonce,
                    login_enc=login_enc, login_nonce=login_nonce,
                    totp_seed_enc=totp_enc, totp_seed_nonce=totp_nonce,
                    tags=sd.get("tags", ""), url=sd.get("url", ""),
                    is_favorite=bool(sd.get("is_favorite")),
                ))
                n_secrets += 1
        s.commit()
        audit("import:json", target=f"{n_secrets} secrets, {n_folders} folders",
              ip=_client_ip(request))
    return {"created_secrets": n_secrets, "created_folders": n_folders, "skipped": n_skip}


# ─── Endpoints: webhooks (v0.3) ──────────────────────────────────────────────
class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=512)
    event_filter: str = "*"
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = _check_url(v)
        if not _webhook_target_allowed(v):
            raise ValueError("webhook target resolves to a private or loopback address "
                             "(set VAULT_WEBHOOK_ALLOW_PRIVATE=1 to allow)")
        return v


def _webhook_target_allowed(url: str) -> bool:
    """SSRF guard: a webhook is admin-configured, but the vault should still not become a
    way to poke at the metadata service or internal hosts. Private/loopback/link-local
    targets are refused unless explicitly allowed."""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    if cfgmod.SETTINGS.webhook_allow_private:
        return True
    host = urlparse(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False
    return bool(infos)


def _emit(event: str, data: dict) -> None:
    """Fire webhooks for an event without blocking the request. Payload carries names and
    ids only — never values."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_fire_webhook(event, data))


@app.get("/api/webhooks")
async def list_webhooks(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.Webhook).order_by(db.Webhook.name).all()
        return [{
            "id": w.id, "name": w.name, "url": w.url,
            "event_filter": w.event_filter, "enabled": w.enabled,
            "created_at": w.created_at.isoformat() if w.created_at else "",
            "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
            "last_status": w.last_status,
        } for w in rows]


@app.post("/api/webhooks")
async def create_webhook(req: WebhookCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        signing = pysecrets.token_hex(16)
        w = db.Webhook(name=req.name, url=req.url, event_filter=req.event_filter,
                       enabled=req.enabled, signing_secret=signing)
        s.add(w); s.commit(); s.refresh(w)
        audit("webhook:create", target=req.name, ip=_client_ip(request))
        return {"id": w.id, "signing_secret": signing,
                "note": "Save the signing_secret — the receiver uses it to verify the HMAC"}


@app.delete("/api/webhooks/{wid}")
async def delete_webhook(wid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        w = s.get(db.Webhook, wid)
        if not w:
            raise HTTPException(404, "not found")
        s.delete(w); s.commit()
        audit("webhook:delete", target=w.name, ip=_client_ip(request))
        return {"ok": True}


async def _fire_webhook(event: str, data: dict) -> None:
    """Best-effort delivery: HMAC-SHA256 подпись в X-Vault-Signature."""
    import hmac, hashlib, asyncio
    import urllib.request
    with db.get_session() as s:
        hooks = [w for w in s.query(db.Webhook).filter_by(enabled=True).all()
                 if _event_matches(w.event_filter, event)]
        if not hooks: return
        payload = json.dumps({"event": event, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "data": data}, ensure_ascii=False).encode()
        for w in hooks:
            # Re-checked at delivery time too: DNS may have changed since the hook was created.
            if not (w.url.startswith("https://") or w.url.startswith("http://")) or not _webhook_target_allowed(w.url):
                w.last_status = "err: url not allowed"
                w.last_triggered_at = db.utcnow()
                continue
            sig = hmac.new(w.signing_secret.encode(), payload, hashlib.sha256).hexdigest()
            try:
                req = urllib.request.Request(
                    w.url, data=payload, method="POST",
                    headers={"Content-Type": "application/json",
                             "X-Vault-Event": event,
                             "X-Vault-Signature": f"sha256={sig}"})
                await asyncio.get_event_loop().run_in_executor(None, _deliver_webhook, req)
                w.last_status = "ok"
                metrics.record_webhook("ok")
            except Exception as e:
                w.last_status = f"err: {str(e)[:60]}"
                metrics.record_webhook("error")
            w.last_triggered_at = db.utcnow()
        s.commit()


def _deliver_webhook(req) -> bytes:
    """Отправка webhook'а через urlopen. Вынесено в отдельную функцию чтобы
    nosemgrep-аннотация была локальной. URL валидирован вызывающим
    (http/https only); SSRF-риски выше по стеку (admin-only UI)."""
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    return urllib.request.urlopen(req, timeout=5).read()


def _event_matches(filter_pat: str, event: str) -> bool:
    if filter_pat in ("*", ""): return True
    for p in filter_pat.split(","):
        p = p.strip()
        if p == event: return True
        if p.endswith(":*") and event.startswith(p[:-1]): return True
    return False


# ─── Observability: Prometheus metrics and lock-out listing ─────────────────
def _ops_auth(request: Request) -> None:
    """Bearer VAULT_METRICS_TOKEN. Unset token → endpoints behave as if they did not exist."""
    tok = cfgmod.SETTINGS.metrics_token
    if not tok:
        raise HTTPException(404, "Not Found")
    auth = request.headers.get("authorization", "")
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not secrets_compare(parts[1].strip(), tok):
        raise HTTPException(401, "metrics token required")


@app.get("/metrics")
async def prometheus_metrics(request: Request):
    _ops_auth(request)
    with db.get_session() as s:
        now = db.utcnow()
        secrets_n = s.query(db.Secret).count()
        folders_n = s.query(db.Folder).count()
        tokens_n = s.query(db.ServiceToken).filter(
            db.ServiceToken.revoked.is_(False),
            (db.ServiceToken.expires_at.is_(None)) | (db.ServiceToken.expires_at > now)).count()
        locked_n = sum(1 for r in s.query(db.Lockdown).all() if netutil.is_locked(r.ip))
    body = metrics.render(VERSION, sessions.active_count(), secrets_n, folders_n, tokens_n, locked_n,
                          siem.sent, siem.errors, node=NODE)
    return Response(body, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/security/lockdowns")
async def security_lockdowns(request: Request):
    """Addresses currently over the failed-attempt budget — input for ops/fail2ban/sync-bans.sh."""
    _ops_auth(request)
    with db.get_session() as s:
        rows = s.query(db.Lockdown).order_by(db.Lockdown.last_fail.desc()).all()
        locked = [{"ip": r.ip, "fail_count": r.fail_count or 0,
                   "last_fail": r.last_fail.isoformat() if r.last_fail else None}
                  for r in rows if netutil.is_locked(r.ip)]
    return {"locked": locked, "window_sec": cfgmod.SETTINGS.fail_window_sec,
            "limit_per_ip": cfgmod.SETTINGS.fail_limit_per_ip}


# ─── Machine API (M4) ────────────────────────────────────────────────────────
# Подключаем после определения всего — отдельный router.
try:
    import sdk_api
    app.include_router(sdk_api.build_router())
    app.include_router(sdk_api.build_kv_router())

    @app.exception_handler(sdk_api.KVError)
    async def _kv_error(request: Request, exc: sdk_api.KVError):
        return JSONResponse({"errors": exc.errors}, status_code=exc.status)
except Exception as e:
    logger.warning("sdk_api router not loaded: %s", e)


@app.on_event("startup")
async def _startup():
    db.get_engine()  # создаст таблицы
    crypto.load_config_or_none()        # activates the stored cipher suite before any request
    purged = sessions.purge_expired()
    logger.info("aps-vault v%s started on %s; db=%s initialized=%s cipher=%s sessions_active=%d (purged %d expired)",
                VERSION, NODE, "sqlite" if db.is_sqlite() else "postgresql", crypto.config_exists(), _suite_mod.active(),
                sessions.active_count(), purged)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8086)
