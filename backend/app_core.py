"""The application object and what every request passes through: CORS, security headers, CSRF, the audit
log, request helpers, folder-key crypto helpers and the request/response models.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import json
import logging
import os
import secrets as pysecrets
import socket
from datetime import datetime, timezone

from fastapi import (FastAPI, HTTPException, Request)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

import crypto
import db
import metrics
import netutil
import policy
import settings as cfgmod
import siem
from pydantic import field_validator
from state import current_identity, current_identity_or_none
import users as _users

from version import VERSION  # noqa: F401

logger = logging.getLogger("aps-vault")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

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
    p = request.url.path
    if p.startswith("/api/") or p.startswith("/v1/"):
        # 0.37: API answers carry values — never into the browser's disk cache or a TLS-inspecting proxy's cache
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
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
                       "/api/auth/webauthn/options", "/api/auth/webauthn/unlock", "/api/auth/hsm/unlock", "/api/auth/kms/unlock",
                       "/api/auth/login", "/api/enroll", "/api/auth/agent"}


def _csrf_required(method: str, path: str) -> bool:
    if method in {"GET", "HEAD", "OPTIONS"}:
        return False
    if path in _CSRF_EXEMPT_PATHS:
        return False
    if path.startswith("/api/v1/m/"):     # Machine API — Bearer-only, не cookie
        return False
    if path.startswith("/api/approve/"):  # approver's decision: no session, authenticated by the approver password
        return False
    if path.startswith("/api/invite/"):   # 0.20: the invited person has no session yet; the invite token authenticates
        return False
    if path.startswith("/api/agent/"):    # 0.38: the update agent — its own Bearer token, never a cookie
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
def audit(action: str, target: str = "", actor: str | None = None,
          ip: str = "", ua: str = "", meta: dict | None = None) -> None:
    if actor is None:                       # 0.20: the owner is "master", a named user is their e-mail
        ident = current_identity_or_none()
        actor = ident.actor if ident else "master"
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
    """The folder's key for the current identity: the owner unwraps it with the master key, a named
    user (0.20) opens the grant sealed to their key — no grant, no key."""
    folder = session.get(db.Folder, folder_id)
    if not folder:
        raise HTTPException(404, "folder not found")
    ident = current_identity()
    if ident.kind == "user":
        got = _users.folder_key(ident.user_id, folder_id, ident.key)
        if got is None:
            raise HTTPException(403, "no access to this folder")
        return got[0]
    return crypto.decrypt(ident.key, folder.scope_key_enc, folder.scope_key_nonce)


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
    master_password: str | None = Field(default=None, max_length=256)   # 0.37: needed to LIFT either flag

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
