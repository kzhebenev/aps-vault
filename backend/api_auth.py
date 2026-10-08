"""Initialisation, unlock and lock, sessions; the master key in a PKCS#11 token or a cloud KMS; WebAuthn;
the master password's second factor; recovery.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import secrets as pysecrets
from datetime import datetime, timezone

from fastapi import (Cookie, Depends, HTTPException, Query, Request)
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
import pyotp
from argon2 import PasswordHasher

import crypto
import db
import netutil
import sessions
import settings as cfgmod
import siem
from state import STATE, current_identity, current_master_key
import suite as _suite_mod
import users as _users
import hsm
import kms
import webauthn_auth

from api_users import _issue_user_session  # noqa: F401
from app_core import CSRF_COOKIE, InitRequest, InitResponse, NODE, SESSION_COOKIE, UnlockResponse, _client_ip, _ui_policy_check, app, audit, logger, secrets_compare  # noqa: F401
from authz import _attempt_failed, _guard_attempts, _totp_accept, require_unlocked  # noqa: F401
from version import VERSION  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

@router.get("/api/health")
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
        "cipher_experimental": _suite_mod.experimental(),
        "server_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@router.get("/api/ready")
async def ready():
    """Readiness for a load balancer: 200 when this replica can reach the shared database
    (an uninitialised or locked vault is still *ready* — it can be initialised/unlocked)."""
    if not db.ping():
        return JSONResponse({"ready": False, "node": NODE, "db": "error"}, status_code=503)
    return {"ready": True, "node": NODE, "db": "ok"}


@router.post("/api/init", response_model=InitResponse)
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


@router.post("/api/auth/unlock", response_model=UnlockResponse)
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
        if not _totp_accept("owner", totp_secret, req.totp_code):
            netutil.record_fail(ip)
            audit("auth:totp_fail", ip=ip)
            raise HTTPException(401, "wrong TOTP code")

    # v0.13: security key as a second factor on top of the password
    if cfg.webauthn_second_factor and _webauthn_registered():
        if not req.webauthn:
            raise HTTPException(401, "security key required: present a WebAuthn assertion", headers={"X-WebAuthn-Required": "1"})
        try:
            cred = webauthn_auth.verify_assertion(req.webauthn, "second_factor")
            if getattr(cred, "user_id", None):
                # 0.37: a named user's key is not the owner's second factor (it used to pass)
                raise ValueError("this security key belongs to a named user, not to the owner")
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


@router.get("/api/auth/hsm/status")
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


@router.post("/api/auth/hsm/enable")
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


@router.post("/api/auth/hsm/disable")
async def hsm_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.hsm_master_enc, cfg.hsm_master_iv, cfg.hsm_key_label = b"", b"", ""
    crypto.save_config(cfg)
    audit("auth:hsm_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@router.post("/api/auth/hsm/unlock")
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


@router.get("/api/auth/kms/status")
async def kms_status():
    cfg = crypto.load_config_or_none()
    out = {"configured": kms.configured(), "enabled": bool(cfg and cfg.kms_master_enc), "pin_bound": bool(cfg and cfg.kms_pin_bound),
           "provider": cfg.kms_provider if cfg and cfg.kms_provider else (cfgmod.SETTINGS.kms_provider or None), "key_id": cfg.kms_key_id if cfg and cfg.kms_key_id else None}
    if kms.configured():
        out["kms"] = kms.info()
    return out


@router.post("/api/auth/kms/enable")
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


@router.post("/api/auth/kms/disable")
async def kms_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.kms_master_enc, cfg.kms_provider, cfg.kms_key_id, cfg.kms_pin_bound = b"", "", "", False
    crypto.save_config(cfg)
    audit("auth:kms_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@router.post("/api/auth/kms/unlock")
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
        key, legacy = kms.decrypt_with_info(cfg.kms_master_enc, req.pin)
    except kms.KmsError as e:
        fails = netutil.record_fail(ip)
        audit("auth:kms_fail", ip=ip, meta={"stage": "unlock", "attempts": fails, "error": str(e)[:120]})
        siem.security_log("kms", ip)
        raise HTTPException(401, "KMS refused the PIN context")
    if not crypto.verify_master_key(key, cfg):
        netutil.record_fail(ip); audit("auth:kms_fail", ip=ip, meta={"stage": "unlock", "error": "verifier"})
        raise HTTPException(401, "cell opened but does not match this vault (re-enable KMS)")
    if legacy:
        # 0.37: a pre-0.37 cell had the PIN in the KMS context (CloudTrail) — re-wrap it into the local-Argon2 form now
        try:
            cfg.kms_master_enc = kms.encrypt(key, req.pin); crypto.save_config(cfg)
            audit("auth:kms_rewrapped", ip=ip, meta={"from": "pin-in-context", "to": "pin-local-argon2"})
        except kms.KmsError as e:
            logger.warning("kms re-wrap of a legacy PIN cell failed: %s", e)
    netutil.clear_fails(ip)
    return _issue_session_response(key, ip, request, how="kms")


# ─── WebAuthn: security keys / Touch ID (v0.13) ──────────────────────────────


def _webauthn_registered() -> bool:
    """The owner has at least one security key (users' keys, user_id set, do not count)."""
    with db.get_session() as s:
        return s.query(db.WebauthnCredential).filter_by(user_id=None).count() > 0


def _issue_session_response(key: bytes, ip: str, request: Request, how: str) -> JSONResponse:
    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(key, csrf_token, ip=ip)
    import oidc as _oidc
    if _oidc.is_enabled():
        STATE.node_master_key = key
    audit("auth:unlock", ip=ip, ua=request.headers.get("user-agent", ""), meta={"node": NODE, "how": how})
    return _session_cookies(sid, csrf_token)


def _session_cookies(sid: str, csrf_token: str) -> JSONResponse:
    """The unlock response: session and CSRF cookies plus csrf_token in the body (0.41.8: shared with agent keys)."""
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


@router.get("/api/auth/webauthn/status")
async def webauthn_status(email: str | None = Query(default=None)):
    """Public: what the login screen may offer — the owner's keys, or a named user's when `email` is given (0.23)."""
    try:
        cfg = crypto.load_config_or_none()
    except Exception:
        cfg = None
    rp_id, _ = webauthn_auth.rp()
    if email:
        u = _users.by_email(email)
        with db.get_session() as s:
            creds = s.query(db.WebauthnCredential).filter_by(user_id=u.id).all() if u and u.is_active else []
        return {"rp_id": rp_id, "credentials": len(creds), "prf_unlock": any(c.prf_master_enc for c in creds),
                "second_factor": bool(u and u.is_active and u.webauthn_second_factor and creds)}
    with db.get_session() as s:
        creds = s.query(db.WebauthnCredential).filter_by(user_id=None).all()
    return {"rp_id": rp_id, "credentials": len(creds), "prf_unlock": any(c.prf_master_enc for c in creds),
            "second_factor": bool(cfg and cfg.webauthn_second_factor and creds)}


@router.get("/api/auth/webauthn/credentials")
async def webauthn_list(_: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind == "user":
        u = _users.by_id(ident.user_id)
        return {"credentials": webauthn_auth.list_credentials(ident.user_id), "second_factor": bool(u and u.webauthn_second_factor), "rp_id": webauthn_auth.rp()[0]}
    cfg = crypto.load_config()
    return {"credentials": webauthn_auth.list_credentials(), "second_factor": bool(cfg.webauthn_second_factor), "rp_id": webauthn_auth.rp()[0]}


@router.post("/api/auth/webauthn/register/options")
async def webauthn_register_options(req: WebauthnRegisterOptions, _: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind == "user":
        return webauthn_auth.registration_options(req.name, ident.user_id, ident.email)
    return webauthn_auth.registration_options(req.name)


@router.post("/api/auth/webauthn/register/finish")
async def webauthn_register_finish(req: WebauthnRegisterFinish, request: Request, _: str = Depends(require_unlocked)):
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    ident = current_identity()
    if ident.kind == "user":
        # 0.23: a named user proves their own password; the PRF cell then wraps their private key
        got = _users.authenticate(ident.email, req.master_password)
        if not got:
            netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "webauthn-register"})
            raise HTTPException(401, "wrong password")
        key, user_id = got[1], ident.user_id
    else:
        cfg = crypto.load_config()
        key = crypto.verify_master_password(req.master_password, cfg)
        if not key:
            netutil.record_fail(ip); audit("auth:fail", ip=ip, meta={"scope": "webauthn-register"})
            raise HTTPException(401, "wrong master password")
        user_id = None
    try:
        out = webauthn_auth.registration_finish(req.credential, req.name, key, req.prf_output, req.transports, user_id=user_id)
    except Exception as e:
        raise HTTPException(400, f"registration rejected: {e}")
    audit("auth:webauthn_registered", ip=ip, meta={"name": out["name"], "prf": out["prf"]})
    return out


@router.delete("/api/auth/webauthn/credentials/{cid}")
async def webauthn_delete(cid: int, request: Request, _: str = Depends(require_unlocked)):
    ident = current_identity()
    with db.get_session() as s:
        c = s.get(db.WebauthnCredential, cid)
        if not c or (c.user_id or None) != (ident.user_id if ident.kind == "user" else None):
            raise HTTPException(404, "not found")
        name = c.name; s.delete(c); s.commit()
    if ident.kind == "user":
        if not webauthn_auth.list_credentials(ident.user_id):
            _users.set_second_factor(ident.user_id, False)        # never lock the person out
    elif not _webauthn_registered():
        cfg = crypto.load_config()
        if cfg.webauthn_second_factor:
            cfg.webauthn_second_factor = False; crypto.save_config(cfg)   # never lock the admin out
    audit("auth:webauthn_removed", ip=_client_ip(request), meta={"name": name})
    return {"ok": True}


class WebauthnSecondFactor(BaseModel):
    enabled: bool
    password: str = Field(default="", max_length=256)    # 0.37: required to turn the factor OFF


@router.post("/api/auth/webauthn/second-factor")
async def webauthn_second_factor(req: WebauthnSecondFactor, request: Request, _: str = Depends(require_unlocked)):
    ident = current_identity()
    if not req.enabled:
        # 0.37: turning a factor off weakens every future sign-in — a session alone is not enough
        _guard_attempts(request)
        ok = (bool(_users.authenticate(ident.email, req.password)) if ident.kind == "user"
              else bool(crypto.verify_master_password(req.password, crypto.load_config())))
        if not ok:
            _attempt_failed(request, "auth:webauthn_second_factor_fail")
            raise HTTPException(401, "wrong password: confirm turning the second factor off with your password")
    if ident.kind == "user":
        if req.enabled and not webauthn_auth.list_credentials(ident.user_id):
            raise HTTPException(409, "register a security key first")
        _users.set_second_factor(ident.user_id, req.enabled)
        audit("auth:webauthn_second_factor", ip=_client_ip(request), meta={"enabled": req.enabled})
        return {"ok": True, "second_factor": req.enabled}
    if req.enabled and not _webauthn_registered():
        raise HTTPException(409, "register a security key first")
    cfg = crypto.load_config(); cfg.webauthn_second_factor = req.enabled; crypto.save_config(cfg)
    audit("auth:webauthn_second_factor", ip=_client_ip(request), meta={"enabled": req.enabled})
    return {"ok": True, "second_factor": req.enabled}


@router.post("/api/auth/webauthn/options")
async def webauthn_options(purpose: str = Query(default="unlock", pattern="^(unlock|second_factor)$"), email: str | None = Query(default=None)):
    """Public: a challenge for touch-to-unlock (PRF credentials) or for the second factor — the owner's
    keys, or a named user's when `email` is given (0.23)."""
    if not crypto.config_exists():
        raise HTTPException(412, "vault is not initialised")
    user_id = None
    if email:
        u = _users.by_email(email)
        if not u or not u.is_active:
            raise HTTPException(404, "no registered security key for this purpose")
        user_id = u.id
    try:
        return webauthn_auth.authentication_options(purpose, user_id)
    except LookupError as e:
        raise HTTPException(404, str(e))


@router.post("/api/auth/webauthn/unlock")
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
    if getattr(cred, "user_id", None):
        # 0.23: the key belongs to a named user — the PRF cell held their private key
        u = _users.by_id(cred.user_id)
        if not u or not u.is_active:
            raise HTTPException(401, "user is deactivated")
        return _issue_user_session(u, key, ip, request, how=f"webauthn:{cred.name}")
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


@router.get("/api/auth/oidc/status")
async def oidc_status():
    """Включён ли OIDC — фронт показывает кнопку только тогда; и откуда эта реплика возьмёт мастер-ключ."""
    import oidc as _oidc
    return {"enabled": _oidc.is_enabled(), "sso_unlock": sso_unlock_source()}


class SsoUnlockEnable(BaseModel):
    master_password: str


@router.get("/api/auth/sso-unlock/status")
async def sso_unlock_status(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"available": bool(cfgmod.SETTINGS.sso_unlock_key), "enabled": bool(cfg.sso_master_enc), "source": sso_unlock_source()}


@router.post("/api/auth/sso-unlock/enable")
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


@router.post("/api/auth/sso-unlock/disable")
async def sso_unlock_disable(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.sso_master_enc, cfg.sso_master_nonce = b"", b""
    crypto.save_config(cfg)
    STATE.lock()
    audit("auth:sso_unlock_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@router.get("/api/auth/oidc/login")
async def oidc_login():
    """Старт OIDC: ставит state+PKCE+nonce cookies, 302 на Keycloak."""
    import oidc as _oidc
    return _oidc.login_redirect()


@router.get("/api/auth/oidc/callback")
async def oidc_callback(request: Request):
    """OIDC callback: валидация → разлок (если master в env) → сессия → 302 /."""
    import oidc as _oidc
    user = _oidc.exchange_code(request)
    ip = _client_ip(request)
    _ui_policy_check(request)

    # 0.23: an e-mail that belongs to a named user signs that user in — through their SSO cell
    # (private key under the server SSO key, written when they set their password)
    if _users.exists_active(user["email"]):
        got = _users.sso_open(user["email"])
        if not got:
            audit("oidc:user_no_cell", actor=user["email"], ip=ip, meta={"email": user["email"]})
            raise HTTPException(503, "SSO for this user is not ready: sign in with the password once (VAULT_SSO_UNLOCK_KEY must be set on the server)")
        u, priv = got
        csrf_token = pysecrets.token_urlsafe(32)
        sid = sessions.issue(priv, csrf_token, oidc_user=u.email, ip=ip, user_id=u.id)
        audit("oidc:login", actor=u.email, ip=ip, ua=request.headers.get("user-agent", ""), meta={"email": u.email, "name": user.get("name"), "kind": "user"})
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(SESSION_COOKIE, sid, max_age=8 * 3600, httponly=True, samesite="lax", secure=True, path="/")
        resp.set_cookie(CSRF_COOKIE, csrf_token, max_age=8 * 3600, httponly=False, samesite="lax", secure=True, path="/")
        _oidc.clear_oidc_cookies(resp)
        return resp

    # 0.37: the owner path is NOT the default for "everyone else". An e-mail that belongs (or belonged) to a named
    # user never becomes the owner — a deactivated user used to fall through here and get an owner session — and
    # the owner must be listed explicitly in VAULT_OIDC_OWNERS (e-mail or sub:<subject>).
    if _users.exists_any(user["email"]):
        audit("oidc:user_inactive", actor=user["email"], ip=ip, meta={"email": user["email"]})
        raise HTTPException(403, "this account is deactivated in the vault")
    owners = _oidc._cfg()["owners"]
    if user["email"] not in owners and f"sub:{user.get('sub', '')}" not in owners:
        audit("oidc:not_allowed", ip=ip, ua=request.headers.get("user-agent", ""), meta={"email": user["email"], "sub": user.get("sub", "")})
        raise HTTPException(403, "this SSO account is neither a vault user nor a listed owner (VAULT_OIDC_OWNERS)")

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


@router.post("/api/auth/lock")
async def lock(request: Request, sid: str = Depends(require_unlocked), all: bool = Query(default=False)):
    """Drop this session everywhere (the row is shared). `?all=1` drops every session —
    the "lock the vault" of the single-node days, now cluster-wide."""
    if all and current_identity().kind != "owner":
        raise HTTPException(403, "locking every session is the owner's action")
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


@router.get("/api/auth/2fa/status")
async def twofa_status(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"enabled": bool(cfg.totp_secret_enc)}


@router.post("/api/auth/2fa/setup", response_model=TwoFaSetupResponse)
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


@router.post("/api/auth/2fa/verify")
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


@router.post("/api/auth/2fa/disable")
async def twofa_disable(req: TwoFaDisableRequest, request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    if not cfg.totp_secret_enc:
        raise HTTPException(409, "2FA is not enabled")
    secret = _read_2fa_secret(current_master_key(), cfg)
    _guard_attempts(request)
    if not secret or not pyotp.TOTP(secret).verify(req.totp_code, valid_window=1):
        _attempt_failed(request, "auth:2fa_disable_fail")       # 0.37: 6 digits from a session are no longer free to guess
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


@router.post("/api/auth/recover")
async def recover(req: RecoverRequest, request: Request):
    """
    Сброс master-password через одноразовый recovery code (получен при init).

    Логика: recovery_code дешифрует сохранённую копию master_key. master_key
    остаётся ТЕМ ЖЕ — поэтому все scope-keys и зашифрованные значения остаются
    рабочими. Меняется только пароль которым master_key защищён.

    После успеха старый recovery_code инвалидируется, выдаётся новый
    (показать ОДИН РАЗ как при init).
    """
    _ui_policy_check(request)                                   # 0.37: the master-password reset obeys the UI policy
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
