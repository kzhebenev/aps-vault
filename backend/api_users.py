"""Named users with roles per folder, their TOTP, and folder-key rotation after a revocation.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import secrets as pysecrets
import urllib.parse
import urllib.request

from fastapi import (Depends, HTTPException, Request)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import pyotp

import crypto
import db
import netutil
import sessions
import siem
from state import current_identity, current_master_key
import users as _users
import rotation as _rotation
import webauthn_auth

from app_core import CSRF_COOKIE, NODE, SESSION_COOKIE, UnlockResponse, _client_ip, _ui_policy_check, app, audit  # noqa: F401
from authz import _attempt_failed, _guard_attempts, _owner_only, _require_role, _totp_accept, require_unlocked  # noqa: F401
from webhooks import _emit  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

# ─── Named users with per-folder roles (v0.20) ───────────────────────────────
class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=256)
    name: str = Field(default="", max_length=128)
    grants: list[dict] = []            # [{folder_id, role}] applied right away


class GrantSet(BaseModel):
    folder_id: int
    role: str = Field(pattern="^(reader|writer|manager)$")


class UserLogin(BaseModel):
    email: str
    password: str
    webauthn: dict | None = None            # 0.23: assertion when the user's second factor is on
    totp_code: str | None = None      # 0.30: when the user enabled TOTP


def _issue_user_session(u, priv: bytes, ip: str, request: Request, how: str = "password") -> JSONResponse:
    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(priv, csrf_token, ip=ip, user_id=u.id)
    audit("auth:login", actor=u.email, ip=ip, ua=request.headers.get("user-agent", ""), meta={"node": NODE, "how": how})
    resp = JSONResponse({**UnlockResponse(ok=True, session_ttl_sec=8 * 3600).model_dump(), "csrf_token": csrf_token,
                         "kind": "user", "email": u.email, "name": u.name or ""})
    resp.set_cookie(SESSION_COOKIE, sid, max_age=8 * 3600, httponly=True, samesite="lax", secure=True, path="/")
    resp.set_cookie(CSRF_COOKIE, csrf_token, max_age=8 * 3600, httponly=False, samesite="lax", secure=True, path="/")
    return resp


class InviteAccept(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class UserPasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


@router.get("/api/me")
async def whoami(_: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind == "owner":
        return {"kind": "owner", "email": "", "name": "", "grants": {}}
    return {"kind": "user", "id": ident.user_id, "email": ident.email, "name": ident.name, "grants": _users.grants_of(ident.user_id),
            "totp_enabled": _users.totp_enabled(ident.user_id)}


@router.get("/api/users")
async def list_users(_: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind == "owner":
        return _users.list_users()
    # 0.30: a folder manager sees the directory of active people with their roles on the managed folders only
    managed = {fid for fid, r in _users.grants_of(ident.user_id).items() if r == "manager"}
    if not managed:
        raise HTTPException(403, "this action belongs to the vault owner (master password)")
    return [{"id": u["id"], "email": u["email"], "name": u["name"], "is_active": u["is_active"],
             "grants": [g for g in u["grants"] if g["folder_id"] in managed]}
            for u in _users.list_users() if u["is_active"] and u["has_password"]]


@router.post("/api/users")
async def create_user(req: UserCreate, request: Request, _: str = Depends(require_unlocked)):
    """Owner creates a person and gets a one-time invite link; grants may be attached at once."""
    _owner_only()
    try:
        u, invite = _users.create(req.email, req.name)
        for g in req.grants:
            _users.set_grant(u.id, int(g["folder_id"]), str(g.get("role", "reader")), current_master_key())
    except _users.UserError as e:
        raise HTTPException(400, str(e))
    audit("user:create", target=u.email, ip=_client_ip(request), meta={"grants": len(req.grants)})
    return {"id": u.id, "email": u.email, "invite_url": f"/invite/{invite}", "invite_expires_sec": _users.INVITE_TTL_SEC,
            "note": "Give this link to the person — it is shown once and sets their password."}


@router.post("/api/users/{uid}/invite")
async def reinvite_user(uid: int, request: Request, _: str = Depends(require_unlocked)):
    """Password reset: new key pair under a new invite, grants re-created, sessions closed."""
    _owner_only()
    try:
        invite = _users.reinvite(uid, current_master_key())
    except _users.UserError as e:
        raise HTTPException(404, str(e))
    audit("user:reinvite", target=str(uid), ip=_client_ip(request))
    return {"invite_url": f"/invite/{invite}", "invite_expires_sec": _users.INVITE_TTL_SEC}


@router.delete("/api/users/{uid}")
async def deactivate_user(uid: int, request: Request, _: str = Depends(require_unlocked)):
    _owner_only()
    try:
        _users.deactivate(uid)
    except _users.UserError as e:
        raise HTTPException(404, str(e))
    audit("user:deactivate", target=str(uid), ip=_client_ip(request))
    return {"ok": True}


@router.put("/api/users/{uid}/grants")
async def set_user_grant(uid: int, req: GrantSet, request: Request, _: str = Depends(require_unlocked)):
    """The owner grants any role on any folder. A folder **manager** (0.30) grants any role on the
    folders they manage — they hold the folder key, so the grant is wrapped from it; they cannot touch
    their own grant (the owner changes managers)."""
    ident = current_identity()
    try:
        if ident.kind == "owner":
            _users.set_grant(uid, req.folder_id, req.role, master_key=current_master_key())
        else:
            _require_role(req.folder_id, "manager")
            if uid == ident.user_id:
                raise HTTPException(403, "a manager cannot change their own grant — ask the owner")
            if req.role == "manager" or _users.role_on(uid, req.folder_id) == "manager":
                # 0.37: managers are appointed and removed by the owner — peers cannot demote or create each other
                raise HTTPException(403, "only the owner appoints or changes managers")
            got = _users.folder_key(ident.user_id, req.folder_id, ident.key)
            _users.set_grant(uid, req.folder_id, req.role, folder_key=got[0])
    except _users.UserError as e:
        raise HTTPException(400, str(e))
    audit("user:grant", target=str(uid), ip=_client_ip(request), meta={"folder_id": req.folder_id, "role": req.role})
    return {"ok": True}


@router.delete("/api/users/{uid}/grants/{fid}")
async def remove_user_grant(uid: int, fid: int, request: Request, _: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind != "owner":
        _require_role(fid, "manager")
        if uid == ident.user_id:
            raise HTTPException(403, "a manager cannot remove their own grant — ask the owner")
        if _users.role_on(uid, fid) == "manager":
            raise HTTPException(403, "only the owner appoints or changes managers")
    if not _users.remove_grant(uid, fid):
        raise HTTPException(404, "no such grant")
    audit("user:revoke_grant", target=str(uid), ip=_client_ip(request), meta={"folder_id": fid})
    return {"ok": True}


@router.get("/api/invite/{token}")
async def invite_info(token: str):
    u = _users.invite_info(token)
    if not u:
        raise HTTPException(404, "invitation is unknown, used or expired")
    return {"email": u.email, "name": u.name or ""}


@router.post("/api/invite/{token}")
async def invite_accept(token: str, req: InviteAccept, request: Request):
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)                                   # 0.37: the UI network/hours policy covers invitations too
    try:
        u = _users.accept_invite(token, req.password)
    except _users.UserError as e:
        n = netutil.record_fail(ip)
        audit("user:invite_fail", ip=ip, meta={"attempts": n})
        raise HTTPException(400, str(e))
    audit("user:invite_accepted", target=u.email, actor=u.email, ip=ip)
    return {"ok": True, "email": u.email}


@router.post("/api/auth/login")
async def user_login(req: UserLogin, request: Request):
    """A named user signs in with e-mail and password; the session carries their private key."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    _ui_policy_check(request)
    got = _users.authenticate(req.email, req.password)
    if not got:
        fails = netutil.record_fail(ip)
        audit("auth:fail", actor=req.email.strip().lower()[:256], ip=ip, meta={"attempts": fails, "scope": "user"})
        siem.security_log("user", ip)
        raise HTTPException(401, "wrong e-mail or password")
    u, priv = got
    if u.totp_secret_enc:
        secret = _users.totp_secret(u, priv)
        if not req.totp_code:
            raise HTTPException(401, "TOTP code required: this user enabled one-time codes", headers={"X-TOTP-Required": "1"})
        if not secret or not _totp_accept(f"user:{u.id}", secret, req.totp_code):
            fails = netutil.record_fail(ip)
            audit("auth:totp_fail", actor=u.email, ip=ip, meta={"attempts": fails, "scope": "user"})
            raise HTTPException(401, "wrong TOTP code")
    if u.webauthn_second_factor:
        if not req.webauthn:
            raise HTTPException(401, "security key required: pass a WebAuthn assertion for this user", headers={"X-WebAuthn-Required": "1"})
        try:
            cred = webauthn_auth.verify_assertion(req.webauthn, "second_factor")
            if (cred.user_id or None) != u.id:
                raise ValueError("key belongs to someone else")
        except Exception as e:
            fails = netutil.record_fail(ip)
            audit("auth:webauthn_fail", actor=u.email, ip=ip, meta={"stage": "second_factor", "attempts": fails, "error": e.__class__.__name__})
            raise HTTPException(401, f"security key rejected: {e.__class__.__name__}")
    netutil.clear_fails(ip)
    how = "password" + ("+totp" if u.totp_secret_enc else "") + ("+webauthn" if u.webauthn_second_factor else "")
    return _issue_user_session(u, priv, ip, request, how=how)


@router.post("/api/me/password")
async def user_change_password(req: UserPasswordChange, request: Request, sid: str = Depends(require_unlocked)):
    ident = current_identity()
    if ident.kind != "user":
        raise HTTPException(400, "the owner changes the master password in Settings")
    _guard_attempts(request)
    try:
        _users.change_password(ident.user_id, ident.key, req.current_password, req.new_password)
    except _users.UserError as e:
        if "current" in str(e).lower():
            _attempt_failed(request, "user:password_change_fail")
        raise HTTPException(400, str(e))
    closed = sessions.revoke_user_except(ident.user_id, sid)     # 0.37: a stolen session must not outlive the change
    audit("user:password_changed", ip=_client_ip(request), meta={"other_sessions_closed": closed})
    return {"ok": True, "other_sessions_closed": closed}




# ─── TOTP for named users (0.30): seed under KDF(private key), checked at password login ─────
class UserTotpVerify(BaseModel):
    secret_base32: str = Field(min_length=16, max_length=64)
    code: str = Field(min_length=6, max_length=8)
    password: str = Field(min_length=1, max_length=256)


class UserTotpDisable(BaseModel):
    code: str = Field(min_length=6, max_length=8)


def _me_user():
    ident = current_identity()
    if ident.kind != "user":
        raise HTTPException(400, "the owner manages 2FA in Settings")
    return ident


@router.get("/api/me/totp")
async def me_totp_status(_: str = Depends(require_unlocked)):
    ident = _me_user()
    return {"enabled": _users.totp_enabled(ident.user_id)}


@router.post("/api/me/totp/setup")
async def me_totp_setup(_: str = Depends(require_unlocked)):
    """A fresh seed with its otpauth URL and QR — not stored until /verify confirms a code and the password."""
    ident = _me_user()
    if _users.totp_enabled(ident.user_id):
        raise HTTPException(409, "TOTP is already enabled; disable it first")
    secret = pyotp.random_base32()
    issuer = "APS%20Vault"
    label = urllib.parse.quote(ident.email)
    otpauth = f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}"
    qr = ""
    try:
        import base64, io
        import qrcode
        from qrcode.image.pure import PyPNGImage
        buf = io.BytesIO(); qrcode.make(otpauth, image_factory=PyPNGImage).save(buf)
        qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass
    return {"secret_base32": secret, "otpauth_url": otpauth, "qr_data_url": qr, "enabled": False}


@router.post("/api/me/totp/verify")
async def me_totp_verify(req: UserTotpVerify, request: Request, _: str = Depends(require_unlocked)):
    ident = _me_user()
    _guard_attempts(request)
    if not pyotp.TOTP(req.secret_base32).verify(req.code.strip(), valid_window=1):
        raise HTTPException(400, "wrong code — try again in 30 seconds")
    if not _users.authenticate(ident.email, req.password):
        _attempt_failed(request, "user:totp_enable_fail")
        raise HTTPException(401, "wrong password")
    try:
        _users.totp_set(ident.user_id, ident.key, req.secret_base32)
    except _users.UserError as e:
        raise HTTPException(409, str(e))
    audit("user:totp_enabled", ip=_client_ip(request))
    return {"ok": True, "enabled": True}


@router.post("/api/me/totp/disable")
async def me_totp_disable(req: UserTotpDisable, request: Request, _: str = Depends(require_unlocked)):
    ident = _me_user()
    u = _users.by_id(ident.user_id)
    secret = _users.totp_secret(u, ident.key) if u else None
    if not secret:
        raise HTTPException(409, "TOTP is not enabled")
    _guard_attempts(request)
    if not pyotp.TOTP(secret).verify(req.code.strip(), valid_window=1):
        _attempt_failed(request, "user:totp_disable_fail")
        raise HTTPException(401, "wrong TOTP code")
    _users.totp_clear(ident.user_id)
    audit("user:totp_disabled", ip=_client_ip(request))
    return {"ok": True, "enabled": False}


# ─── Folder key rotation (0.30): a new key for the folder after a revocation ─────────────────
@router.post("/api/folders/{fid}/rotate-key")
async def rotate_folder_key(fid: int, request: Request, _: str = Depends(require_unlocked)):
    """Owner only. Generates a new folder key and re-encrypts everything under it: every secret (value,
    login, notes, TOTP seed), the history, the rotation configurations; re-wraps the grants of every
    user and the automation cell. Service tokens and enrolment codes of the folder carry the OLD key
    under a secret the vault does not have (the token itself) — they are revoked and must be
    re-issued; their names are returned so the operator knows what to redeploy."""
    _owner_only()
    with db.get_session() as s:
        f = s.get(db.Folder, fid)
        if not f:
            raise HTTPException(404, "folder not found")
        mk = current_master_key()
        old_key = crypto.decrypt(mk, f.scope_key_enc, f.scope_key_nonce)
        new_key = pysecrets.token_bytes(32)
        n_secrets = 0
        for sec in s.query(db.Secret).filter_by(folder_id=fid).all():
            for enc_attr, nonce_attr in (("value_enc", "value_nonce"), ("notes_enc", "notes_nonce"), ("login_enc", "login_nonce"), ("totp_seed_enc", "totp_seed_nonce")):
                ct = getattr(sec, enc_attr)
                if ct:
                    plain = crypto.decrypt(old_key, ct, getattr(sec, nonce_attr))
                    new_ct, new_nonce = crypto.encrypt(new_key, plain)
                    setattr(sec, enc_attr, new_ct); setattr(sec, nonce_attr, new_nonce)
            rot = s.query(db.Rotation).filter_by(secret_id=sec.id).first()
            if rot:
                rot.config_enc, rot.config_nonce = crypto.encrypt(new_key, crypto.decrypt(old_key, rot.config_enc, rot.config_nonce))
            n_secrets += 1
        n_hist = 0
        for h in s.query(db.SecretHistory).filter_by(folder_id=fid).all():
            try:
                plain = crypto.decrypt(old_key, h.value_enc, h.value_nonce)
            except Exception:
                continue
            h.value_enc, h.value_nonce = crypto.encrypt(new_key, plain); n_hist += 1
        n_grants = 0
        for g in s.query(db.FolderGrant).filter_by(folder_id=fid).all():
            u = s.get(db.User, g.user_id)
            g.folder_key_blob = _users.wrap_for(bytes(u.public_key), new_key); n_grants += 1
        if f.automation_key_enc:
            _rotation.cell_write(f, new_key)
        revoked_tokens = []
        for t in s.query(db.ServiceToken).filter_by(folder_id=fid, revoked=False).all():
            t.revoked = True; revoked_tokens.append(t.name)
        n_enrol = s.query(db.Enrollment).filter_by(folder_id=fid, revoked=False).update({"revoked": True})
        f.scope_key_enc, f.scope_key_nonce = crypto.encrypt(mk, new_key)
        s.commit()
        audit("folder:rotate_key", target=f.name, ip=_client_ip(request), meta={"secrets": n_secrets, "history": n_hist, "grants": n_grants, "tokens_revoked": len(revoked_tokens), "enrollments_revoked": n_enrol})
        _emit("folder:rotate_key", {"folder": f.name, "id": f.id, "tokens_revoked": revoked_tokens})
        for name in revoked_tokens:
            _emit("token:revoke", {"name": name, "reason": "folder key rotated"})
        return {"ok": True, "secrets": n_secrets, "history": n_hist, "grants": n_grants, "tokens_revoked": revoked_tokens, "enrollments_revoked": n_enrol}
