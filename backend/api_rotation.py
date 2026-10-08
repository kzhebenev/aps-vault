"""Rotation in target systems (PostgreSQL, MySQL, LDAP, SSH, HTTP) and its scheduler.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import secrets as pysecrets
import time
import urllib.parse
import urllib.request

from fastapi import (Depends, HTTPException, Path as FPath,
                     Request)
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
import pyotp
from argon2 import PasswordHasher

import crypto
import db
import netutil
import sessions
import settings as cfgmod
import siem
from pydantic import field_validator
from state import STATE, current_identity
import rotation as _rotation
import webauthn_auth

from api_auth import _hsm_rewrap, _kms_rewrap, _read_2fa_secret  # noqa: F401
from app_core import CSRF_COOKIE, SESSION_COOKIE, _client_ip, _dec_with_folder, _enc_with_folder, _get_or_create_folder_key, app, archive_value, audit, generate_value, logger  # noqa: F401
from authz import _require_role, _visible_folder_ids, require_unlocked  # noqa: F401
from version import VERSION  # noqa: F401
from webhooks import _emit, _webhook_target_allowed  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

# ─── Rotation in target systems (0.24) ────────────────────────────────────────
class RotationSet(BaseModel):
    target: str
    config: dict = Field(default_factory=dict)
    interval_days: int = Field(default=0, ge=0, le=3650)
    generate: str | None = None
    enabled: bool = True

    @field_validator("generate")
    @classmethod
    def _gen(cls, v):
        if v is not None:
            generate_value(v)
        return v


def _drop_cell_if_unused(session, folder) -> None:
    """Least privilege: the automation cell lives only while a scheduled rotation needs the folder."""
    if folder is None or not folder.automation_key_enc:
        return
    n = session.query(db.Rotation).join(db.Secret, db.Secret.id == db.Rotation.secret_id).filter(
        db.Secret.folder_id == folder.id, db.Rotation.enabled == True, db.Rotation.interval_days > 0).count()
    if n == 0 and not _folder_is_dsn_source(session, folder.id):
        _rotation.cell_drop(folder)


def _folder_is_dsn_source(session, folder_id: int) -> bool:
    """Cheap check, no decryption: is any secret of this folder possibly an administrator DSN of a
    postgres rotation? True when postgres rotations exist at all — their configs are encrypted,
    so the cell of a DSN folder is kept until the last postgres rotation is gone."""
    return session.query(db.Rotation).filter(db.Rotation.target.in_(_rotation.ADMIN_TARGETS), db.Rotation.enabled == True,
                                             db.Rotation.interval_days > 0).count() > 0


def _rotation_rows(session):
    vis = _visible_folder_ids()
    rows = session.query(db.Rotation, db.Secret, db.Folder).join(db.Secret, db.Secret.id == db.Rotation.secret_id)\
        .join(db.Folder, db.Folder.id == db.Secret.folder_id).order_by(db.Folder.name, db.Secret.name).all()
    return [r for r in rows if vis is None or r[2].id in vis]


@router.get("/api/rotations/status")
async def rotation_status(_: str = Depends(require_unlocked)):
    """Is the scheduler able to run: server key present, how many rotations are scheduled, due,
    failing, and which folders still lack an automation cell (saved before the key existed)."""
    with db.get_session() as s:
        rows = _rotation_rows(s)
        now = _rotation.now_naive()
        scheduled = [r for r, _, _ in rows if r.enabled and (r.interval_days or 0) > 0]
        missing = sorted({f.name for r, _, f in rows if r.enabled and (r.interval_days or 0) > 0 and not f.automation_key_enc})
        return {"configured": _rotation.configured(), "tick_sec": cfgmod.SETTINGS.rotation_tick_sec,
                "total": len(rows), "scheduled": len(scheduled),
                "due": sum(1 for r in scheduled if r.next_at and r.next_at <= now),
                "failing": sum(1 for r, _, _ in rows if r.last_status == "err"),
                "cells_missing": missing}


@router.get("/api/rotations")
async def list_rotations(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        return [_rotation.to_dict(r, sec.name, f.name, f.id) for r, sec, f in _rotation_rows(s)]


@router.get("/api/secrets/{sid}/rotation")
async def get_rotation(sid: int, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "manager")
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first()
        if not rot:
            raise HTTPException(404, "no rotation on this secret")
        f = s.get(db.Folder, sec.folder_id)
        cfg = _rotation.decode_config(_dec_with_folder(s, sec.folder_id, rot.config_enc, rot.config_nonce))
        return _rotation.to_dict(rot, sec.name, f.name, f.id, include_config=_rotation.public_config(rot.target, cfg))


@router.put("/api/secrets/{sid}/rotation")
async def set_rotation(sid: int, req: RotationSet, request: Request, _: str = Depends(require_unlocked)):
    """Create or change the rotation of a secret (folder manager or the owner). The configuration
    is validated here — a postgres target must name an existing DSN secret the caller may read, an
    http receiver must be https and outside private networks unless allowed — and stored encrypted
    under the folder key. With an interval and the server key present, the automation cells of the
    secret's folder (and of the DSN secret's folder) are written so the scheduler can work alone."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "manager")
        f = s.get(db.Folder, sec.folder_id)
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first()
        previous = _rotation.decode_config(_dec_with_folder(s, sec.folder_id, rot.config_enc, rot.config_nonce)) if rot and rot.target == req.target else None
        try:
            cfg = _rotation.validate_config(req.target, req.config, dev=cfgmod.SETTINGS.dev, allow_private=cfgmod.SETTINGS.webhook_allow_private,
                                            target_allowed=_webhook_target_allowed, previous=previous)
        except ValueError as e:
            raise HTTPException(422, str(e))
        dsn_folder = None
        ident = current_identity()
        if req.target in _rotation.ADMIN_TARGETS:
            # 0.37: an administrator credential (DSN / bind / SSH admin) lets the vault change ANY account in the target;
            # which account it changes is the owner's decision — a manager could point it at postgres / root / cn=admin
            if ident.kind != "owner" or ident.agent:          # 0.41.9: the owner in person, not an agent key
                raise HTTPException(403, "rotation through an administrator credential is configured by the owner")
            dsn_sec = s.get(db.Secret, cfg["dsn_secret_id"])
            if not dsn_sec:
                raise HTTPException(422, "dsn_secret_id: no such secret")
            dsn_folder = s.get(db.Folder, dsn_sec.folder_id)
            # bind the target account NOW: an empty role means "the secret's current login", frozen into the config,
            # so changing the login later (a writer can) does not retarget the rotation
            if not cfg.get("role"):
                cur_login = _dec_with_folder(s, sec.folder_id, sec.login_enc, sec.login_nonce).decode("utf-8") if sec.login_enc else ""
                if not cur_login:
                    raise HTTPException(422, "no account to rotate: set the secret's login or the rotation's role")
                cfg["role"] = cur_login
        elif bool(sec.machine_only) or bool(getattr(sec, "require_approval", False)):
            if ident.kind != "owner" or ident.agent:          # 0.41.9: an agent key must not open this way out either
                # an http receiver gets the NEW value in the request body — for a flagged secret that is a way out
                raise HTTPException(403, "an http receiver for a 'machines only' / 'requires approval' secret is configured by the owner")
        created = rot is None
        if created:
            rot = db.Rotation(secret_id=sid, target=req.target, config_enc=b"", config_nonce=b"", created_by=current_identity().actor)
            s.add(rot)
        interval_changed = created or (rot.interval_days or 0) != req.interval_days or rot.target != req.target or not rot.enabled and req.enabled
        rot.target = req.target
        rot.config_enc, rot.config_nonce = _enc_with_folder(s, sec.folder_id, _rotation.encode_config(cfg))
        rot.generate = req.generate or _rotation.GENERATE_DEFAULT[req.target]
        rot.interval_days = req.interval_days
        rot.enabled = req.enabled
        if not req.enabled or req.interval_days == 0:
            rot.next_at = None
        elif interval_changed or rot.next_at is None:
            rot.next_at = _rotation.next_after(req.interval_days)
        cells = 0
        if req.enabled and req.interval_days > 0:
            if _rotation.cell_write(f, _get_or_create_folder_key(s, f.id)):
                cells += 1
            if dsn_folder is not None and dsn_folder.id != f.id and _rotation.cell_write(dsn_folder, _get_or_create_folder_key(s, dsn_folder.id)):
                cells += 1
        else:
            _drop_cell_if_unused(s, f)
        s.commit(); s.refresh(rot)
        audit("rotation:set", target=f"{f.name}/{sec.name}", ip=_client_ip(request),
              meta={"target": req.target, "interval_days": req.interval_days, "enabled": req.enabled, "created": created})
        out = _rotation.to_dict(rot, sec.name, f.name, f.id, include_config=_rotation.public_config(req.target, cfg))
        out["scheduler"] = "active" if _rotation.configured() else ("unavailable: VAULT_ROTATION_KEY is not set — this rotation runs by hand only" if req.interval_days > 0 else "manual")
        out["cells_written"] = cells
        if req.target == "http" and not (previous or {}).get("signing_secret"):
            out["signing_secret"] = cfg["signing_secret"]       # shown once: the receiver verifies X-Vault-Signature with it
        return out


@router.delete("/api/secrets/{sid}/rotation")
async def delete_rotation(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "manager")
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first()
        if not rot:
            raise HTTPException(404, "no rotation on this secret")
        f = s.get(db.Folder, sec.folder_id)
        s.delete(rot); s.flush()
        _drop_cell_if_unused(s, f)
        if not _folder_is_dsn_source(s, 0):      # no postgres rotations left anywhere → DSN folders need no cell
            for other in s.query(db.Folder).filter(db.Folder.automation_key_enc != b"").all():
                _drop_cell_if_unused(s, other)
        s.commit()
        audit("rotation:delete", target=f"{f.name}/{sec.name}", ip=_client_ip(request))
        return {"ok": True}


def _run_rotation(s, rot, sec, folder_key: bytes, actor: str, key_for_folder, ip: str = "") -> dict:
    """generate → apply in the target → verify → store. Raises RotationError when the target did
    not take the value; the vault then still holds the old one and nothing has been archived."""
    f = s.get(db.Folder, sec.folder_id)
    cfg = _rotation.decode_config(crypto.decrypt(folder_key, rot.config_enc, rot.config_nonce))
    new_value = generate_value(rot.generate or _rotation.GENERATE_DEFAULT.get(rot.target, "base64:32"))
    old_value = crypto.decrypt(folder_key, sec.value_enc, sec.value_nonce).decode("utf-8") if sec.value_enc else None
    login = crypto.decrypt(folder_key, sec.login_enc, sec.login_nonce).decode("utf-8") if sec.login_enc else ""
    role = cfg.get("role") or (login if rot.target not in _rotation.ADMIN_TARGETS else "")   # 0.37: admin targets use the bound role only
    admin_dsn, admin_login = None, ""
    if rot.target in _rotation.ADMIN_TARGETS:
        dsn_sec = s.get(db.Secret, cfg.get("dsn_secret_id"))
        if not dsn_sec:
            raise _rotation.RotationError("the administrator DSN secret no longer exists")
        dkey = folder_key if dsn_sec.folder_id == sec.folder_id else key_for_folder(dsn_sec.folder_id)
        if dkey is None:
            raise _rotation.RotationError("no key for the folder of the administrator DSN secret (automation cell missing)")
        admin_dsn = crypto.decrypt(dkey, dsn_sec.value_enc, dsn_sec.value_nonce).decode("utf-8")
        admin_login = crypto.decrypt(dkey, dsn_sec.login_enc, dsn_sec.login_nonce).decode("utf-8") if dsn_sec.login_enc else ""
    if rot.target == "http" and not _webhook_target_allowed(cfg.get("url", "")):
        raise _rotation.RotationError("receiver address is no longer allowed (DNS now points into a private network?)")
    note = _rotation.apply(rot.target, cfg, role=role, new_value=new_value, old_value=old_value, admin_dsn=admin_dsn,
                           admin_login=admin_login, secret_name=sec.name, folder_name=f.name, version=(sec.version or 1) + 1)
    archive_value(s, sec, f"{actor}:rotate")
    sec.value_enc, sec.value_nonce = crypto.encrypt(folder_key, new_value.encode("utf-8"))
    sec.updated_at = db.utcnow()
    now = _rotation.now_naive()
    rot.last_at, rot.last_status, rot.last_error, rot.runs = now, "ok", "", (rot.runs or 0) + 1
    rot.next_at = _rotation.next_after(rot.interval_days, now) if rot.enabled else None
    s.commit()
    audit("rotation:run", target=f"{f.name}/{sec.name}", actor=actor, ip=ip, meta={"target": rot.target, "version": sec.version, "note": note})
    _emit("secret:update", {"folder": f.name, "name": sec.name, "id": sec.id, "rotated": True, "target": rot.target, "version": sec.version})
    return {"ok": True, "version": sec.version, "previous_version": sec.version - 1, "note": note}


def _rotation_failed(s, rot, sec, err, actor: str, ip: str = "") -> None:
    f = s.get(db.Folder, sec.folder_id)
    rot.last_at, rot.last_status, rot.last_error = _rotation.now_naive(), "err", str(err)[:256]
    s.commit()
    audit("rotation:fail", target=f"{f.name}/{sec.name}", actor=actor, ip=ip, meta={"target": rot.target, "error": str(err)[:200]})
    _emit("rotation:fail", {"folder": f.name, "name": sec.name, "id": sec.id, "target": rot.target, "error": str(err)[:200]})


@router.post("/api/secrets/{sid}/rotation/run")
async def run_rotation_now(sid: int, request: Request, _: str = Depends(require_unlocked)):
    """Rotate in the target right now with the caller's key (writer or the owner). A folder the
    caller cannot read (the DSN secret's) is opened through its automation cell when one exists."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "writer")
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first()
        if not rot:
            raise HTTPException(404, "no rotation on this secret")
        key = _get_or_create_folder_key(s, sec.folder_id)

        def key_for(fid: int):
            try:
                return _get_or_create_folder_key(s, fid)
            except HTTPException:
                return _rotation.cell_open(s.get(db.Folder, fid))
        import asyncio, contextvars
        loop = asyncio.get_running_loop()
        actor, ip = current_identity().actor, _client_ip(request)
        try:
            # the worker thread needs the request's identity (folder keys of a user come from their grants)
            return await loop.run_in_executor(None, contextvars.copy_context().run, lambda: _run_rotation(s, rot, sec, key, actor, key_for, ip))
        except _rotation.RotationError as e:
            _rotation_failed(s, rot, sec, e, actor, ip)
            raise HTTPException(502, f"rotation failed, the vault keeps the previous value: {e}")


@router.post("/api/rotations/cells")
async def write_rotation_cells(request: Request, _: str = Depends(require_unlocked)):
    """Owner: (re)write the automation cells of every folder a scheduled rotation needs — after
    VAULT_ROTATION_KEY was added or changed on the server."""
    if current_identity().kind != "owner":
        raise HTTPException(403, "this action belongs to the vault owner (master password)")
    if not _rotation.configured():
        raise HTTPException(409, "VAULT_ROTATION_KEY is not set on this server — the scheduler cannot run")
    with db.get_session() as s:
        written = set()
        for rot, sec, f in _rotation_rows(s):
            if not (rot.enabled and (rot.interval_days or 0) > 0):
                continue
            _rotation.cell_write(f, _get_or_create_folder_key(s, f.id)); written.add(f.id)
            if rot.target in _rotation.ADMIN_TARGETS:
                cfg = _rotation.decode_config(_dec_with_folder(s, f.id, rot.config_enc, rot.config_nonce))
                dsn_sec = s.get(db.Secret, cfg.get("dsn_secret_id"))
                if dsn_sec and dsn_sec.folder_id not in written:
                    df = s.get(db.Folder, dsn_sec.folder_id)
                    _rotation.cell_write(df, _get_or_create_folder_key(s, df.id)); written.add(df.id)
        s.commit()
        audit("rotation:cells", ip=_client_ip(request), meta={"folders": len(written)})
        return {"ok": True, "folders": len(written)}


def _rotation_tick_sync() -> int:
    """One pass of the scheduler: claim due rotations (one conditional UPDATE each, so replicas
    never collide) and run them with the folders' automation cells. Returns the number rotated."""
    if not _rotation.configured():
        return 0
    with db.get_session() as s:
        ids = _rotation.claim_due(s)
    done = 0
    for rid in ids:
        with db.get_session() as s:
            rot = s.get(db.Rotation, rid)
            sec = s.get(db.Secret, rot.secret_id) if rot else None
            if not rot or not sec:
                continue
            key = _rotation.cell_open(s.get(db.Folder, sec.folder_id))
            try:
                if key is None:
                    raise _rotation.RotationError("automation cell missing on the folder — save the rotation again, or the owner presses “write cells”")
                _run_rotation(s, rot, sec, key, "scheduler", lambda fid: _rotation.cell_open(s.get(db.Folder, fid)))
                done += 1
            except _rotation.RotationError as e:
                _rotation_failed(s, rot, sec, e, "scheduler")
            except Exception as e:                      # a bug must not kill the loop or hide the row's state
                logger.exception("rotation %s crashed", rid)
                _rotation_failed(s, rot, sec, f"internal error: {str(e)[:150]}", "scheduler")
    return done


async def _rotation_loop() -> None:
    import asyncio
    tick = cfgmod.SETTINGS.rotation_tick_sec
    while True:
        await asyncio.sleep(tick)
        try:
            n = await asyncio.get_running_loop().run_in_executor(None, _rotation_tick_sync)
            if n:
                logger.info("rotation scheduler: %d rotated", n)
        except Exception:
            logger.exception("rotation tick failed")


@router.get("/api/secrets/{sid}/totp")
async def secret_totp(sid: int, _: str = Depends(require_unlocked)):
    """Current TOTP code with its remaining lifetime — for the live countdown in the UI.
    Deliberately does not bump access_count or write a `secret:read` audit row: the read was
    audited when the secret was opened; refreshing the code every 30 s is not a new access."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "reader")
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


@router.get("/api/tools/hibp/{prefix}")
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
        with netutil.urlopen_noredirect(req, timeout=6) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception as e:
        raise HTTPException(503, f"leak database unreachable: {e.__class__.__name__}")
    return Response(body, media_type="text/plain")


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = None


@router.post("/api/auth/change-password")
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
