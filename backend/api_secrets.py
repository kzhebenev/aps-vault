"""Folders and secrets: CRUD, favourites, history, stats, JSON export/import and import from other managers.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import secrets as pysecrets
from datetime import datetime, timezone

from fastapi import (Depends, HTTPException, Query, Request)
from pydantic import BaseModel, Field
import pyotp

import crypto
import db
from pydantic import field_validator
from state import current_identity, current_master_key
import users as _users
import rotation as _rotation
import importers as _importers
from fastapi import File, Form, UploadFile

from api_rotation import _drop_cell_if_unused  # noqa: F401
from api_sharing import _approval_gate  # noqa: F401
from app_core import FolderCreate, SecretCreate, SecretUpdate, _client_ip, _dec_with_folder, _enc_with_folder, _get_or_create_folder_key, _parse_expires, app, archive_value, audit, generate_value  # noqa: F401
from authz import _attempt_failed, _guard_attempts, _require_role, _visible_folder_ids, require_unlocked  # noqa: F401
from webhooks import _emit, _webhook_target_allowed  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

# ─── Endpoints: folders ───────────────────────────────────────────────────────
@router.get("/api/folders")
async def list_folders(_: str = Depends(require_unlocked)):
    vis = _visible_folder_ids()
    with db.get_session() as s:
        rows = s.query(db.Folder).order_by(db.Folder.name).all()
        return [{"id": f.id, "name": f.name, "description": f.description,
                 "created_at": f.created_at.isoformat() if f.created_at else "",
                 **({"role": _users.grants_of(current_identity().user_id).get(f.id)} if vis is not None else {})}
                for f in rows if vis is None or f.id in vis]


@router.post("/api/folders")
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


@router.delete("/api/folders/{fid}")
async def delete_folder(fid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        f = s.get(db.Folder, fid)
        if not f:
            raise HTTPException(404, "folder not found")
        n = s.query(db.Secret).filter_by(folder_id=fid).count()
        if n > 0:
            raise HTTPException(400, f"folder still has {n} secrets — delete them first")
        # 0.33: the folder's service tokens go with it — they cannot work without the folder, and a revoked
        # token left behind kept the folder referenced (PostgreSQL refused the delete with a foreign-key error).
        # Their watch rows (profiles, alerts) go too: SQLite does not cascade.
        tok_ids = [t.id for t in s.query(db.ServiceToken.id).filter_by(folder_id=fid).all()]
        if tok_ids:
            s.query(db.TokenAlert).filter(db.TokenAlert.token_id.in_(tok_ids)).delete(synchronize_session=False)
            s.query(db.TokenProfile).filter(db.TokenProfile.token_id.in_(tok_ids)).delete(synchronize_session=False)
            s.query(db.ServiceToken).filter(db.ServiceToken.id.in_(tok_ids)).delete(synchronize_session=False)
        # 0.30: rows that referenced the folder must not survive it (SQLite does not cascade and reuses ids)
        s.query(db.FolderGrant).filter_by(folder_id=fid).delete()
        s.query(db.Enrollment).filter_by(folder_id=fid).delete()
        s.query(db.SecretHistory).filter_by(folder_id=fid).delete()
        s.delete(f)
        s.commit()
        audit("folder:delete", target=f.name, ip=_client_ip(request), meta={"tokens": len(tok_ids)} if tok_ids else None)
        return {"ok": True, "tokens_deleted": len(tok_ids)}


# ─── Endpoints: secrets ───────────────────────────────────────────────────────
def _secret_to_list_item(sec: db.Secret, folder_name: str, rot=None) -> dict:
    return {
        "rotation": _rotation.to_dict(rot) if rot is not None else None,     # 0.24: target, schedule, last result
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


@router.get("/api/secrets")
async def list_secrets(
    folder_id: int | None = Query(default=None),
    q: str | None = Query(default=None),
    _: str = Depends(require_unlocked),
):
    vis = _visible_folder_ids()
    with db.get_session() as s:
        query = s.query(db.Secret, db.Folder).join(db.Folder)
        if vis is not None:
            query = query.filter(db.Secret.folder_id.in_(vis or [-1]))
        if folder_id is not None:
            query = query.filter(db.Secret.folder_id == folder_id)
        if q:
            like = f"%{q}%"
            query = query.filter((db.Secret.name.ilike(like)) | (db.Secret.tags.ilike(like)) | (db.Secret.url.ilike(like)))
        rows = query.order_by(db.Folder.name, db.Secret.name).all()
        rots = {r.secret_id: r for r in s.query(db.Rotation).filter(db.Rotation.secret_id.in_([sec.id for sec, _ in rows])).all()} if rows else {}
        return [_secret_to_list_item(sec, f.name, rots.get(sec.id)) for sec, f in rows]


@router.post("/api/secrets")
async def create_secret(req: SecretCreate, request: Request, _: str = Depends(require_unlocked)):
    _require_role(req.folder_id, "writer")
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


@router.get("/api/secrets/{sid}")
async def get_secret(sid: int, request: Request, approval: int | None = Query(default=None), sid_cookie: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "reader")
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
        item = _secret_to_list_item(sec, f.name, s.query(db.Rotation).filter_by(secret_id=sec.id).first())
        item.update({
            "value": value.decode("utf-8"), "value_hidden": hidden,
            "login": login.decode("utf-8") if login else "",
            "notes": notes.decode("utf-8") if notes else "",
            "totp": totp_code,
        })
        return item


@router.patch("/api/secrets/{sid}")
async def update_secret(sid: int, req: SecretUpdate, request: Request,
                        _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "writer")
        if req.folder_id is not None and req.folder_id != sec.folder_id:
            _require_role(req.folder_id, "writer")
        if req.name is not None:
            sec.name = req.name
        if req.value is not None:
            # history — the previous value is kept (encrypted under the same folder key), numbered
            archive_value(s, sec, current_identity().actor)
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
        clearing = ((req.require_approval is False and bool(getattr(sec, "require_approval", False)))
                    or (req.machine_only is False and bool(sec.machine_only)))
        if clearing:
            # 0.37: a flag that keeps people away from the value is lifted by the owner, with the master password —
            # a writer used to PATCH it off and read the value at once (the two-person rule was one request deep)
            if current_identity().kind != "owner":
                raise HTTPException(403, "only the owner can lift 'requires approval' / 'machines only'")
            _guard_attempts(request)
            if not crypto.verify_master_password(req.master_password or "", crypto.load_config()):
                _attempt_failed(request, "secret:flag_clear_fail")
                raise HTTPException(401, "lifting a protection flag needs the master password")
        if req.require_approval is not None and req.require_approval != bool(getattr(sec, "require_approval", False)):
            sec.require_approval = req.require_approval
            flag_action = "secret:approval_on" if req.require_approval else "secret:approval_off"
            hide_action = hide_action or flag_action
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
            # 0.24: the rotation configuration is encrypted under the folder key too
            rot_row = s.query(db.Rotation).filter_by(secret_id=sec.id).first()
            if rot_row:
                plain = _dec_with_folder(s, sec.folder_id, rot_row.config_enc, rot_row.config_nonce)
                rot_row.config_enc, rot_row.config_nonce = _enc_with_folder(s, req.folder_id, plain)
                if rot_row.enabled and rot_row.interval_days > 0:
                    _rotation.cell_write(s.get(db.Folder, req.folder_id), _get_or_create_folder_key(s, req.folder_id))
            old_folder = s.get(db.Folder, sec.folder_id)
            sec.folder_id = req.folder_id
            s.flush()
            _drop_cell_if_unused(s, old_folder)
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


@router.delete("/api/secrets/{sid}")
async def delete_secret(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "writer")
        f = s.get(db.Folder, sec.folder_id)
        name = sec.name
        # explicit cleanup: SQLite does not enforce ON DELETE CASCADE, and it reuses a freed id — without this a
        # new secret could inherit a deleted one's history rows (found by test_folder_key_rotation, 0.30)
        s.query(db.Rotation).filter_by(secret_id=sec.id).delete()
        s.query(db.SecretHistory).filter_by(secret_id=sec.id).delete()
        s.delete(sec)
        s.flush()
        _drop_cell_if_unused(s, f)
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


@router.post("/api/secrets/{sid}/rotate")
async def rotate_secret(sid: int, req: RotateRequest, request: Request, _: str = Depends(require_unlocked)):
    """Replace the value with a fresh server-generated one; the old value becomes the previous
    version (readable by machines through `?version=N` while they re-wrap their data). The
    administrator never sees either value — made for machine-only key material."""
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "writer")
        archive_value(s, sec, current_identity().actor + ":rotate")
        sec.value_enc, sec.value_nonce = _enc_with_folder(s, sec.folder_id, generate_value(req.generate).encode("utf-8"))
        sec.updated_at = db.utcnow()
        s.commit()
        f = s.get(db.Folder, sec.folder_id)
        audit("secret:rotate", target=f"{f.name}/{sec.name}", ip=_client_ip(request), meta={"version": sec.version, "generate": req.generate})
        _emit("secret:update", {"folder": f.name, "name": sec.name, "id": sec.id, "rotated": True})
        return {"ok": True, "version": sec.version, "previous_version": sec.version - 1}


# ─── Endpoints: favorites (v0.3) ──────────────────────────────────────────────
@router.post("/api/secrets/{sid}/favorite")
async def toggle_favorite(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "not found")
        _require_role(sec.folder_id, "reader")
        sec.is_favorite = not bool(getattr(sec, "is_favorite", False))
        s.commit()
        return {"id": sec.id, "is_favorite": sec.is_favorite}


# ─── Endpoints: secret history (v0.3) ────────────────────────────────────────
@router.get("/api/secrets/{sid}/history")
async def get_secret_history(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "not found")
        _require_role(sec.folder_id, "reader")
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


# ─── Endpoints: stats (v0.3) ──────────────────────────────────────────────────
@router.get("/api/stats")
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
@router.get("/api/export")
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
    on_conflict: str = "skip"           # 0.29: skip | version (archive the old value, write the new) | rename ("name (2)")

    @field_validator("on_conflict")
    @classmethod
    def _oc(cls, v):
        v = (v or "skip").strip().lower()
        if v not in ("skip", "version", "rename"):
            raise ValueError("on_conflict must be skip, version or rename")
        return v


# ─── Import from other managers (0.29): parse → preview → POST /api/import ──────


@router.post("/api/import/parse")
async def import_parse(request: Request, file: UploadFile = File(...), format: str = Form("auto"), into_folder: str = Form(""),
                       prefix: str = Form(""), password: str = Form(""), keyfile: UploadFile | None = File(None), _: str = Depends(require_unlocked)):
    """Turn an export of another manager (Bitwarden, KeePass XML, 1Password CSV/1PUX, LastPass CSV, any CSV,
    .env, this vault's JSON) into the vault's import payload — for the preview. Nothing is stored; the UI
    sends the payload to POST /api/import when the administrator confirms."""
    if current_identity().kind != "owner":
        raise HTTPException(403, "import belongs to the vault owner (master password)")
    data = await file.read(_importers.MAX_BYTES + 1)
    kf = await keyfile.read(1024 * 1024) if keyfile is not None else None       # 0.35: KDBX key file (optional)
    try:
        # the KDBX key derivation (Argon2) is CPU-bound: off the event loop
        import asyncio
        res = await asyncio.get_running_loop().run_in_executor(None, lambda: _importers.parse(
            (format or "auto").strip().lower(), file.filename or "", data, into_folder=into_folder or None, prefix=prefix or "", password=password or "", keyfile=kf))
    except _importers.ImportError_ as e:
        raise HTTPException(422, str(e))
    audit("import:parse", target=f"{res['format']}: {res['stats']['secrets']} secrets", ip=_client_ip(request), meta={"filename": (file.filename or "")[:120], **res["stats"]})
    return res


class HashicorpImport(BaseModel):
    addr: str = Field(min_length=8, max_length=512)
    token: str = Field(min_length=1, max_length=512)
    mount: str = Field(min_length=1, max_length=128)
    path: str = Field(default="", max_length=512)
    into_folder: str = Field(default="", max_length=128)


@router.post("/api/import/hashicorp")
async def import_hashicorp(req: HashicorpImport, request: Request, _: str = Depends(require_unlocked)):
    """Pull a KV v2 mount of a HashiCorp Vault / Deckhouse Stronghold into the import payload (preview).
    The source token is used for the calls and forgotten. The address must be reachable from the vault and
    passes the same guard as webhooks (private networks need VAULT_WEBHOOK_ALLOW_PRIVATE=1)."""
    if current_identity().kind != "owner":
        raise HTTPException(403, "import belongs to the vault owner (master password)")
    addr = req.addr.strip().rstrip("/")
    if not (addr.startswith("https://") or addr.startswith("http://")):
        raise HTTPException(422, "addr must start with http:// or https://")
    if not _webhook_target_allowed(addr):
        raise HTTPException(422, "source address not allowed: private, loopback or unresolvable (VAULT_WEBHOOK_ALLOW_PRIVATE=1 permits private networks)")
    import asyncio
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, lambda: _importers.pull_hashicorp(addr, req.token, req.mount, req.path, into_folder=req.into_folder or None))
    except _importers.ImportError_ as e:
        raise HTTPException(422, str(e))
    audit("import:parse", target=f"hashicorp {req.mount}: {res['stats']['secrets']} secrets", ip=_client_ip(request), meta={"addr": addr[:120], "mount": req.mount, **res["stats"]})
    return res


class PassworkImport(BaseModel):
    host: str = Field(min_length=8, max_length=512)
    token: str = Field(min_length=1, max_length=4096)
    master_password: str = Field(default="", max_length=512)
    master_key: str = Field(default="", max_length=1024)
    vault_id: str = Field(default="", max_length=128)
    into_folder: str = Field(default="", max_length=128)


@router.post("/api/import/passwork")
async def import_passwork(req: PassworkImport, request: Request, _: str = Depends(require_unlocked)):
    """Pull a Passwork (7+, API v1) instance into the import payload (preview): vaults → folders → items,
    decrypted here when the instance uses client-side encryption (master password or master key). Token and
    master password are used for the calls and forgotten."""
    if current_identity().kind != "owner":
        raise HTTPException(403, "import belongs to the vault owner (master password)")
    host = req.host.strip().rstrip("/")
    if not (host.startswith("https://") or host.startswith("http://")):
        raise HTTPException(422, "host must start with http:// or https://")
    if not _webhook_target_allowed(host):
        raise HTTPException(422, "source address not allowed: private, loopback or unresolvable (VAULT_WEBHOOK_ALLOW_PRIVATE=1 permits private networks)")
    import asyncio
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, lambda: _importers.pull_passwork(host, req.token, master_password=req.master_password, master_key=req.master_key,
                                                                               vault_id=req.vault_id, into_folder=req.into_folder or None))
    except _importers.ImportError_ as e:
        raise HTTPException(422, str(e))
    audit("import:parse", target=f"passwork: {res['stats']['secrets']} secrets", ip=_client_ip(request), meta={"host": host[:120], "encrypted": bool(req.master_password or req.master_key), **res["stats"]})
    return res

@router.post("/api/import")
async def import_json(payload: ImportPayload, request: Request, _: str = Depends(require_unlocked)):
    n_secrets = 0; n_folders = 0; n_skip = 0; n_updated = 0
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
            existing = {sec.name: sec for sec in s.query(db.Secret).filter_by(folder_id=folder.id)}
            existing_names = set(existing)
            for sd in fld.get("secrets", []):
                name = sd.get("name", "")
                if not name: continue
                if sd.get("value") is None:
                    n_skip += 1; continue      # a machine-only secret exported without its value
                if name in existing_names:
                    if payload.on_conflict == "version":
                        old = existing[name]
                        archive_value(s, old, current_identity().actor + ":import")
                        old.value_enc, old.value_nonce = _enc_with_folder(s, folder.id, (sd.get("value", "") or "").encode("utf-8"))
                        if sd.get("login"):
                            old.login_enc, old.login_nonce = _enc_with_folder(s, folder.id, sd["login"].encode("utf-8"))
                        if sd.get("notes"):
                            old.notes_enc, old.notes_nonce = _enc_with_folder(s, folder.id, sd["notes"].encode("utf-8"))
                        if sd.get("totp_seed"):
                            old.totp_seed_enc, old.totp_seed_nonce = _enc_with_folder(s, folder.id, sd["totp_seed"].encode("utf-8"))
                        if sd.get("url"):
                            old.url = sd["url"]
                        old.updated_at = db.utcnow()
                        n_updated += 1
                        continue
                    if payload.on_conflict == "rename":
                        k = 2
                        while f"{name} ({k})" in existing_names:
                            k += 1
                        name = f"{name} ({k})"
                    else:
                        n_skip += 1; continue
                existing_names.add(name)
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
              ip=_client_ip(request), meta={"updated": n_updated, "skipped": n_skip, "on_conflict": payload.on_conflict})
    return {"created_secrets": n_secrets, "created_folders": n_folders, "skipped": n_skip, "updated": n_updated}
