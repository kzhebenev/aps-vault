"""Read approvals and one-time share links.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

from __future__ import annotations

import json
import secrets as pysecrets
import urllib.parse
import urllib.request
from datetime import timedelta

from fastapi import (Depends, HTTPException, Query, Request)
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import crypto
import db
import netutil
import settings as cfgmod
import siem
from state import current_identity, hash_token
import users as _users

from app_core import _client_ip, _get_or_create_folder_key, app, audit, logger  # noqa: F401
from authz import _require_role, _wipe_spent_keys, require_unlocked  # noqa: F401
from webhooks import _emit, _outbound_scheme_ok, _webhook_target_allowed  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

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
    if not _outbound_scheme_ok(st.approval_notify_url) or not _webhook_target_allowed(st.approval_notify_url):
        logger.warning("approval notify: URL not allowed (plain http or a private target without VAULT_WEBHOOK_ALLOW_PRIVATE?)")
        return False
    def q(v: str) -> str:   # placeholders are substituted as JSON-safe strings
        return json.dumps(v, ensure_ascii=False)[1:-1]
    body = st.approval_notify_body
    for k, v in (("text", text), ("url", url), ("secret", secret), ("reason", reason), ("requester_ip", requester_ip)):
        body = body.replace("{" + k + "}", q(v))
    headers = {"Content-Type": "application/json", **st.approval_notify_headers}
    try:
        req = urllib.request.Request(st.approval_notify_url, data=body.encode("utf-8"), method=st.approval_notify_method, headers=headers)
        with netutil.urlopen_noredirect(req, timeout=8) as r:
            return 200 <= r.status < 300
    except Exception as e:
        logger.warning("approval notify failed: %s", e.__class__.__name__)
        return False


def _notify_event(text: str, *, kind: str = "", token: str = "", ip: str = "") -> bool:
    """Token-watch alerts go through the same HTTP receiver as approval requests
    (VAULT_APPROVAL_NOTIFY_URL / _HEADERS / _BODY / _METHOD): {text}, {url} = the Tokens page,
    {reason} = the anomaly kind, {secret} = the token name, {requester_ip} = the source address."""
    st = cfgmod.SETTINGS
    if not st.approval_notify_url:
        return False
    return _notify_approver(text, f"{st.public_url}/#/tokens", token, kind, ip)


class ApproverSet(BaseModel):
    master_password: str
    approver_password: str = Field(min_length=12, max_length=256)


class ApprovalRequest(BaseModel):
    reason: str = Field(default="", max_length=512)


class ApprovalDecision(BaseModel):
    approver_password: str
    decision: str = Field(pattern="^(approve|deny)$")


@router.get("/api/approvals/settings")
async def approvals_settings(_: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    return {"approver_set": bool(cfg.approver_hash), "notify_configured": bool(cfgmod.SETTINGS.approval_notify_url),
            "request_ttl_min": APPROVAL_REQUEST_TTL_MIN, "ticket_min": APPROVAL_TICKET_MIN}


@router.post("/api/approvals/approver")
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


@router.delete("/api/approvals/approver")
async def approvals_clear_approver(request: Request, _: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    cfg.approver_hash = ""
    crypto.save_config(cfg)
    audit("approval:approver_cleared", ip=_client_ip(request))
    return {"ok": True, "approver_set": False}


@router.get("/api/approvals")
async def approvals_list(limit: int = Query(default=50, le=200), _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.Approval, db.Secret, db.Folder).join(db.Secret, db.Approval.secret_id == db.Secret.id).join(db.Folder, db.Secret.folder_id == db.Folder.id)\
            .order_by(db.Approval.created_at.desc()).limit(limit).all()
        return [_approval_item(a, f"{f.name}/{sec.name}") for a, sec, f in rows]


@router.post("/api/secrets/{sid}/approvals")
async def approval_request(sid: int, req: ApprovalRequest, request: Request, session_id: str = Depends(require_unlocked)):
    cfg = crypto.load_config()
    if not cfg.approver_hash:
        raise HTTPException(409, "no approver is configured (Settings → Approvals)")
    ip = _client_ip(request)
    with db.get_session() as s:
        sec = s.get(db.Secret, sid)
        if not sec:
            raise HTTPException(404, "secret not found")
        _require_role(sec.folder_id, "reader")
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


@router.get("/api/approvals/{aid}")
async def approval_status(aid: int, session_id: str = Depends(require_unlocked)):
    with db.get_session() as s:
        a = s.get(db.Approval, aid)
        if not a or a.requester_sid_hash != hash_token(session_id):
            raise HTTPException(404, "approval not found")
        sec = s.get(db.Secret, a.secret_id); f = s.get(db.Folder, sec.folder_id) if sec else None
        return _approval_item(a, f"{f.name}/{sec.name}" if sec and f else "?")


@router.get("/api/approve/{token}")
async def approve_info(token: str):
    """Public (the approver has no session): what is being asked, nothing about the value."""
    with db.get_session() as s:
        a = s.query(db.Approval).filter_by(token_hash=hash_token(token)).first()
        if not a:
            raise HTTPException(404, "approval link not found")
        sec = s.get(db.Secret, a.secret_id); f = s.get(db.Folder, sec.folder_id) if sec else None
        item = _approval_item(a, f"{f.name}/{sec.name}" if sec and f else "(deleted)")
        return {k: item[k] for k in ("secret", "status", "reason", "requester_ip", "created_at", "expires_at", "decided_at")}


@router.post("/api/approve/{token}")
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


@router.post("/api/share/note")
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


@router.post("/api/share")
async def create_share(req: ShareCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        sec = s.get(db.Secret, req.secret_id)
        if not sec:
            raise HTTPException(404, "secret not found")
        if getattr(sec, "machine_only", False):
            raise HTTPException(403, "machine-only secrets cannot be shared with people")
        if getattr(sec, "require_approval", False):
            raise HTTPException(403, "approval-required secrets cannot be shared")
        _require_role(sec.folder_id, "manager")
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


@router.get("/api/share/{token}")
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
        if bool(sec.machine_only) or bool(getattr(sec, "require_approval", False)):
            # 0.37: the flag was set after the link was made — the link stops, as the docs promise
            link.revoked = True; link.folder_key_enc = b""; link.folder_key_nonce = b""; s.commit()
            raise HTTPException(410, "this secret is no longer shareable")
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
        if link.used_count >= link.max_uses:
            link.folder_key_enc = b""; link.folder_key_nonce = b""; s.commit()   # 0.37: a spent link keeps no folder key
        audit("share:read", target=f"share:{sec.name}", actor="unauth", ip=_client_ip(request))
        return {
            "name": sec.name, "value": value.decode("utf-8"), "login": login.decode("utf-8"),
            "uses_left": link.max_uses - link.used_count,
            "expires_at": link.expires_at.isoformat(),
            "note": link.note,
        }


@router.get("/api/shares")
async def list_shares(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        _wipe_spent_keys(s)
    ident = current_identity()
    managed = None if ident.kind == "owner" else {fid for fid, r in _users.grants_of(ident.user_id).items() if r == "manager"}
    with db.get_session() as s:
        rows = s.query(db.ShareLink, db.Secret).join(db.Secret).order_by(db.ShareLink.created_at.desc()).limit(100).all()
        if managed is not None:
            rows = [(l, sec) for l, sec in rows if l.folder_id in managed]
        out = [{
            "id": l.id, "kind": "secret", "secret_name": sec.name, "secret_id": sec.id,
            "created_at": l.created_at.isoformat() if l.created_at else "",
            "expires_at": l.expires_at.isoformat() if l.expires_at else "",
            "max_uses": l.max_uses, "used_count": l.used_count,
            "revoked": l.revoked, "note": l.note,
        } for l, sec in rows]
        for n in (s.query(db.NoteShare).order_by(db.NoteShare.created_at.desc()).limit(100).all() if managed is None else []):
            out.append({"id": n.id, "kind": "note", "secret_name": n.title or "note", "secret_id": None,
                        "created_at": n.created_at.isoformat() if n.created_at else "", "expires_at": n.expires_at.isoformat() if n.expires_at else "",
                        "max_uses": n.max_uses, "used_count": n.used_count, "revoked": n.revoked, "note": n.note})
        out.sort(key=lambda x: x["created_at"], reverse=True)
        return out[:100]


@router.delete("/api/shares/note/{nid}")
async def revoke_note_share(nid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        n = s.get(db.NoteShare, nid)
        if not n:
            raise HTTPException(404, "not found")
        if current_identity().kind != "owner":
            raise HTTPException(403, "note links are managed by the owner")
        n.revoked = True; s.commit()
        audit("share:revoke", target=f"note:{n.title or n.id}", ip=_client_ip(request))
        return {"ok": True}


@router.delete("/api/shares/{sid}")
async def revoke_share(sid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        l = s.get(db.ShareLink, sid)
        if not l:
            raise HTTPException(404, "not found")
        _require_role(l.folder_id, "manager")
        l.revoked = True
        l.folder_key_enc = b""; l.folder_key_nonce = b""        # 0.37: nothing to steal from a revoked link
        s.commit()
        audit("share:revoke", target=f"share:{l.id}", ip=_client_ip(request))
        return {"ok": True}
