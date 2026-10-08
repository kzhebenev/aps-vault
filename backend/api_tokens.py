"""Service tokens, token watch (alerts, freezing, trusted networks, leak check) and node enrolment.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import json
import secrets as pysecrets
from datetime import timedelta

from fastapi import (Depends, HTTPException, Query, Request)
from pydantic import BaseModel, Field

import crypto
import db
from sqlalchemy import func
import netutil
import policy
import settings as cfgmod
from pydantic import field_validator
from state import current_identity, hash_token
import suite as _suite_mod
import users as _users
import watch as _watch

from app_core import _client_ip, _get_or_create_folder_key, app, audit  # noqa: F401
from authz import _owner_only_if_flagged, _require_role, _wipe_spent_keys, require_unlocked  # noqa: F401
from webhooks import _emit  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

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
    client_public_key: str = Field(default="", max_length=2048)      # 0.27: the hybrid key is 1216 bytes → 1624 base64 chars
    # token watch (0.26): a canary trips on any use; on_anomaly = alert | freeze
    canary: bool = False
    on_anomaly: str = "alert"

    @field_validator("on_anomaly")
    @classmethod
    def _on_anomaly(cls, v: str) -> str:
        v = (v or "alert").strip().lower()
        if v not in ("alert", "freeze"):
            raise ValueError("on_anomaly must be alert or freeze")
        return v

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



# ─── Token watch (0.26): alerts, freeze / unfreeze, trusted networks, leak check ──────


def _token_for_manager(s, tid: int):
    t = s.get(db.ServiceToken, tid)
    if not t:
        raise HTTPException(404, "token not found")
    _require_role(t.folder_id, "manager")
    return t


def _managed_folder_ids():
    """None for the owner; the folders a user manages otherwise."""
    ident = current_identity()
    if ident.kind == "owner":
        return None
    return {fid for fid, r in _users.grants_of(ident.user_id).items() if r == "manager"}


@router.get("/api/tokens/alerts")
async def list_token_alerts(include_acknowledged: int = Query(default=0), limit: int = Query(default=200, le=1000), _: str = Depends(require_unlocked)):
    managed = _managed_folder_ids()
    with db.get_session() as s:
        q = s.query(db.TokenAlert, db.ServiceToken, db.Folder).join(db.ServiceToken, db.ServiceToken.id == db.TokenAlert.token_id)\
            .join(db.Folder, db.Folder.id == db.ServiceToken.folder_id)
        if not include_acknowledged:
            q = q.filter(db.TokenAlert.acknowledged == False, db.ServiceToken.revoked == False)   # noqa: E712
        rows = q.order_by(db.TokenAlert.last_at.desc()).limit(limit).all()
        return [_watch.alert_to_dict(a, t, f.name) for a, t, f in rows if managed is None or t.folder_id in managed]


@router.post("/api/tokens/alerts/{aid}/ack")
async def ack_token_alert(aid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        a = s.get(db.TokenAlert, aid)
        if not a:
            raise HTTPException(404, "alert not found")
        t = _token_for_manager(s, a.token_id)
        a.acknowledged = True
        s.commit()
        audit("token:alert_ack", target=t.name, ip=_client_ip(request), meta={"alert_id": aid, "kind": a.kind})
        return {"ok": True}


@router.get("/api/tokens/{tid}/profile")
async def token_profile(tid: int, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        _token_for_manager(s, tid)
        return _watch.profile_to_dict(s.get(db.TokenProfile, tid))


class TokenPatch(BaseModel):
    on_anomaly: str | None = None

    @field_validator("on_anomaly")
    @classmethod
    def _oa(cls, v):
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ("alert", "freeze"):
            raise ValueError("on_anomaly must be alert or freeze")
        return v


@router.patch("/api/tokens/{tid}")
async def patch_token(tid: int, req: TokenPatch, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        t = _token_for_manager(s, tid)
        if req.on_anomaly is not None:
            t.on_anomaly = req.on_anomaly
        s.commit()
        audit("token:update", target=t.name, ip=_client_ip(request), meta={"on_anomaly": t.on_anomaly})
        return {"ok": True, "on_anomaly": t.on_anomaly}


@router.post("/api/tokens/{tid}/freeze")
async def freeze_token(tid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        t = _token_for_manager(s, tid)
        t.frozen, t.frozen_reason = True, "manual"
        s.commit()
        audit("token:freeze", target=t.name, ip=_client_ip(request))
        _emit("token:freeze", {"name": t.name, "id": t.id, "reason": "manual"})
        return {"ok": True}


@router.post("/api/tokens/{tid}/unfreeze")
async def unfreeze_token(tid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        t = _token_for_manager(s, tid)
        t.frozen, t.frozen_reason = False, ""
        s.commit()
        audit("token:unfreeze", target=t.name, ip=_client_ip(request))
        _emit("token:unfreeze", {"name": t.name, "id": t.id})
        return {"ok": True}


class TrustNetwork(BaseModel):
    network: str = Field(min_length=1, max_length=64)


@router.post("/api/tokens/{tid}/trust-network")
async def trust_token_network(tid: int, req: TrustNetwork, request: Request, _: str = Depends(require_unlocked)):
    """A new office, a new CI runner: mark the network as expected — its open alerts are acknowledged
    and it no longer counts as new or as the "other place" of a parallel-use alert."""
    with db.get_session() as s:
        t = _token_for_manager(s, tid)
        if not _watch.trust_network(s, tid, req.network):
            raise HTTPException(422, "network must be an address or CIDR, e.g. 203.0.113.0/24")
        net = _watch.normalize_network(req.network)
        s.query(db.TokenAlert).filter(db.TokenAlert.token_id == tid, db.TokenAlert.network == net, db.TokenAlert.acknowledged == False).update({"acknowledged": True})   # noqa: E712
        s.commit()
        audit("token:trust_network", target=t.name, ip=_client_ip(request), meta={"network": net})
        return {"ok": True, "network": net}


class LeakCheck(BaseModel):
    hashes: list[str] = Field(min_length=1, max_length=5000)
    revoke: bool = False

    @field_validator("hashes")
    @classmethod
    def _hex(cls, v):
        import re
        bad = [h for h in v if not re.fullmatch(r"[0-9a-fA-F]{64}", h or "")]
        if bad:
            raise ValueError("hashes must be 64 hex characters each (the vault's token hash: SHA-256 in the aes suite, Streebog-256 in gost)")
        return [h.lower() for h in v]


@router.post("/api/tokens/leak-check")
async def leak_check(req: LeakCheck, request: Request, _: str = Depends(require_unlocked)):
    """Owner: which of these token hashes belong to live tokens. A scanner (ops/leak-scan.py) finds
    `vlt_…` strings in repositories, logs or chats, hashes them and asks here — the plaintext never
    travels. `revoke: true` revokes the matches on the spot."""
    if current_identity().kind != "owner":
        raise HTTPException(403, "this action belongs to the vault owner (master password)")
    with db.get_session() as s:
        rows = s.query(db.ServiceToken, db.Folder).join(db.Folder).filter(db.ServiceToken.token_hash.in_(req.hashes)).all()
        found = [{"hash": t.token_hash, "token_id": t.id, "name": t.name, "folder_name": f.name, "revoked": bool(t.revoked),
                  "last_used": t.last_used.isoformat() if t.last_used else None} for t, f in rows]
        revoked_now = []
        if req.revoke:
            for t, f in rows:
                if not t.revoked:
                    t.revoked = True; revoked_now.append((t.id, t.name))
                    s.query(db.TokenAlert).filter(db.TokenAlert.token_id == t.id, db.TokenAlert.acknowledged == False).update({"acknowledged": True})   # noqa: E712
            s.commit()
    # audited after the commit (SQLite: one writer at a time)
    for tid, name in revoked_now:
        audit("token:revoke", target=name, ip=_client_ip(request), meta={"reason": "leak-check"})
        _emit("token:revoke", {"name": name, "id": tid, "reason": "leak"})
    audit("token:leak_check", ip=_client_ip(request), meta={"checked": len(req.hashes), "found": len(found), "revoked": len(revoked_now)})
    return {"checked": len(req.hashes), "found": found, "revoked": len(revoked_now)}


@router.get("/api/tokens")
async def list_tokens(_: str = Depends(require_unlocked)):
    ident = current_identity()
    managed = None if ident.kind == "owner" else {fid for fid, r in _users.grants_of(ident.user_id).items() if r == "manager"}
    with db.get_session() as s:
        rows = s.query(db.ServiceToken, db.Folder).join(db.Folder).order_by(db.ServiceToken.name).all()
        if managed is not None:
            rows = [(t, f) for t, f in rows if t.folder_id in managed]
        open_alerts = dict(s.query(db.TokenAlert.token_id, func.count(db.TokenAlert.id)).filter(db.TokenAlert.acknowledged == False).group_by(db.TokenAlert.token_id).all())   # noqa: E712
        uses = dict(s.query(db.TokenProfile.token_id, db.TokenProfile.uses).all())
        return [{
            "canary": bool(getattr(t, "canary", False)), "on_anomaly": getattr(t, "on_anomaly", "alert") or "alert",
            "frozen": bool(getattr(t, "frozen", False)), "frozen_reason": getattr(t, "frozen_reason", "") or "",
            "alerts_open": open_alerts.get(t.id, 0), "uses": uses.get(t.id, 0),
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


def _issue_token(s, f, folder_key: bytes, name: str, opts: dict, client_public_key: str = "", created_by: str | None = None):
    """Create a service token row for folder `f`: the folder key is re-encrypted under the
    suite's token KDF of the fresh random token (Argon2id light / KDF_TREE), salted by the
    folder nonce. Shared by the human endpoint and node enrolment (0.21). Returns (row, raw)."""
    import suite as _suite
    raw = crypto.gen_service_token()
    token_key = _suite.token_kdf(raw.encode("utf-8"), f.scope_key_nonce[:16] + b"\x00" * (16 - min(16, len(f.scope_key_nonce))))
    fk_enc, fk_nonce = crypto.encrypt(token_key, folder_key)
    expires_at = db.utcnow() + timedelta(days=int(opts["expires_days"])) if opts.get("expires_days") else None
    t = db.ServiceToken(
        name=name, token_hash=hash_token(raw), folder_id=f.id, folder_key_enc=fk_enc, folder_key_nonce=fk_nonce,
        can_read_notes=bool(opts.get("can_read_notes")), can_read_totp=bool(opts.get("can_read_totp")), can_write=bool(opts.get("can_write")),
        allowed_cidrs=opts.get("allowed_cidrs", "") or "", allowed_hours=opts.get("allowed_hours", "") or "",
        allowed_cert_fingerprints=opts.get("allowed_cert_fingerprints", "") or "", client_public_key=client_public_key or "",
        expires_at=expires_at,
        canary=bool(opts.get("canary")), on_anomaly=opts.get("on_anomaly") or "alert",
        created_by=created_by if created_by is not None else current_identity().actor,
    )
    s.add(t); s.commit(); s.refresh(t)
    return t, raw


# ─── Node enrolment (v0.21): a one-time code → the node makes its key pair → sealed token ───
class EnrollmentCreate(BaseModel):
    folder_id: int
    name_prefix: str = Field(default="node", min_length=1, max_length=64)
    ttl_minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)
    max_uses: int = Field(default=1, ge=1, le=500)
    expires_days: int | None = None                  # of the issued tokens
    can_read_notes: bool = False
    can_read_totp: bool = False
    # 0.30.1: a node that must write (a BFF that migrates its own keys into the vault) gets
    # can_write from the code; default stays read-only, as before.
    can_write: bool = False
    allowed_cidrs: str = Field(default="", max_length=512)
    allowed_hours: str = Field(default="", max_length=256)

    @field_validator("allowed_cidrs")
    @classmethod
    def _cidrs(cls, v: str) -> str:
        policy.parse_cidrs(v)
        return " ".join(v.replace(",", " ").split())

    @field_validator("allowed_hours")
    @classmethod
    def _hours(cls, v: str) -> str:
        policy.parse_hours(v)
        return v.strip()


class EnrollRequest(BaseModel):
    code: str = Field(min_length=10, max_length=128)
    public_key: str = Field(min_length=40, max_length=2048)      # the node's X25519 (32 B), GOST (64 B), P-256 (65 B) or hybrid (1216 B) public key, base64
    name: str = Field(default="", max_length=64)                  # host name; the token becomes "<prefix>-<name>"

    @field_validator("public_key")
    @classmethod
    def _pk(cls, v: str) -> str:
        import sealed
        return sealed.normalize_public_key(v)


def _enroll_key(code: str) -> bytes:
    import suite as _suite
    return _suite.token_kdf(code.encode("utf-8"), _suite.digest(("enroll:" + code).encode("utf-8"))[:16])


@router.post("/api/enrollments")
async def create_enrollment(req: EnrollmentCreate, request: Request, _: str = Depends(require_unlocked)):
    """Owner or folder manager: a code a node presents once to receive a sealed token for this
    folder — nobody copies tokens by hand. The folder key travels inside the code (encrypted
    under KDF(code)), so enrolment needs no human session."""
    _require_role(req.folder_id, "manager")
    with db.get_session() as s:
        f = s.get(db.Folder, req.folder_id)
        if not f:
            raise HTTPException(404, "folder not found")
        _owner_only_if_flagged(s, f.id)
        _wipe_spent_keys(s)
        folder_key = _get_or_create_folder_key(s, f.id)
        code = "enr_" + pysecrets.token_urlsafe(24)
        fk_enc, fk_nonce = crypto.encrypt(_enroll_key(code), folder_key)
        opts = {k: getattr(req, k) for k in ("expires_days", "can_read_notes", "can_read_totp", "can_write", "allowed_cidrs", "allowed_hours")}
        e = db.Enrollment(code_hash=hash_token(code), folder_id=f.id, name_prefix=req.name_prefix.strip(), folder_key_enc=fk_enc, folder_key_nonce=fk_nonce,
                          options=json.dumps(opts), max_uses=req.max_uses, created_by=current_identity().actor,
                          expires_at=(db.utcnow() + timedelta(minutes=req.ttl_minutes)).replace(tzinfo=None))
        s.add(e); s.commit(); s.refresh(e)
        audit("enroll:create", target=f"{f.name}:{req.name_prefix}", ip=_client_ip(request), meta={"max_uses": req.max_uses, "ttl_min": req.ttl_minutes})
        return {"id": e.id, "code": code, "folder_name": f.name, "expires_at": e.expires_at.isoformat(), "max_uses": e.max_uses,
                "command": f"python3 -m aps_vault enroll {cfgmod.SETTINGS.public_url or '<vault-url>'} {code}",
                "note": "The code is shown once. Each node runs the enrol command: it makes its own key pair and gets a sealed token."}


@router.get("/api/enrollments")
async def list_enrollments(_: str = Depends(require_unlocked)):
    ident = current_identity()
    managed = None if ident.kind == "owner" else {fid for fid, r in _users.grants_of(ident.user_id).items() if r == "manager"}
    with db.get_session() as s:
        rows = s.query(db.Enrollment, db.Folder).join(db.Folder, db.Folder.id == db.Enrollment.folder_id).order_by(db.Enrollment.created_at.desc()).limit(100).all()
        now = db.utcnow().replace(tzinfo=None)
        return [{"id": e.id, "folder_id": e.folder_id, "folder_name": f.name, "name_prefix": e.name_prefix, "max_uses": e.max_uses, "used_count": e.used_count,
                 "created_by": e.created_by, "created_at": e.created_at.isoformat() if e.created_at else "", "expires_at": e.expires_at.isoformat(),
                 "revoked": bool(e.revoked), "active": not e.revoked and e.expires_at > now and e.used_count < e.max_uses,
                 "options": json.loads(e.options or "{}")}
                for e, f in rows if managed is None or e.folder_id in managed]


@router.delete("/api/enrollments/{eid}")
async def revoke_enrollment(eid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        e = s.get(db.Enrollment, eid)
        if not e:
            raise HTTPException(404, "not found")
        _require_role(e.folder_id, "manager")
        e.revoked = True; e.folder_key_enc = b""; e.folder_key_nonce = b""; s.commit()
        audit("enroll:revoke", target=str(eid), ip=_client_ip(request))
        return {"ok": True}


@router.post("/api/enroll")
async def enroll_node(req: EnrollRequest, request: Request):
    """Public: the node presents the code and its public key and receives a token sealed to that
    key. Wrong or spent codes count towards the IP's failed-attempt budget."""
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    with db.get_session() as s:
        e = s.query(db.Enrollment).filter_by(code_hash=hash_token(req.code)).first()
        now = db.utcnow().replace(tzinfo=None)
        if not e or e.revoked or e.expires_at <= now:
            netutil.record_fail(ip); audit("enroll:fail", actor="unauth", ip=ip, meta={"reason": "unknown, revoked or expired"})
            raise HTTPException(404, "enrolment code is unknown, revoked or expired")
        opts = json.loads(e.options or "{}")
        if opts.get("allowed_cidrs") and policy.check(opts["allowed_cidrs"], "", ip):
            netutil.record_fail(ip); audit("enroll:fail", actor="unauth", ip=ip, meta={"reason": "source address"})
            raise HTTPException(403, "enrolment is not allowed from this address")
        from sqlalchemy import text as _text
        consumed = s.execute(_text("UPDATE enrollments SET used_count = used_count + 1 WHERE id = :id AND used_count < max_uses AND NOT revoked"), {"id": e.id}).rowcount
        if not consumed:
            s.commit(); netutil.record_fail(ip); audit("enroll:fail", actor="unauth", ip=ip, meta={"reason": "spent"})
            raise HTTPException(410, "enrolment code has been used up")
        try:
            folder_key = crypto.decrypt(_enroll_key(req.code), e.folder_key_enc, e.folder_key_nonce)
        except Exception:
            s.commit(); raise HTTPException(500, "enrolment record does not open — re-create the code")
        f = s.get(db.Folder, e.folder_id)
        base = f"{e.name_prefix}-{(req.name or 'node').strip()[:40]}".strip("-") or "node"
        name, n = base, 2
        while s.query(db.ServiceToken).filter_by(name=name).first():
            name = f"{base}-{n}"; n += 1
        t, raw = _issue_token(s, f, folder_key, name, opts, req.public_key, created_by=e.created_by or "")
        netutil.clear_fails(ip)
        audit("enroll:issue", target=f"{f.name}:{name}", actor="unauth", ip=ip, ua=request.headers.get("user-agent", ""), meta={"enrollment": e.id, "sealed": True})
        _emit("token:create", {"folder": f.name, "name": name, "id": t.id})
        return {"raw_token": raw, "token_name": name, "folder_name": f.name, "sealed": True, "cipher": _suite_mod.active(),
                "vault_url": cfgmod.SETTINGS.public_url or "", "note": "Store the token and your private key with mode 0600; the token alone opens nothing."}


@router.post("/api/tokens")
async def create_token(req: TokenCreate, request: Request, _: str = Depends(require_unlocked)):
    _require_role(req.folder_id, "manager")
    with db.get_session() as s:
        f = s.get(db.Folder, req.folder_id)
        if not f:
            raise HTTPException(404, "folder not found")
        _owner_only_if_flagged(s, f.id)
        if s.query(db.ServiceToken).filter_by(name=req.name).first():
            # names are unique across the vault and revoked tokens keep theirs (audit rows point at them)
            raise HTTPException(409, f"a token named '{req.name}' already exists (revoked tokens keep their names) — choose another name")
        folder_key = _get_or_create_folder_key(s, f.id)
        t, raw = _issue_token(s, f, folder_key, req.name, req.model_dump(), req.client_public_key)
        audit("token:create", target=f"{f.name}:{req.name}", ip=_client_ip(request), meta={"sealed": True} if req.client_public_key else None)
        _emit("token:create", {"folder": f.name, "name": req.name, "id": t.id})
        return {
            "id": t.id, "name": t.name, "folder_name": f.name,
            "raw_token": raw, "sealed": bool(req.client_public_key),
            "note": "SAVE THIS TOKEN NOW — it is not shown again.",
        }


@router.delete("/api/tokens/{tid}")
async def revoke_token(tid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        t = s.get(db.ServiceToken, tid)
        if not t:
            raise HTTPException(404, "token not found")
        _require_role(t.folder_id, "manager")
        t.revoked = True
        # a revoked token is a closed incident: its open watch alerts are acknowledged with it
        s.query(db.TokenAlert).filter(db.TokenAlert.token_id == t.id, db.TokenAlert.acknowledged == False).update({"acknowledged": True})   # noqa: E712
        s.commit()
        audit("token:revoke", target=t.name, ip=_client_ip(request))
        _emit("token:revoke", {"name": t.name, "id": t.id})
        return {"ok": True}
