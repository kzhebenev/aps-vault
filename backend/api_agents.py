"""Agent keys (0.41.8): machine access for AI sessions and automation that acts as the owner — without the master
password in an environment variable and without a person at the keyboard.

The owner issues a key in Settings (or through this API); the raw key is shown once. `POST /api/auth/agent` with it
opens an ordinary session whose identity is the owner but marked `agent:<name>`: authz.require_unlocked checks the key
on every request (revoked or expired → the session ends; allowed networks), and authz._AGENT_PATHS is the allow-list of
what such a session may call. The audit log names the agent. The key wraps the master key under the suite's token KDF
of the raw key with a random salt — the database alone opens nothing."""
from __future__ import annotations

import secrets as pysecrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

import crypto
import db
import policy
import sessions
import suite as _suite
from app_core import _client_ip, audit
from authz import _attempt_failed, _guard_attempts, _human_owner_only, require_unlocked
from state import current_master_key, hash_token

router = APIRouter()

PREFIX = "vlt_agent_"


class AgentKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._@:-]+$")
    allowed_cidrs: str = Field(default="", max_length=512)
    expires_days: int | None = Field(default=None, ge=1, le=3650)

    @field_validator("allowed_cidrs")
    @classmethod
    def _cidrs(cls, v: str) -> str:
        policy.parse_cidrs(v)
        return " ".join(v.replace(",", " ").split())


class AgentLogin(BaseModel):
    key: str = Field(min_length=20, max_length=256)


def _view(k: db.AgentKey) -> dict:
    return {"id": k.id, "name": k.name, "allowed_cidrs": k.allowed_cidrs or "", "revoked": bool(k.revoked),
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat() if k.created_at else "", "created_by": k.created_by or "",
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None, "last_ip": k.last_ip or ""}


@router.get("/api/agent-keys")
async def list_agent_keys(_: str = Depends(require_unlocked)):
    _human_owner_only()
    with db.get_session() as s:
        return [_view(k) for k in s.query(db.AgentKey).order_by(db.AgentKey.id).all()]


@router.post("/api/agent-keys")
async def create_agent_key(req: AgentKeyCreate, request: Request, _: str = Depends(require_unlocked)):
    _human_owner_only()
    raw = PREFIX + pysecrets.token_urlsafe(32)
    salt = pysecrets.token_bytes(16)
    enc, nonce = crypto.encrypt(_suite.token_kdf(raw.encode("utf-8"), salt), current_master_key())
    with db.get_session() as s:
        if s.query(db.AgentKey).filter_by(name=req.name).first():
            raise HTTPException(409, "an agent key with this name already exists")
        k = db.AgentKey(name=req.name, key_hash=hash_token(raw), salt=salt, master_key_enc=enc, master_key_nonce=nonce,
                        allowed_cidrs=req.allowed_cidrs,
                        expires_at=db.utcnow() + timedelta(days=req.expires_days) if req.expires_days else None,
                        created_by="master")
        s.add(k); s.commit(); s.refresh(k)
        out = _view(k)
    audit("agent_key:create", target=req.name, ip=_client_ip(request), ua=request.headers.get("user-agent", ""),
          meta={"allowed_cidrs": req.allowed_cidrs, "expires_days": req.expires_days})
    return {**out, "key": raw}


@router.delete("/api/agent-keys/{kid}")
async def revoke_agent_key(kid: int, request: Request, _: str = Depends(require_unlocked)):
    _human_owner_only()
    with db.get_session() as s:
        k = s.get(db.AgentKey, kid)
        if not k:
            raise HTTPException(404, "no such agent key")
        k.revoked = True
        s.commit()
        name = k.name
    ended = sessions.revoke_agent_key(kid)
    audit("agent_key:revoke", target=name, ip=_client_ip(request), meta={"sessions_ended": ended})
    return {"ok": True, "sessions_ended": ended}


@router.post("/api/auth/agent")
async def agent_login(req: AgentLogin, request: Request):
    """Exchange an agent key for a session (cookie + csrf_token, like /api/auth/unlock). Wrong keys count against the
    same attempt limit as the master password."""
    import api_auth                                   # the one place that shapes an unlock response
    _guard_attempts(request)
    ip = _client_ip(request)
    raw = req.key.strip()
    with db.get_session() as s:
        k = s.query(db.AgentKey).filter_by(key_hash=hash_token(raw)).first() if raw.startswith(PREFIX) else None
        if not k or k.revoked or (k.expires_at and k.expires_at.replace(tzinfo=None) < db.utcnow().replace(tzinfo=None)):
            _attempt_failed(request, "auth:agent_fail")
            raise HTTPException(401, "unknown, revoked or expired agent key")
        if k.allowed_cidrs and policy.check(k.allowed_cidrs, "", ip):
            audit("auth:agent_denied", target=k.name, ip=ip, meta={"reason": "network"})
            raise HTTPException(403, "this agent key may not be used from this address")
        try:
            master = crypto.decrypt(_suite.token_kdf(raw.encode("utf-8"), k.salt), k.master_key_enc, k.master_key_nonce)
        except Exception:
            _attempt_failed(request, "auth:agent_fail")
            raise HTTPException(401, "unknown, revoked or expired agent key")
        k.last_used_at, k.last_ip = db.utcnow(), ip[:64]
        s.commit()
        kid, name = k.id, k.name
    csrf_token = pysecrets.token_urlsafe(32)
    sid = sessions.issue(master, csrf_token, ip=ip, agent_key_id=kid)
    audit("auth:agent", target=name, actor=f"agent:{name}", ip=ip, ua=request.headers.get("user-agent", ""))
    return api_auth._session_cookies(sid, csrf_token)
