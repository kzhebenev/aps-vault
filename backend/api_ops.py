"""The audit log, encrypted backups to S3, updates by the agent, Prometheus metrics and lock-outs.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

from __future__ import annotations

import json

from fastapi import (Depends, Header, HTTPException, Query, Request)
from fastapi.responses import Response
from pydantic import BaseModel, Field

import crypto
import db
import metrics
import netutil
import sessions
import settings as cfgmod
import updates
import backup
import sealed
import siem
import suite as _suite_mod

from app_core import NODE, _client_ip, app, audit, logger, secrets_compare  # noqa: F401
from authz import _attempt_failed, _guard_attempts, _owner_only, require_unlocked  # noqa: F401
from version import VERSION  # noqa: F401
from webhooks import _emit  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

# ─── Endpoints: audit ─────────────────────────────────────────────────────────
@router.get("/api/audit")
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


# ─── Endpoints: encrypted backups to S3 (0.39) ──────────────────────────────
class BackupConfig(BaseModel):
    enabled: bool | None = None
    include_env: bool | None = None                 # 0.40: the VAULT_* / OIDC_* environment in the backup
    mode: str | None = Field(default=None, pattern="^(change|hourly|daily)$")


class BackupKey(BaseModel):
    public_key: str = Field(min_length=40, max_length=2048)
    master_password: str = Field(min_length=1, max_length=256)


class BackupKeygen(BaseModel):
    kind: str = Field(default="", pattern="^(|pqc|gost-pqc|x25519|gost)$")
    master_password: str = Field(min_length=1, max_length=256)


def _backup_emit(r: dict) -> None:
    """A scheduled run finished: audit it; a failure is also a webhook event (someone must look)."""
    audit(f"backup:{r['state']}", target=r["object_key"] or r["reason"], actor="backup", meta={"reason": r["reason"], "size": r["size"], "error": r["error"][:200]})
    if r["state"] == "failed":
        _emit("backup:failed", {"reason": r["reason"], "error": r["error"][:200], "node": r["node"]})


def _backup_password(req_pw: str, request: Request, action: str) -> None:
    _guard_attempts(request)
    if not crypto.verify_master_password(req_pw, crypto.load_config()):
        _attempt_failed(request, f"backup:{action}_fail")
        raise HTTPException(401, "wrong master password")


@router.get("/api/backup/status")
async def backup_status(_: str = Depends(require_unlocked)):
    _owner_only()
    return backup.status()


@router.put("/api/backup/config")
async def backup_config(req: BackupConfig, request: Request, _: str = Depends(require_unlocked)):
    _owner_only()
    with db.get_session() as s:
        st = backup.state_row(s)
        if req.enabled is not None:
            if req.enabled and not st.recipient_pk:
                raise HTTPException(409, "set the backup key first — a backup without a recipient cannot be encrypted")
            if req.enabled and backup.s3_missing():
                raise HTTPException(409, "S3 is not configured: " + ", ".join(backup.s3_missing()))
            st.enabled = req.enabled
        if req.mode is not None:
            st.mode = req.mode
        if req.include_env is not None:
            st.include_env = req.include_env
            st.state_hash = ""                       # the next tick uploads with / without the settings
        s.commit()
        audit("backup:config", ip=_client_ip(request), meta={"enabled": bool(st.enabled), "mode": st.mode, "include_env": st.include_env is not False})
    return backup.status()


@router.put("/api/backup/key")
async def backup_set_key(req: BackupKey, request: Request, _: str = Depends(require_unlocked)):
    """Whoever sets the recipient decides who can read every future backup — the master password again."""
    _owner_only()
    _backup_password(req.master_password, request, "key")
    try:
        k = backup.set_recipient(req.public_key)
    except ValueError as e:
        raise HTTPException(422, str(e))
    audit("backup:key_set", target=k["fingerprint"], ip=_client_ip(request), meta={"kind": k["kind"]})
    return backup.status()


@router.post("/api/backup/keygen")
async def backup_keygen(req: BackupKeygen, request: Request, _: str = Depends(require_unlocked)):
    """Convenience: the server makes a key pair, keeps the public half and returns the private one ONCE. The safer way
    is to make the pair offline (`python -m aps_vault keygen` / docs/BACKUP.md) and paste only the public key."""
    _owner_only()
    _backup_password(req.master_password, request, "keygen")
    kind = req.kind or ("gost-pqc" if _suite_mod.active() == "gost" else "pqc")
    import asyncio
    sk, pk = await asyncio.to_thread(sealed.generate_keypair, kind)
    k = backup.set_recipient(pk)
    audit("backup:keygen", target=k["fingerprint"], ip=_client_ip(request), meta={"kind": kind})
    return {"private_key": sk, "public_key": pk, "fingerprint": k["fingerprint"], "kind": kind,
            "note": "Save the private key now and keep it away from this server — it is not stored and every backup needs it."}


@router.post("/api/backup/run")
async def backup_run_now(request: Request, _: str = Depends(require_unlocked)):
    _owner_only()
    import asyncio
    try:
        r = await asyncio.to_thread(backup.run, "manual")
    except backup.BackupError as e:
        raise HTTPException(409, str(e))
    audit(f"backup:{r['state']}", target=r["object_key"], ip=_client_ip(request), meta={"reason": "manual", "size": r["size"], "error": r["error"][:200]})
    if r["state"] == "failed":
        _emit("backup:failed", {"reason": "manual", "error": r["error"][:200], "node": r["node"]})
    return r


async def _backup_loop() -> None:
    import asyncio
    while True:
        await asyncio.sleep(cfgmod.SETTINGS.backup_tick_sec)
        try:
            await asyncio.get_running_loop().run_in_executor(None, backup.tick, _backup_emit)
        except Exception:
            logger.exception("backup tick failed")


# ─── Endpoints: updates (0.38) ───────────────────────────────────────────────
class UpdateApply(BaseModel):
    version: str = Field(min_length=5, max_length=32)
    master_password: str = Field(min_length=1, max_length=256)


@router.get("/api/update/status")
async def update_status(_: str = Depends(require_unlocked)):
    """Installed version, what the channel offers, release notes and history, the agent and the last job."""
    _owner_only()
    import asyncio
    return await asyncio.to_thread(updates.status)


@router.post("/api/update/check")
async def update_check(request: Request, _: str = Depends(require_unlocked)):
    _owner_only()
    import asyncio
    if not cfgmod.SETTINGS.update_channel:
        raise HTTPException(409, "the update channel is off (VAULT_UPDATE_CHANNEL=off)")
    await asyncio.to_thread(updates.check, True)
    audit("update:check", ip=_client_ip(request))
    return await asyncio.to_thread(updates.status)


@router.post("/api/update/apply")
async def update_apply(req: UpdateApply, request: Request, _: str = Depends(require_unlocked)):
    """The owner asks the agent to update the installation. The master password is asked again: an open session alone
    must not be enough to restart the vault on another version."""
    _owner_only()
    _guard_attempts(request)
    if not crypto.verify_master_password(req.master_password, crypto.load_config()):
        _attempt_failed(request, "update:apply_fail")
        raise HTTPException(401, "wrong master password")
    import asyncio
    try:
        job = await asyncio.to_thread(updates.request, req.version, "master")
    except updates.UpdateError as e:
        raise HTTPException(e.status, str(e))
    audit("update:requested", target=job["target_version"], ip=_client_ip(request), meta={"from": job["from_version"], "job": job["id"]})
    return job


@router.post("/api/update/jobs/{jid}/cancel")
async def update_cancel(jid: int, request: Request, _: str = Depends(require_unlocked)):
    _owner_only()
    try:
        job = updates.cancel(jid)
    except updates.UpdateError as e:
        raise HTTPException(409, str(e))
    audit("update:cancelled", target=job["target_version"], ip=_client_ip(request), meta={"job": jid})
    return job


def _agent_auth(request: Request, authorization: str | None) -> None:
    ip = _client_ip(request)
    if netutil.is_locked(ip):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    raw = (authorization or "").partition(" ")[2].strip() if (authorization or "").lower().startswith("bearer ") else ""
    if not updates.agent_token_ok(raw):
        n = netutil.record_fail(ip)
        audit("update:agent_denied", ip=ip, meta={"attempts": n, "configured": bool(cfgmod.SETTINGS.update_agent_token)})
        raise HTTPException(401, "invalid agent token" if cfgmod.SETTINGS.update_agent_token else "the update agent is not enabled (VAULT_UPDATE_AGENT_TOKEN)")


class AgentReport(BaseModel):
    state: str = Field(pattern="^(running|done|failed)$")
    step: str = Field(default="", max_length=64)
    log: str = Field(default="", max_length=20000)


@router.get("/api/agent/update")
async def agent_poll(request: Request, agent_id: str = "", mode: str = "", agent_version: str = "", current: str = "", verify: str = "",
                     host: str = "", authorization: str | None = Header(default=None)):
    """The agent's heartbeat; answers with a job to carry out, if the owner requested one."""
    _agent_auth(request, authorization)
    if not agent_id or len(agent_id) > 64:
        raise HTTPException(422, "agent_id is required")
    updates.agent_seen(agent_id, mode, agent_version, current, verify, host)
    for lost in updates.settle_abandoned(agent_id, current):      # 0.41.4: a job its agent dropped no longer blocks updates
        audit(f"update:{lost['state']}", target=lost["target_version"], actor=f"agent:{agent_id}", meta={"job": lost["id"], "step": lost["step"]})
        _emit(f"update:{lost['state']}", {"job": lost["id"], "from": lost["from_version"], "to": lost["target_version"], "step": lost["step"]})
    job = updates.pick(agent_id)
    if job:
        audit("update:picked", target=job["target_version"], actor=f"agent:{agent_id}", meta={"job": job["id"]})
    return {"job": job}


@router.post("/api/agent/update/{jid}")
async def agent_report(jid: int, req: AgentReport, request: Request, agent_id: str = "", authorization: str | None = Header(default=None)):
    _agent_auth(request, authorization)
    try:
        job = updates.report(jid, agent_id, req.state, req.step, req.log)
    except updates.UpdateError as e:
        raise HTTPException(409, str(e))
    if req.state in ("done", "failed"):
        audit(f"update:{req.state}", target=job["target_version"], actor=f"agent:{agent_id}", meta={"job": jid, "step": req.step})
        _emit(f"update:{req.state}", {"job": jid, "from": job["from_version"], "to": job["target_version"], "step": req.step})
    return job


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


@router.get("/metrics")
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
    with db.get_session() as s:
        alerts_open = s.query(db.TokenAlert).filter(db.TokenAlert.acknowledged == False).count()   # noqa: E712
    body = metrics.render(VERSION, sessions.active_count(), secrets_n, folders_n, tokens_n, locked_n,
                          siem.sent, siem.errors, node=NODE, token_alerts_open=alerts_open)
    return Response(body, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/api/security/lockdowns")
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
