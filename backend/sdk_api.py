"""
APS Vault — Machine API (для интеграций с другими сервисами).

URL: /api/v1/m/*

Аутентификация: Bearer <service-token> (vlt_…)

Endpoints:
  GET  /api/v1/m/secret/{name}    — получить значение секрета по имени (в scope токена)
  POST /api/v1/m/secret/{name}    — создать/обновить секрет (нужен can_write на токене)
  GET  /api/v1/m/secrets          — список секретов в scope токена (без values)
  GET  /api/v1/m/health           — жив ли machine API + права токена

Логика:
  1. raw token → SHA-256 → look-up в БД (service_tokens)
  2. raw token → Argon2(token, salt из folder.scope_key_nonce) → token_key
  3. decrypt(folder_key_enc, token_key) → folder_key
  4. decrypt(secret value_enc, folder_key) → plaintext

Master-key НЕ требуется. Vault может быть locked — machine API работает независимо
(каждый токен носит свой шифрованный folder_key).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from argon2 import low_level
from fastapi import APIRouter, Depends, Header, HTTPException, Path as FPath, Request
from pydantic import BaseModel, field_validator
import pyotp

import crypto
import db
from state import STATE, hash_token

logger = logging.getLogger("aps-vault-sdk")


def _extract_token(authorization: str | None, x_vault_token: str | None) -> str:
    if x_vault_token:
        return x_vault_token.strip()
    if authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() in {"bearer", "token"}:
            return parts[1].strip()
        return authorization.strip()
    return ""


def _client_ip(request: Request) -> str:
    import netutil
    return netutil.client_ip(request)


def _audit(action: str, target: str, token_id: int, ip: str, ua: str, meta: dict | None = None) -> None:
    import metrics
    import siem
    import json as _json
    with db.get_session() as s:
        s.add(db.AuditLog(
            action=action, target=target, actor=f"token:{token_id}",
            ip=ip[:64], user_agent=ua[:256],
            meta=_json.dumps(meta, ensure_ascii=False) if meta else "",
        ))
        s.commit()
    siem.send(action, actor=f"token:{token_id}", target=target, ip=ip, ua=ua, meta=meta,
              version=getattr(__import__("main"), "VERSION", ""))
    metrics.record(action)


def _validate_token(request: Request,
                    authorization: str | None,
                    x_vault_token: str | None):
    """Возвращает (db_token, folder_key plaintext). HTTPException при ошибках."""
    raw = _extract_token(authorization, x_vault_token)
    if not raw:
        raise HTTPException(401, "service token is missing")
    th = hash_token(raw)
    with db.get_session() as s:
        t = s.query(db.ServiceToken).filter_by(token_hash=th).first()
        if not t:
            ip = _client_ip(request)
            ua = request.headers.get("user-agent", "")
            _audit("m:auth:fail", target="", token_id=0, ip=ip, ua=ua)
            import siem
            siem.security_log("token", ip)
            logger.warning("m: auth failed from %s", ip)
            raise HTTPException(401, "invalid service token")
        if t.revoked:
            raise HTTPException(401, "service token has been revoked")
        if t.expires_at and t.expires_at < db.utcnow():
            raise HTTPException(401, "service token has expired")
        # PAM-style policy on the token: where from and when (policy.py)
        import policy
        ip = _client_ip(request)
        reason = policy.check(getattr(t, "allowed_cidrs", "") or "", getattr(t, "allowed_hours", "") or "", ip)
        if reason:
            _audit("m:auth:policy_denied", target=t.name, token_id=t.id, ip=ip,
                   ua=request.headers.get("user-agent", ""), meta={"reason": reason})
            import siem
            siem.security_log("policy", ip, f"token={t.id}")
            logger.warning("m: policy denied for %s (token %s): %s", ip, t.id, reason)
            raise HTTPException(403, f"access policy: {reason}")
        f = s.get(db.Folder, t.folder_id)
        if not f:
            raise HTTPException(500, "scope folder is gone")
        # Derive token_key (Argon2id, ускоренные параметры — токен сам по себе random 32B)
        token_key = low_level.hash_secret_raw(
            secret=raw.encode("utf-8"),
            salt=f.scope_key_nonce[:16] + b"\x00" * (16 - min(16, len(f.scope_key_nonce))),
            time_cost=2, memory_cost=8 * 1024, parallelism=2, hash_len=32,
            type=low_level.Type.ID,
        )
        try:
            folder_key = crypto.decrypt(token_key, t.folder_key_enc, t.folder_key_nonce)
        except Exception:
            # Не должно случаться, но защитимся: token-key не подошёл к folder_key
            raise HTTPException(500, "envelope decryption failed (corruption?)")
        # Бамп last_used
        t.last_used = db.utcnow()
        s.commit()
        # Возвращаем dataclass-like объект
        return {
            "id": t.id, "name": t.name, "folder_id": t.folder_id, "folder_name": f.name,
            "can_read_notes": t.can_read_notes, "can_read_totp": t.can_read_totp,
            "can_write": bool(getattr(t, "can_write", False)),
        }, folder_key


class SecretPutBody(BaseModel):
    value: str
    login: str = ""   # optional login (user name / e-mail)
    tags: str = ""
    url: str = ""

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("url must start with http:// or https://")
        return v


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/m", tags=["machine-api"])

    @router.get("/health", summary="статус API + scope текущего токена")
    async def health(request: Request,
                     authorization: str | None = Header(default=None),
                     x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, _ = _validate_token(request, authorization, x_vault_token)
        return {
            "status": "ok",
            "token_name": t["name"],
            "scope_folder": t["folder_name"],
            "can_read_notes": t["can_read_notes"],
            "can_read_totp": t["can_read_totp"],
            "server_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    @router.get("/secrets", summary="список секретов в scope (без values)")
    async def list_secrets(request: Request,
                           authorization: str | None = Header(default=None),
                           x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, _ = _validate_token(request, authorization, x_vault_token)
        with db.get_session() as s:
            rows = s.query(db.Secret).filter_by(folder_id=t["folder_id"]).order_by(db.Secret.name).all()
            return [{
                "id": r.id, "name": r.name, "tags": r.tags or "", "url": r.url or "",
                "has_totp": bool(r.totp_seed_enc),
                "has_notes": bool(r.notes_enc),
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
            } for r in rows]

    @router.get("/secret/{name}", summary="расшифрованное значение секрета по имени")
    async def get_secret_by_name(
        request: Request,
        name: str = FPath(..., description="имя секрета в scope-папке"),
        authorization: str | None = Header(default=None),
        x_vault_token: str | None = Header(default=None, alias="X-Vault-Token"),
    ):
        t, folder_key = _validate_token(request, authorization, x_vault_token)
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise HTTPException(404, f"secret '{name}' not found in scope '{t['folder_name']}'")
            value = crypto.decrypt(folder_key, sec.value_enc, sec.value_nonce)
            result = {"name": sec.name, "value": value.decode("utf-8"),
                      "updated_at": sec.updated_at.isoformat() if sec.updated_at else ""}
            # v0.3.2: login отдаём вместе с value — не PII в смысле «секрет»,
            # обычно email/имя пользователя. Не требует отдельного can_read_*.
            if getattr(sec, "login_enc", None):
                login = crypto.decrypt(folder_key, sec.login_enc, sec.login_nonce)
                result["login"] = login.decode("utf-8")
            if t["can_read_notes"] and sec.notes_enc:
                notes = crypto.decrypt(folder_key, sec.notes_enc, sec.notes_nonce)
                result["notes"] = notes.decode("utf-8")
            if t["can_read_totp"] and sec.totp_seed_enc:
                seed = crypto.decrypt(folder_key, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
                try:
                    result["totp"] = pyotp.TOTP(seed.replace(" ", "")).now()
                except Exception:
                    result["totp"] = None
            # Бамп access count
            sec.last_accessed = db.utcnow()
            sec.access_count = (sec.access_count or 0) + 1
            s.commit()
            _audit("m:secret:read", target=f"{t['folder_name']}/{name}",
                   token_id=t["id"], ip=_client_ip(request),
                   ua=request.headers.get("user-agent", ""))
            return result

    @router.post("/secret/{name}", summary="создать/обновить секрет в scope (нужен can_write)")
    async def put_secret_by_name(
        body: SecretPutBody,
        request: Request,
        name: str = FPath(..., description="имя секрета в scope-папке"),
        authorization: str | None = Header(default=None),
        x_vault_token: str | None = Header(default=None, alias="X-Vault-Token"),
    ):
        """v0.3.1: запись через machine API. Криптографически токен всегда мог
        шифровать (несёт folder_key) — ограничение было только интерфейсным.
        Доступ гейтится флагом can_write (по умолчанию выкл у всех токенов).
        Upsert: существующее значение уезжает в SecretHistory (как в human API).
        """
        t, folder_key = _validate_token(request, authorization, x_vault_token)
        if not t["can_write"]:
            raise HTTPException(403, "this service token has no write permission (can_write)")
        if not name or len(name) > 128:
            raise HTTPException(400, "secret name must be 1..128 characters")
        value_enc, value_nonce = crypto.encrypt(folder_key, body.value.encode("utf-8"))
        login_enc, login_nonce = (b"", b"")
        if body.login:
            login_enc, login_nonce = crypto.encrypt(folder_key, body.login.encode("utf-8"))
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            created = sec is None
            if created:
                sec = db.Secret(
                    folder_id=t["folder_id"], name=name,
                    value_enc=value_enc, value_nonce=value_nonce,
                    notes_enc=b"", notes_nonce=b"",
                    login_enc=login_enc, login_nonce=login_nonce,
                    totp_seed_enc=b"", totp_seed_nonce=b"",
                    tags=body.tags, url=body.url,
                )
                s.add(sec)
            else:
                # Старое значение — в историю (паттерн human API PATCH)
                s.add(db.SecretHistory(
                    secret_id=sec.id, folder_id=sec.folder_id,
                    value_enc=sec.value_enc, value_nonce=sec.value_nonce,
                    changed_by=f"token:{t['id']}",
                ))
                sec.value_enc, sec.value_nonce = value_enc, value_nonce
                if body.login:
                    sec.login_enc, sec.login_nonce = login_enc, login_nonce
                if body.tags:
                    sec.tags = body.tags
                if body.url:
                    sec.url = body.url
                sec.updated_at = db.utcnow()
            s.commit()
            s.refresh(sec)
            _audit("m:secret:put", target=f"{t['folder_name']}/{name}",
                   token_id=t["id"], ip=_client_ip(request),
                   ua=request.headers.get("user-agent", ""))
            return {"id": sec.id, "name": name, "created": created}

    return router


# ── HashiCorp KV v2 compatible facade ───────────────────────────────────────
# Lets a service written against HashiCorp Vault (KV v2 read) run unchanged against APS
# Vault — and lets an APS Vault user move to HashiCorp later by changing URL and token only.
# Mount = folder name; the token's scope folder must match. Read-only.


def build_kv_router() -> APIRouter:
    """`/v1/<mount>/data/<name>` with `X-Vault-Token` returning HashiCorp KV v2 JSON."""
    kv = APIRouter(tags=["hashicorp-kv2-compat"])

    def _kv_response(payload: dict, version: int, created: str, updated: str) -> dict:
        return {
            "request_id": "", "lease_id": "", "renewable": False, "lease_duration": 0,
            "data": {"data": payload,
                     "metadata": {"created_time": created, "custom_metadata": None, "deletion_time": "",
                                  "destroyed": False, "version": version}},
            "wrap_info": None, "warnings": None, "auth": None,
        }

    @kv.get("/v1/sys/health", summary="HashiCorp-style health")
    async def kv_health():
        import main as _m
        return {"initialized": True, "sealed": False, "standby": False, "performance_standby": False,
                "replication_performance_mode": "disabled", "replication_dr_mode": "disabled",
                "server_time_utc": int(datetime.now(timezone.utc).timestamp()), "version": f"aps-vault {_m.VERSION}"}

    @kv.get("/v1/{mount}/data/{name:path}", summary="HashiCorp KV v2 read (compat)")
    async def kv_read(request: Request, mount: str, name: str,
                      version: int | None = None,
                      authorization: str | None = Header(default=None),
                      x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, folder_key = _validate_token(request, authorization, x_vault_token)
        if t["folder_name"] != mount:
            raise HTTPException(403, {"errors": [f"permission denied: token is scoped to '{t['folder_name']}'"]})
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise HTTPException(404, {"errors": []})
            payload = {"value": crypto.decrypt(folder_key, sec.value_enc, sec.value_nonce).decode("utf-8")}
            if getattr(sec, "login_enc", None):
                payload["login"] = crypto.decrypt(folder_key, sec.login_enc, sec.login_nonce).decode("utf-8")
            if t["can_read_notes"] and sec.notes_enc:
                payload["notes"] = crypto.decrypt(folder_key, sec.notes_enc, sec.notes_nonce).decode("utf-8")
            if t["can_read_totp"] and sec.totp_seed_enc:
                seed = crypto.decrypt(folder_key, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
                try:
                    payload["totp"] = pyotp.TOTP(seed.replace(" ", "")).now()
                except Exception:
                    pass
            versions = s.query(db.SecretHistory).filter_by(secret_id=sec.id).count() + 1
            sec.last_accessed = db.utcnow(); sec.access_count = (sec.access_count or 0) + 1
            s.commit()
            _audit("m:secret:read", target=f"{t['folder_name']}/{name}", token_id=t["id"],
                   ip=_client_ip(request), ua=request.headers.get("user-agent", ""), meta={"compat": "kv2"})
            return _kv_response(payload, versions,
                                sec.created_at.isoformat() + "Z" if sec.created_at else "",
                                sec.updated_at.isoformat() + "Z" if sec.updated_at else "")

    return kv
