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

from fastapi import Query, APIRouter, Depends, Header, HTTPException, Path as FPath, Request
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
        # stored naive UTC; compare naive to naive (an aware utcnow() here raised TypeError → 500 for every expiring token)
        if t.expires_at and t.expires_at.replace(tzinfo=None) < db.utcnow().replace(tzinfo=None):
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
        # mTLS binding (0.11): the fingerprint header counts only when a trusted proxy sent it
        bound = getattr(t, "allowed_cert_fingerprints", "") or ""
        if bound:
            import netutil
            presented = request.headers.get(__import__("settings").SETTINGS.client_cert_header) if netutil.from_trusted_proxy(request) else None
            if not policy.cert_allowed(bound, presented):
                _audit("m:auth:policy_denied", target=t.name, token_id=t.id, ip=ip,
                       ua=request.headers.get("user-agent", ""), meta={"reason": "client certificate", "presented": (presented or "")[:64]})
                import siem
                siem.security_log("policy", ip, f"token={t.id} cert")
                raise HTTPException(403, "access policy: this token is bound to a client certificate that was not presented")
        f = s.get(db.Folder, t.folder_id)
        if not f:
            raise HTTPException(500, "scope folder is gone")
        # token key: the suite's one-way mapping of the random token (Argon2id light / KDF_TREE), salted by the folder nonce
        import suite
        token_key = suite.token_kdf(raw.encode("utf-8"), f.scope_key_nonce[:16] + b"\x00" * (16 - min(16, len(f.scope_key_nonce))))
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
            "cert_bound": bool(getattr(t, "allowed_cert_fingerprints", "")),
            "client_public_key": getattr(t, "client_public_key", "") or "",     # 0.17: sealed delivery
            "expires_at": t.expires_at, "created_at": t.created_at,              # 0.25: lookup-self expire_time/ttl (ESO checks them)
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
            "sealed": bool(t["client_public_key"]),
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

    @router.get("/secret/{name}/versions", summary="версии значения секрета (без самих значений)")
    async def list_secret_versions(
        request: Request,
        name: str = FPath(..., description="имя секрета в scope-папке"),
        authorization: str | None = Header(default=None),
        x_vault_token: str | None = Header(default=None, alias="X-Vault-Token"),
    ):
        """For a key rotation: a service learns which versions exist and reads an old one with
        `GET /secret/{name}?version=N`. Metadata only — no decrypt, no access-count bump."""
        t, _ = _validate_token(request, authorization, x_vault_token)
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise HTTPException(404, f"secret '{name}' not found in scope '{t['folder_name']}'")
            cur = sec.version or 1
            out = [{"version": cur, "current": True, "changed_at": sec.updated_at.isoformat() if sec.updated_at else "", "changed_by": None}]
            for h in s.query(db.SecretHistory).filter_by(secret_id=sec.id).order_by(db.SecretHistory.version.desc()).all():
                out.append({"version": h.version, "current": False, "changed_at": h.changed_at.isoformat() if h.changed_at else "",
                            "changed_by": h.changed_by, "readable": h.folder_id == sec.folder_id})
            return {"name": sec.name, "current_version": cur, "versions": out}

    @router.get("/secret/{name}", summary="расшифрованное значение секрета по имени (?version=N — старое значение)")
    async def get_secret_by_name(
        request: Request,
        name: str = FPath(..., description="имя секрета в scope-папке"),
        version: int | None = Query(default=None, ge=1, description="номер версии; без параметра — текущая"),
        authorization: str | None = Header(default=None),
        x_vault_token: str | None = Header(default=None, alias="X-Vault-Token"),
    ):
        t, folder_key = _validate_token(request, authorization, x_vault_token)
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise HTTPException(404, f"secret '{name}' not found in scope '{t['folder_name']}'")
            cur = sec.version or 1
            if version is not None and version != cur:
                h = s.query(db.SecretHistory).filter_by(secret_id=sec.id, version=version).first()
                if not h:
                    raise HTTPException(404, f"secret '{name}' has no version {version} (current is {cur})")
                if h.folder_id != sec.folder_id:
                    raise HTTPException(409, f"version {version} is encrypted under another folder's key")
                value = crypto.decrypt(folder_key, h.value_enc, h.value_nonce)
            else:
                value = crypto.decrypt(folder_key, sec.value_enc, sec.value_nonce)
            result = {"name": sec.name, "version": version or cur, "current_version": cur,
                      "updated_at": sec.updated_at.isoformat() if sec.updated_at else ""}
            payload = {"value": value.decode("utf-8")}
            # v0.3.2: login отдаём вместе с value — не PII в смысле «секрет»,
            # обычно email/имя пользователя. Не требует отдельного can_read_*.
            if getattr(sec, "login_enc", None):
                login = crypto.decrypt(folder_key, sec.login_enc, sec.login_nonce)
                payload["login"] = login.decode("utf-8")
            if t["can_read_notes"] and sec.notes_enc:
                notes = crypto.decrypt(folder_key, sec.notes_enc, sec.notes_nonce)
                payload["notes"] = notes.decode("utf-8")
            if t["can_read_totp"] and sec.totp_seed_enc:
                seed = crypto.decrypt(folder_key, sec.totp_seed_enc, sec.totp_seed_nonce).decode("utf-8")
                try:
                    payload["totp"] = pyotp.TOTP(seed.replace(" ", "")).now()
                except Exception:
                    payload["totp"] = None
            meta = {"version": version} if version is not None and version != cur else {}
            if t["client_public_key"]:
                # 0.17: sealed delivery — the plaintext never enters the response
                import sealed
                result["sealed"] = sealed.seal(payload, t["client_public_key"], sec.name)
                meta["sealed"] = True
            else:
                result.update(payload)
            # Бамп access count
            sec.last_accessed = db.utcnow()
            sec.access_count = (sec.access_count or 0) + 1
            s.commit()
            _audit("m:secret:read", target=f"{t['folder_name']}/{name}",
                   token_id=t["id"], ip=_client_ip(request),
                   ua=request.headers.get("user-agent", ""),
                   meta=meta or None)
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
                # Старое значение — в историю под своим номером версии (как human API PATCH)
                __import__("main").archive_value(s, sec, f"token:{t['id']}")
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
            return {"id": sec.id, "name": name, "created": created, "version": sec.version or 1}

    return router


# ── HashiCorp KV v2 compatible facade ───────────────────────────────────────
# Lets a service written against HashiCorp Vault (KV v2 read) run unchanged against APS
# Vault — and lets an APS Vault user move to HashiCorp later by changing URL and token only.
# Mount = folder name; the token's scope folder must match. Read-only.


class KVError(Exception):
    """Error in HashiCorp's shape — `{"errors": [...]}` at top level, 403 for any auth problem
    (HashiCorp never distinguishes "bad token" from "forbidden"; hvac relies on that)."""

    def __init__(self, status: int, *errors: str) -> None:
        super().__init__("; ".join(errors))
        self.status = status
        self.errors = list(errors)


def _kv_validate(request: Request, authorization: str | None, x_vault_token: str | None):
    try:
        return _validate_token(request, authorization, x_vault_token)
    except HTTPException as e:
        if e.status_code in (401, 403):
            raise KVError(403, "permission denied") from None
        raise


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

    # --- what `vault` CLI and hvac call around a KV read/write ---------------
    @kv.get("/v1/sys/internal/ui/mounts/{path:path}", summary="mount info (vault CLI detects KV v2 here)")
    async def kv_mount_info(request: Request, path: str,
                            authorization: str | None = Header(default=None),
                            x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, _ = _kv_validate(request, authorization, x_vault_token)
        mount = path.split("/", 1)[0]
        if mount != t["folder_name"]:
            raise KVError(403, "permission denied")
        return {"data": {"type": "kv", "path": f"{mount}/", "options": {"version": "2"},
                         "accessor": f"kv_{t['folder_id']}", "description": "APS Vault folder", "local": False, "seal_wrap": False}}

    @kv.get("/v1/auth/token/lookup-self", summary="token introspection")
    async def kv_lookup_self(request: Request,
                             authorization: str | None = Header(default=None),
                             x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, _ = _kv_validate(request, authorization, x_vault_token)
        # HashiCorp shape: expire_time is null for a token without expiry, RFC 3339 otherwise; ttl in seconds.
        # External Secrets Operator refuses a store whose lookup-self lacks expire_time ("no expiration time found").
        exp = t.get("expires_at")
        exp = exp.replace(tzinfo=None) if exp is not None else None
        now = db.utcnow().replace(tzinfo=None)
        created = t.get("created_at")
        return {"data": {"accessor": f"tok_{t['id']}", "display_name": t["name"], "policies": ["default", f"folder-{t['folder_name']}"],
                         "meta": {"scope_folder": t["folder_name"], "can_write": t["can_write"]},
                         "renewable": False, "orphan": True, "type": "service", "path": "auth/token/create", "entity_id": "",
                         "creation_time": int(created.replace(tzinfo=None).timestamp()) if created else 0,
                         "creation_ttl": int((exp - created.replace(tzinfo=None)).total_seconds()) if exp and created else 0,
                         "explicit_max_ttl": 0,
                         "expire_time": (exp.isoformat(timespec="seconds") + "Z") if exp else None,
                         "ttl": max(0, int((exp - now).total_seconds())) if exp else 0}}

    @kv.api_route("/v1/{mount}/metadata/{name:path}", methods=["LIST"], summary="KV v2 list (LIST method)")
    @kv.get("/v1/{mount}/metadata/{name:path}", summary="KV v2 metadata / list (?list=true)")
    async def kv_metadata(request: Request, mount: str, name: str = "",
                          authorization: str | None = Header(default=None),
                          x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, _ = _kv_validate(request, authorization, x_vault_token)
        if t["folder_name"] != mount:
            raise KVError(403, f"permission denied: token is scoped to '{t['folder_name']}'")
        listing = request.method == "LIST" or request.query_params.get("list") in ("true", "1")
        with db.get_session() as s:
            if listing:
                prefix = name.strip("/")
                prefix = prefix + "/" if prefix else ""
                keys = set()
                for (n,) in s.query(db.Secret.name).filter_by(folder_id=t["folder_id"]).all():
                    if not n.startswith(prefix):
                        continue
                    rest = n[len(prefix):]
                    keys.add(rest.split("/", 1)[0] + "/" if "/" in rest else rest)
                if not keys:
                    raise KVError(404, "not found")
                return {"data": {"keys": sorted(keys)}}
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise KVError(404, "not found")
            ver = sec.version or 1
            versions = {str(ver): {"created_time": (sec.updated_at.isoformat() + "Z") if sec.updated_at else "", "deletion_time": "", "destroyed": False}}
            hist = s.query(db.SecretHistory).filter_by(secret_id=sec.id).order_by(db.SecretHistory.version.asc()).all()
            for h in hist:
                versions[str(h.version)] = {"created_time": (h.changed_at.isoformat() + "Z") if h.changed_at else "", "deletion_time": "", "destroyed": False}
            return {"data": {"created_time": (sec.created_at.isoformat() + "Z") if sec.created_at else "",
                             "current_version": ver, "max_versions": 0, "oldest_version": min([ver] + [h.version for h in hist if h.version]),
                             "updated_time": (sec.updated_at.isoformat() + "Z") if sec.updated_at else "",
                             "versions": versions}}

    @kv.api_route("/v1/{mount}/data/{name:path}", methods=["POST", "PUT"], summary="KV v2 write (compat; token needs can_write)")
    async def kv_write(request: Request, mount: str, name: str,
                       authorization: str | None = Header(default=None),
                       x_vault_token: str | None = Header(default=None, alias="X-Vault-Token")):
        t, folder_key = _kv_validate(request, authorization, x_vault_token)
        if t["folder_name"] != mount:
            raise KVError(403, f"permission denied: token is scoped to '{t['folder_name']}'")
        if not t["can_write"]:
            raise KVError(403, "permission denied: token has no write permission")
        body = await request.json()
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict) or "value" not in data:
            raise KVError(400, "body must be {\"data\": {\"value\": ..., \"login\"?: ...}}")
        value = str(data["value"]); login = str(data.get("login", "") or "")
        value_enc, value_nonce = crypto.encrypt(folder_key, value.encode("utf-8"))
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if sec is None:
                sec = db.Secret(folder_id=t["folder_id"], name=name, value_enc=value_enc, value_nonce=value_nonce,
                                notes_enc=b"", notes_nonce=b"", totp_seed_enc=b"", totp_seed_nonce=b"",
                                login_enc=b"", login_nonce=b"", tags="", url="")
                s.add(sec)
            else:
                __import__("main").archive_value(s, sec, f"token:{t['id']}")
                sec.value_enc, sec.value_nonce = value_enc, value_nonce
                sec.updated_at = db.utcnow()
            if login:
                sec.login_enc, sec.login_nonce = crypto.encrypt(folder_key, login.encode("utf-8"))
            s.commit(); s.refresh(sec)
            ver = sec.version or 1
            _audit("m:secret:put", target=f"{t['folder_name']}/{name}", token_id=t["id"],
                   ip=_client_ip(request), ua=request.headers.get("user-agent", ""), meta={"compat": "kv2"})
            return {"data": {"created_time": (sec.updated_at.isoformat() + "Z") if sec.updated_at else "",
                             "deletion_time": "", "destroyed": False, "version": ver}}

    @kv.get("/v1/sys/seal-status", summary="HashiCorp-style seal status (never sealed: tokens work regardless)")
    async def kv_seal_status():
        import main as _m
        return {"type": "shamir", "initialized": True, "sealed": False, "t": 1, "n": 1, "progress": 0,
                "version": f"aps-vault {_m.VERSION}", "cluster_name": "aps-vault", "storage_type": "sqlite"}

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
        t, folder_key = _kv_validate(request, authorization, x_vault_token)
        if t["folder_name"] != mount:
            raise KVError(403, f"permission denied: token is scoped to '{t['folder_name']}'")
        if t["client_public_key"]:
            # 0.17: a sealed token never yields plaintext — and the KV v2 shape has no place for an envelope
            raise KVError(403, "permission denied: this token delivers sealed values; read it through /api/v1/m/secret/{name} with the client library")
        with db.get_session() as s:
            sec = s.query(db.Secret).filter_by(folder_id=t["folder_id"], name=name).first()
            if not sec:
                raise KVError(404, "not found")
            cur = sec.version or 1
            if version is not None and version != cur:
                # HashiCorp semantics: an unknown version is 404 with an empty body; an older one
                # comes back with its own metadata.version
                h = s.query(db.SecretHistory).filter_by(secret_id=sec.id, version=version).first()
                if not h or h.folder_id != sec.folder_id:
                    raise KVError(404, "not found")
                payload = {"value": crypto.decrypt(folder_key, h.value_enc, h.value_nonce).decode("utf-8")}
                created = (h.changed_at.isoformat() + "Z") if h.changed_at else ""
                s.commit()
                _audit("m:secret:read", target=f"{t['folder_name']}/{name}", token_id=t["id"],
                       ip=_client_ip(request), ua=request.headers.get("user-agent", ""), meta={"compat": "kv2", "version": version})
                return _kv_response(payload, version, created, created)
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
            sec.last_accessed = db.utcnow(); sec.access_count = (sec.access_count or 0) + 1
            s.commit()
            _audit("m:secret:read", target=f"{t['folder_name']}/{name}", token_id=t["id"],
                   ip=_client_ip(request), ua=request.headers.get("user-agent", ""), meta={"compat": "kv2"})
            return _kv_response(payload, cur,
                                sec.created_at.isoformat() + "Z" if sec.created_at else "",
                                sec.updated_at.isoformat() + "Z" if sec.updated_at else "")

    return kv
