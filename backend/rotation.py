"""Rotation in target systems (0.24).

Until 0.23 "rotation" meant a new value *inside the vault*: the server generated it, the old one
became a numbered version, and somebody still had to carry the new value into PostgreSQL, the
broker or the API that actually checks it. This module closes the loop: the vault changes the
credential **in the target first**, proves that the new one works, and only then stores it.

Targets:
  postgres — `ALTER ROLE <login> WITH PASSWORD …` through an administrator connection whose DSN is
             itself a secret in the vault; the new password is verified by logging in with it, and
             on a failed verification the old password is put back.
  http     — a signed POST with the new value to a receiver you run (an API that sets the password
             in Kafka, RabbitMQ, LDAP, a cloud console …); 2xx means "applied".

Order of operations is the whole point: generate → apply in the target → verify → store in the
vault. If the target refuses, the vault keeps the old value and reports the error; nothing is
half-done. A rotation can run by hand from a session (the person holds the folder key) or on a
schedule; the schedule needs the folder key without a person, which is what the **automation
cell** on the folder is for — the folder key wrapped under HKDF(VAULT_ROTATION_KEY, folder id),
the same construction as the SSO cell. Without that server key there is no schedule, only the
button, and the status endpoint says so.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets as pysecrets
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import crypto
import db
import settings as cfgmod
import suite

logger = logging.getLogger("aps-vault.rotation")

TARGETS = ("postgres", "mysql", "http")
GENERATE_DEFAULT = {"postgres": "alnum:32", "mysql": "alnum:32", "http": "base64:32"}
RETRY_AFTER_FAILURE = timedelta(hours=1)        # a failed scheduled run is retried after this
_SSLMODES = ("", "disable", "allow", "prefer", "require", "verify-ca", "verify-full")
_METHODS = ("POST", "PUT", "PATCH")
# a PostgreSQL role name we are willing to put into ALTER ROLE (quoted as an identifier anyway)
_ROLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$.\-@]{0,62}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9\-]{1,64}$")


class RotationError(Exception):
    """The target did not take the new value (or could not prove it did); the vault keeps the old one."""


# ─── automation cell ─────────────────────────────────────────────────────────
def configured() -> bool:
    return bool(cfgmod.SETTINGS.rotation_key)


def _cell_key(folder_id: int) -> bytes | None:
    k = cfgmod.SETTINGS.rotation_key
    return suite.kdf(k, b"aps-vault/folder-automation-cell/v1", str(folder_id).encode()) if k else None


def cell_write(folder, folder_key: bytes) -> bool:
    """Wrap the folder key for the scheduler. False when the server key is not configured."""
    k = _cell_key(folder.id)
    if not k:
        return False
    folder.automation_key_enc, folder.automation_key_nonce = crypto.encrypt(k, folder_key)
    return True


def cell_open(folder) -> bytes | None:
    if not folder.automation_key_enc:
        return None
    k = _cell_key(folder.id)
    if not k:
        return None
    try:
        return crypto.decrypt(k, folder.automation_key_enc, folder.automation_key_nonce)
    except Exception:
        return None


def cell_drop(folder) -> None:
    folder.automation_key_enc, folder.automation_key_nonce = b"", b""


# ─── configuration ───────────────────────────────────────────────────────────
def validate_config(target: str, cfg: dict, *, dev: bool, allow_private: bool, target_allowed, previous: dict | None = None) -> dict:
    """Normalise and check a target configuration. Raises ValueError with a message for the UI.
    `target_allowed(url)` is the SSRF guard shared with webhooks; `previous` keeps the signing
    secret of an http target across edits."""
    if target not in TARGETS:
        raise ValueError(f"target must be one of {', '.join(TARGETS)}")
    cfg = dict(cfg or {})
    out: dict = {}
    if target == "postgres":
        try:
            out["dsn_secret_id"] = int(cfg.get("dsn_secret_id") or 0)
        except (TypeError, ValueError):
            raise ValueError("dsn_secret_id must be the id of the secret holding the administrator DSN")
        if out["dsn_secret_id"] <= 0:
            raise ValueError("dsn_secret_id is required: the secret whose value is the administrator connection string")
        role = str(cfg.get("role") or "").strip()
        if role and not _ROLE_RE.match(role):
            raise ValueError("role must be a plain PostgreSQL role name (letters, digits, _ $ . - @)")
        out["role"] = role
        sslmode = str(cfg.get("sslmode") or "").strip()
        if sslmode not in _SSLMODES:
            raise ValueError(f"sslmode must be one of {', '.join(m for m in _SSLMODES if m)}")
        out["sslmode"] = sslmode
        out["connect_timeout"] = _int(cfg.get("connect_timeout"), 10, 1, 60, "connect_timeout")
        out["verify"] = bool(cfg.get("verify", True))
        vdb = str(cfg.get("verify_dbname") or "").strip()
        if vdb and not re.match(r"^[A-Za-z0-9_\-.]{1,64}$", vdb):
            raise ValueError("verify_dbname must be a plain database name")
        out["verify_dbname"] = vdb
        return out
    if target == "mysql":
        try:
            out["dsn_secret_id"] = int(cfg.get("dsn_secret_id") or 0)
        except (TypeError, ValueError):
            raise ValueError("dsn_secret_id must be the id of the secret holding the administrator DSN")
        if out["dsn_secret_id"] <= 0:
            raise ValueError("dsn_secret_id is required: the secret whose value is the administrator connection string (mysql://user:pw@host:3306/db)")
        user = str(cfg.get("role") or "").strip()
        if user and not re.match(r"^[A-Za-z0-9_.\-@$]{1,32}$", user):
            raise ValueError("role (the MySQL user) must be a plain account name")
        out["role"] = user
        host = str(cfg.get("user_host") or "%").strip()
        if not re.match(r"^[A-Za-z0-9_.\-%:]{1,255}$", host):
            raise ValueError("user_host must be a host pattern such as % or 10.0.0.%")
        out["user_host"] = host
        out["connect_timeout"] = _int(cfg.get("connect_timeout"), 10, 1, 60, "connect_timeout")
        out["verify"] = bool(cfg.get("verify", True))
        return out
    # http
    url = str(cfg.get("url") or "").strip()
    if url.startswith("https://"):
        pass
    elif url.startswith("http://"):
        if not (dev or allow_private):
            raise ValueError("the receiver must be https:// — the request carries the new value (http:// only with VAULT_WEBHOOK_ALLOW_PRIVATE=1 or VAULT_DEV)")
    else:
        raise ValueError("url must start with https://")
    if not target_allowed(url):
        raise ValueError("receiver address not allowed: private, loopback or unresolvable (VAULT_WEBHOOK_ALLOW_PRIVATE=1 permits private networks)")
    out["url"] = url
    method = str(cfg.get("method") or "POST").strip().upper()
    if method not in _METHODS:
        raise ValueError(f"method must be one of {', '.join(_METHODS)}")
    out["method"] = method
    headers = cfg.get("headers") or {}
    if not isinstance(headers, dict) or len(headers) > 10:
        raise ValueError("headers must be an object with at most 10 entries")
    clean = {}
    for k, v in headers.items():
        k = str(k).strip(); v = str(v).strip()
        if not _HEADER_RE.match(k) or k.lower() in ("content-type", "content-length", "x-vault-signature", "x-vault-event", "host"):
            raise ValueError(f"header {k!r} is not allowed")
        if len(v) > 512 or "\n" in v or "\r" in v:
            raise ValueError(f"header {k!r} value is too long or contains line breaks")
        clean[k] = v
    out["headers"] = clean
    out["timeout"] = _int(cfg.get("timeout"), 10, 1, 60, "timeout")
    prev_secret = (previous or {}).get("signing_secret") if previous else None
    out["signing_secret"] = prev_secret or pysecrets.token_hex(32)
    return out


def _int(v, default: int, lo: int, hi: int, name: str) -> int:
    if v in (None, ""):
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")
    if not lo <= n <= hi:
        raise ValueError(f"{name} must be {lo}..{hi}")
    return n


def public_config(target: str, cfg: dict) -> dict:
    """What the UI may see: everything but the signing secret."""
    out = {k: v for k, v in (cfg or {}).items() if k != "signing_secret"}
    if target == "http":
        out["has_signing_secret"] = bool((cfg or {}).get("signing_secret"))
    return out


def encode_config(cfg: dict) -> bytes:
    return json.dumps(cfg, ensure_ascii=False, sort_keys=True).encode("utf-8")


def decode_config(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8")) if raw else {}


# ─── targets ─────────────────────────────────────────────────────────────────
def apply(target: str, cfg: dict, *, role: str, new_value: str, old_value: str | None, admin_dsn: str | None,
          secret_name: str, folder_name: str, version: int) -> str:
    """Change the credential in the target and prove it works. Returns a short note for the audit
    row. Raises RotationError when the target did not accept the new value — the caller then
    keeps the old value in the vault."""
    if target == "postgres":
        if not admin_dsn:
            raise RotationError("administrator DSN secret is empty")
        if not role:
            raise RotationError("no role to change: set the secret's login or the rotation's role")
        return _apply_postgres(cfg, admin_dsn, role, new_value, old_value)
    if target == "mysql":
        if not admin_dsn:
            raise RotationError("administrator DSN secret is empty")
        if not role:
            raise RotationError("no user to change: set the secret's login or the rotation's role")
        return _apply_mysql(cfg, admin_dsn, role, new_value, old_value)
    if target == "http":
        payload = {"event": "rotation", "secret": secret_name, "folder": folder_name, "login": role or "",
                   "value": new_value, "version": version, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return _apply_http(cfg, payload)
    raise RotationError(f"unknown target {target!r}")


def _apply_postgres(cfg: dict, admin_dsn: str, role: str, new_value: str, old_value: str | None) -> str:
    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
    except ImportError as e:                       # pragma: no cover — psycopg is a runtime dependency
        raise RotationError(f"psycopg is not installed: {e}")
    timeout = int(cfg.get("connect_timeout") or 10)
    kw = {"connect_timeout": timeout, "autocommit": True}
    if cfg.get("sslmode"):
        kw["sslmode"] = cfg["sslmode"]
    try:
        info = conninfo_to_dict(admin_dsn)
    except Exception as e:
        raise RotationError(f"administrator DSN is not a PostgreSQL connection string: {str(e)[:80]}")
    try:
        admin = psycopg.connect(admin_dsn, **kw)
    except Exception as e:
        raise RotationError(f"administrator connection failed: {str(e).strip()[:120]}")
    try:
        try:
            admin.execute(sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(sql.Identifier(role), sql.Literal(new_value)))
        except Exception as e:
            raise RotationError(f"ALTER ROLE failed: {str(e).strip()[:120]}")
        if not cfg.get("verify", True):
            return f"ALTER ROLE {role} (verification off)"
        # prove the new password by logging in with it — the same server, the role's own credentials
        vinfo = dict(info)
        vinfo.update(user=role, password=new_value)
        if cfg.get("verify_dbname"):
            vinfo["dbname"] = cfg["verify_dbname"]
        vkw = {"connect_timeout": timeout}
        if cfg.get("sslmode"):
            vkw["sslmode"] = cfg["sslmode"]
        try:
            with psycopg.connect(make_conninfo(**vinfo), **vkw) as probe:
                probe.execute("SELECT 1")
        except Exception as e:
            reason = str(e).strip()[:120]
            if old_value is not None:
                try:
                    admin.execute(sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(sql.Identifier(role), sql.Literal(old_value)))
                    raise RotationError(f"new password refused on login ({reason}); old password restored")
                except RotationError:
                    raise
                except Exception as e2:
                    raise RotationError(f"new password refused on login ({reason}) AND restoring the old one failed: {str(e2).strip()[:80]} — fix the role by hand")
            raise RotationError(f"new password refused on login ({reason}); no previous value to restore")
        return f"ALTER ROLE {role}, login verified"
    finally:
        try:
            admin.close()
        except Exception:
            pass


def _parse_mysql_dsn(dsn: str) -> dict:
    """mysql://user:password@host:3306/db → connect kwargs (PyMySQL)."""
    from urllib.parse import unquote, urlsplit
    u = urlsplit(dsn.strip())
    if u.scheme not in ("mysql", "mariadb", "mysql+pymysql"):
        raise RotationError("administrator DSN must start with mysql:// (or mariadb://)")
    if not u.hostname:
        raise RotationError("administrator DSN has no host")
    kw = {"host": u.hostname, "port": u.port or 3306, "user": unquote(u.username or ""), "password": unquote(u.password or "")}
    if u.path and u.path != "/":
        kw["database"] = unquote(u.path.lstrip("/"))
    return kw


def _apply_mysql(cfg: dict, admin_dsn: str, user: str, new_value: str, old_value: str | None) -> str:
    """MySQL / MariaDB: ALTER USER 'user'@'host' IDENTIFIED BY '<new>' through the administrator connection,
    then a login as that user with the new password; a failed probe puts the old password back."""
    try:
        import pymysql
    except ImportError as e:                       # pragma: no cover — PyMySQL is a runtime dependency
        raise RotationError(f"PyMySQL is not installed: {e}")
    timeout = int(cfg.get("connect_timeout") or 10)
    host_pat = cfg.get("user_host") or "%"
    base = _parse_mysql_dsn(admin_dsn)
    try:
        admin = pymysql.connect(connect_timeout=timeout, autocommit=True, **base)
    except Exception as e:
        raise RotationError(f"administrator connection failed: {str(e).strip()[:120]}")
    try:
        def alter(pw: str):
            with admin.cursor() as cur:
                cur.execute("ALTER USER %s@%s IDENTIFIED BY %s", (user, host_pat, pw))
        try:
            alter(new_value)
        except Exception as e:
            raise RotationError(f"ALTER USER failed: {str(e).strip()[:120]}")
        if not cfg.get("verify", True):
            return f"ALTER USER {user}@{host_pat} (verification off)"
        probe_kw = dict(base); probe_kw.update(user=user, password=new_value); probe_kw.pop("database", None)
        try:
            with pymysql.connect(connect_timeout=timeout, **probe_kw) as probe:
                with probe.cursor() as cur:
                    cur.execute("SELECT 1")
        except Exception as e:
            reason = str(e).strip()[:120]
            if old_value is not None:
                try:
                    alter(old_value)
                    raise RotationError(f"new password refused on login ({reason}); old password restored")
                except RotationError:
                    raise
                except Exception as e2:
                    raise RotationError(f"new password refused on login ({reason}) AND restoring the old one failed: {str(e2).strip()[:80]} — fix the account by hand")
            raise RotationError(f"new password refused on login ({reason}); no previous value to restore")
        return f"ALTER USER {user}@{host_pat}, login verified"
    finally:
        try:
            admin.close()
        except Exception:
            pass


def _apply_http(cfg: dict, payload: dict) -> str:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sig = hmac.new(str(cfg.get("signing_secret", "")).encode(), body, hashlib.sha256).hexdigest()
    headers = {"Content-Type": "application/json", "X-Vault-Event": "rotation", "X-Vault-Signature": f"sha256={sig}"}
    headers.update(cfg.get("headers") or {})
    req = urllib.request.Request(cfg["url"], data=body, method=cfg.get("method", "POST"), headers=headers)
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=int(cfg.get("timeout") or 10)) as resp:   # URL validated at save time and re-checked by the caller
            code = resp.status
    except urllib.error.HTTPError as e:
        raise RotationError(f"receiver answered HTTP {e.code}")
    except urllib.error.URLError as e:
        raise RotationError(f"receiver unreachable: {str(e.reason)[:100]}")
    except Exception as e:
        raise RotationError(f"receiver error: {str(e)[:100]}")
    if not 200 <= code < 300:
        raise RotationError(f"receiver answered HTTP {code}")
    return f"{cfg.get('method', 'POST')} {cfg['url']} → {code}"


def payload_signature(signing_secret: str, body: bytes) -> str:
    """For receivers and tests: the value of X-Vault-Signature for a body."""
    return "sha256=" + hmac.new(signing_secret.encode(), body, hashlib.sha256).hexdigest()


# ─── scheduling ──────────────────────────────────────────────────────────────
def now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def next_after(interval_days: int, base: datetime | None = None) -> datetime | None:
    if not interval_days or interval_days <= 0:
        return None
    return (base or now_naive()) + timedelta(days=int(interval_days))


def claim_due(session, now: datetime | None = None) -> list[int]:
    """Take every due rotation with one conditional UPDATE each: the row's next_at moves to the
    retry slot, so a second replica (or the next tick) sees it as not due. Returns the claimed ids."""
    now = now or now_naive()
    due = session.query(db.Rotation.id).filter(db.Rotation.enabled == True, db.Rotation.interval_days > 0,   # noqa: E712
                                               db.Rotation.next_at.isnot(None), db.Rotation.next_at <= now).all()
    claimed = []
    for (rid,) in due:
        n = session.query(db.Rotation).filter(db.Rotation.id == rid, db.Rotation.next_at <= now)\
            .update({"next_at": now + RETRY_AFTER_FAILURE}, synchronize_session=False)
        if n == 1:
            claimed.append(rid)
    session.commit()
    return claimed


def to_dict(r, secret_name: str = "", folder_name: str = "", folder_id: int | None = None, include_config: dict | None = None) -> dict:
    return {
        "id": r.id, "secret_id": r.secret_id, "secret_name": secret_name, "folder_id": folder_id, "folder_name": folder_name,
        "target": r.target, "generate": r.generate or GENERATE_DEFAULT.get(r.target, "base64:32"),
        "interval_days": r.interval_days or 0, "enabled": bool(r.enabled),
        "next_at": r.next_at.isoformat() if r.next_at else None,
        "last_at": r.last_at.isoformat() if r.last_at else None,
        "last_status": r.last_status or "", "last_error": r.last_error or "", "runs": r.runs or 0,
        "created_by": r.created_by or "master", "created_at": r.created_at.isoformat() if r.created_at else "",
        **({"config": include_config} if include_config is not None else {}),
    }
