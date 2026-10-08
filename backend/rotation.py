"""Rotation in target systems (0.24).

Until 0.23 "rotation" meant a new value *inside the vault*: the server generated it, the old one
became a numbered version, and somebody still had to carry the new value into PostgreSQL, the
broker or the API that actually checks it. This module closes the loop: the vault changes the
credential **in the target first**, proves that the new one works, and only then stores it.

Targets:
  postgres — `ALTER ROLE <login> WITH PASSWORD …` through an administrator connection whose DSN is
             itself a secret in the vault; the new password is verified by logging in with it, and
             on a failed verification the old password is put back.
  mysql    — `ALTER USER 'user'@'host' IDENTIFIED BY …` the same way (0.30).
  ldap     — `userPassword` (OpenLDAP) or `unicodePwd` (Active Directory) replaced through a bind
             account that is itself a secret; verified by binding as the entry (0.31).
  ssh      — `chpasswd` on a host through an administrator SSH session (password or key), host key
             pinned in the configuration; verified by logging in as the account (0.31).
  http     — a signed POST with the new value to a receiver you run (an API that sets the password
             in Kafka, RabbitMQ, a cloud console …); 2xx means "applied".

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

TARGETS = ("postgres", "mysql", "ldap", "ssh", "http")
# targets whose configuration points at another secret holding the administrator credential
ADMIN_TARGETS = ("postgres", "mysql", "ldap", "ssh")
GENERATE_DEFAULT = {"postgres": "alnum:32", "mysql": "alnum:32", "ldap": "alnum:32", "ssh": "alnum:32", "http": "base64:32"}
_DN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*=.+$")
_SSH_KEY_LINE_RE = re.compile(r"^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-[\w@.-]+) [A-Za-z0-9+/=]+$")
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
    if target == "ldap":
        out["dsn_secret_id"] = _secret_id(cfg, "the secret whose login is the bind DN and whose value is the bind password")
        from urllib.parse import urlsplit
        url = str(cfg.get("url") or "").strip()
        u = urlsplit(url)
        if u.scheme not in ("ldap", "ldaps") or not u.hostname or u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("url must be ldap://host:389 or ldaps://host:636 (nothing after the port)")
        out["url"] = url.rstrip("/")
        dn = str(cfg.get("role") or "").strip()
        if dn and not _DN_RE.match(dn):
            raise ValueError("role (the entry DN) must look like uid=app,ou=svc,dc=example,dc=org")
        out["role"] = dn
        mode = str(cfg.get("mode") or "openldap").strip().lower()
        if mode not in ("openldap", "ad"):
            raise ValueError("mode must be openldap (userPassword) or ad (unicodePwd)")
        out["mode"] = mode
        out["start_tls"] = bool(cfg.get("start_tls", False))
        out["tls_verify"] = bool(cfg.get("tls_verify", True))
        if mode == "ad" and u.scheme != "ldaps" and not out["start_tls"]:
            raise ValueError("Active Directory accepts unicodePwd only over TLS: use ldaps:// or start_tls")
        attr = str(cfg.get("attribute") or "").strip()
        if attr and not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,63}$", attr):
            raise ValueError("attribute must be an LDAP attribute name")
        out["attribute"] = attr
        out["connect_timeout"] = _int(cfg.get("connect_timeout"), 10, 1, 60, "connect_timeout")
        out["verify"] = bool(cfg.get("verify", True))
        return out
    if target == "ssh":
        out["dsn_secret_id"] = _secret_id(cfg, "the secret whose login is the administrator's user name and whose value is the password or an OpenSSH private key")
        host = str(cfg.get("host") or "").strip()
        if not re.match(r"^[A-Za-z0-9_.\-]{1,253}$", host) and not re.match(r"^\[?[0-9A-Fa-f:.]+\]?$", host):
            raise ValueError("host must be a host name or an address")
        out["host"] = host
        out["port"] = _int(cfg.get("port"), 22, 1, 65535, "port")
        hk = " ".join(str(cfg.get("host_key") or "").split())
        if hk.startswith("SHA256:"):
            if not re.match(r"^SHA256:[A-Za-z0-9+/]{43}=?$", hk):
                raise ValueError("host_key fingerprint must be SHA256: followed by 43 base64 characters (ssh-keyscan host | ssh-keygen -lf -)")
            hk = hk.rstrip("=")
        elif _SSH_KEY_LINE_RE.match(hk):
            pass
        elif hk and len(hk.split()) >= 3 and _SSH_KEY_LINE_RE.match(" ".join(hk.split()[1:3])):
            hk = " ".join(hk.split()[1:3])          # a known_hosts / ssh-keyscan line: "host type base64"
        else:
            raise ValueError("host_key is required: the server's SHA256:… fingerprint or its public key line (ssh-keyscan host)")
        out["host_key"] = hk
        user = str(cfg.get("role") or "").strip()
        if user and not re.match(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,31}\$?$", user):
            raise ValueError("role (the account) must be a plain Unix user name")
        out["role"] = user
        out["use_sudo"] = bool(cfg.get("use_sudo", True))
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


def _secret_id(cfg: dict, what: str) -> int:
    try:
        n = int(cfg.get("dsn_secret_id") or 0)
    except (TypeError, ValueError):
        raise ValueError("dsn_secret_id must be the id of " + what)
    if n <= 0:
        raise ValueError("dsn_secret_id is required: " + what)
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
          secret_name: str, folder_name: str, version: int, admin_login: str = "") -> str:
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
    if target == "ldap":
        if not admin_dsn:
            raise RotationError("bind account secret is empty")
        if not admin_login:
            raise RotationError("the bind account secret has no login — its login must be the bind DN")
        if not role:
            raise RotationError("no entry to change: set the secret's login to the entry DN or the rotation's DN")
        return _apply_ldap(cfg, admin_login, admin_dsn, role, new_value, old_value)
    if target == "ssh":
        if not admin_dsn:
            raise RotationError("administrator secret is empty")
        if not admin_login:
            raise RotationError("the administrator secret has no login — its login must be the SSH user name")
        if not role:
            raise RotationError("no account to change: set the secret's login or the rotation's user")
        return _apply_ssh(cfg, admin_login, admin_dsn, role, new_value, old_value)
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


# ─── ldap ────────────────────────────────────────────────────────────────────
def _ldap_server(cfg: dict):
    import ssl
    import ldap3
    from urllib.parse import urlsplit
    u = urlsplit(cfg["url"])
    use_ssl = u.scheme == "ldaps"
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if cfg.get("tls_verify", True) else ssl.CERT_NONE)
    return ldap3.Server(u.hostname, port=u.port or (636 if use_ssl else 389), use_ssl=use_ssl, tls=tls,
                        connect_timeout=int(cfg.get("connect_timeout") or 10), get_info=ldap3.NONE)


def _ldap_bind(cfg: dict, server, dn: str, password: str, who: str):
    """Open + (StartTLS) + simple bind. Returns the connection; raises RotationError with the server's word."""
    import ldap3
    timeout = int(cfg.get("connect_timeout") or 10)
    conn = ldap3.Connection(server, user=dn, password=password, auto_bind=ldap3.AUTO_BIND_NONE,
                            receive_timeout=timeout, raise_exceptions=False, read_only=False)
    try:
        conn.open()
        if cfg.get("start_tls"):
            if not conn.start_tls():
                raise RotationError(f"{who}: StartTLS refused: {conn.result.get('description', '')}")
        if not conn.bind():
            raise RotationError(f"{who} bind failed: {conn.result.get('description', 'invalidCredentials')}")
    except RotationError:
        try:
            conn.unbind()
        except Exception:
            pass
        raise
    except Exception as e:
        raise RotationError(f"{who} connection failed: {str(e).strip()[:120]}")
    return conn


def _ldap_probe(cfg: dict, server, dn: str, password: str) -> None:
    """Bind as the entry with the new password — the proof that the directory took it."""
    _ldap_bind(cfg, server, dn, password, "verification").unbind()


def _apply_ldap(cfg: dict, bind_dn: str, bind_pw: str, dn: str, new_value: str, old_value: str | None) -> str:
    """LDAP: replace the password attribute of `dn` through the bind account, then bind as `dn` with the new
    password; a failed probe puts the old value back. OpenLDAP (`userPassword`, the server hashes it per its
    password policy) or Active Directory (`unicodePwd`, UTF-16LE in quotes, TLS required)."""
    try:
        import ldap3
    except ImportError as e:                       # pragma: no cover — ldap3 is a runtime dependency
        raise RotationError(f"ldap3 is not installed: {e}")
    mode = cfg.get("mode") or "openldap"
    attr = cfg.get("attribute") or ("unicodePwd" if mode == "ad" else "userPassword")
    enc = (lambda v: ('"%s"' % v).encode("utf-16-le")) if attr.lower() == "unicodepwd" else (lambda v: v.encode("utf-8"))
    server = _ldap_server(cfg)
    admin = _ldap_bind(cfg, server, bind_dn, bind_pw, "bind account")
    try:
        def replace(pw: str) -> None:
            if not admin.modify(dn, {attr: [(ldap3.MODIFY_REPLACE, [enc(pw)])]}):
                raise RotationError(f"modify {attr} failed: {admin.result.get('description', '')} {admin.result.get('message', '')}".strip()[:160])
        replace(new_value)
        if not cfg.get("verify", True):
            return f"{attr} replaced on {dn} (verification off)"
        try:
            _ldap_probe(cfg, server, dn, new_value)
        except RotationError as e:
            reason = str(e)[:120]
            if old_value is not None:
                try:
                    replace(old_value)
                    raise RotationError(f"new password refused on bind ({reason}); old password restored")
                except RotationError:
                    raise
                except Exception as e2:
                    raise RotationError(f"new password refused on bind ({reason}) AND restoring the old one failed: {str(e2).strip()[:80]} — fix the entry by hand")
            raise RotationError(f"new password refused on bind ({reason}); no previous value to restore")
        return f"{attr} replaced on {dn}, bind verified"
    finally:
        try:
            admin.unbind()
        except Exception:
            pass


# ─── ssh ─────────────────────────────────────────────────────────────────────
def ssh_fingerprint(key) -> str:
    """SHA256 fingerprint of a paramiko key, the way ssh-keygen -l prints it (no padding)."""
    import base64
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _ssh_load_key(pem: str):
    import io
    import paramiko
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except Exception as e:                      # wrong type for this class, try the next
            last = e
    raise RotationError(f"administrator private key not readable (OpenSSH PEM, unencrypted): {str(last).strip()[:80]}")


def _ssh_connect(cfg: dict, user: str, credential: str, who: str):
    """Connect with the pinned host key; `credential` is a password or an OpenSSH private key."""
    try:
        import paramiko
    except ImportError as e:                       # pragma: no cover — paramiko is a runtime dependency
        raise RotationError(f"paramiko is not installed: {e}")
    pinned = cfg["host_key"]
    timeout = int(cfg.get("connect_timeout") or 10)

    class Pinned(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            fp = ssh_fingerprint(key)
            if pinned == fp or pinned == f"{key.get_name()} {key.get_base64()}":
                return
            raise RotationError(f"host key mismatch: the server presents {key.get_name()} {fp}, the rotation pins {pinned[:60]} — nothing changed")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(Pinned())
    kw = dict(hostname=cfg["host"], port=int(cfg.get("port") or 22), username=user, timeout=timeout, banner_timeout=timeout,
              auth_timeout=timeout, allow_agent=False, look_for_keys=False)
    if credential.lstrip().startswith("-----BEGIN"):
        kw["pkey"] = _ssh_load_key(credential)
    else:
        kw["password"] = credential
    try:
        client.connect(**kw)
    except RotationError:
        raise
    except paramiko.AuthenticationException:
        raise RotationError(f"{who}: authentication refused")
    except Exception as e:
        raise RotationError(f"{who}: connection failed: {str(e).strip()[:120]}")
    return client


def _ssh_run(client, command: str, stdin_data: str | None, timeout: int) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.flush()
    stdin.channel.shutdown_write()
    rc = stdout.channel.recv_exit_status()
    err = stderr.read().decode("utf-8", "replace").strip()
    return rc, err


def _ssh_probe(cfg: dict, user: str, password: str) -> None:
    """Log in as the account with the new password and run `true` — a nologin shell or a DenyUsers rule fails here."""
    timeout = int(cfg.get("connect_timeout") or 10)
    c = _ssh_connect(cfg, user, password, "verification")
    try:
        rc, err = _ssh_run(c, "true", None, timeout)
        if rc != 0:
            raise RotationError(f"verification: login ok but the shell refused (exit {rc}) {err[:80]}".strip())
    finally:
        c.close()


def _apply_ssh(cfg: dict, admin_user: str, admin_cred: str, user: str, new_value: str, old_value: str | None) -> str:
    """SSH: `chpasswd` (through sudo -n unless the administrator is root or use_sudo is off) with "user:password"
    on stdin — never on a command line — then a password login as that account; a failed probe restores the old
    password the same way. The host key is pinned in the configuration: a different key means nothing is sent."""
    timeout = int(cfg.get("connect_timeout") or 10)
    use_sudo = bool(cfg.get("use_sudo", True)) and admin_user != "root"
    cmd = "sudo -n chpasswd" if use_sudo else "chpasswd"
    admin = _ssh_connect(cfg, admin_user, admin_cred, "administrator")
    try:
        def chpasswd(pw: str) -> None:
            if "\n" in user or "\n" in pw or ":" in user:
                raise RotationError("account name or password contains characters chpasswd cannot take")
            rc, err = _ssh_run(admin, cmd, f"{user}:{pw}\n", timeout)
            if rc != 0:
                raise RotationError(f"chpasswd failed (exit {rc}): {err[:120] or 'no message'}")
        chpasswd(new_value)
        if not cfg.get("verify", True):
            return f"chpasswd {user}@{cfg['host']} (verification off)"
        try:
            _ssh_probe(cfg, user, new_value)
        except RotationError as e:
            reason = str(e)[:120]
            if old_value is not None:
                try:
                    chpasswd(old_value)
                    raise RotationError(f"new password refused on login ({reason}); old password restored")
                except RotationError:
                    raise
                except Exception as e2:
                    raise RotationError(f"new password refused on login ({reason}) AND restoring the old one failed: {str(e2).strip()[:80]} — fix the account by hand")
            raise RotationError(f"new password refused on login ({reason}); no previous value to restore")
        return f"chpasswd {user}@{cfg['host']}, login verified"
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
        import netutil
        with netutil.urlopen_noredirect(req, timeout=int(cfg.get("timeout") or 10)) as resp:   # URL validated at save time and re-checked by the caller
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
