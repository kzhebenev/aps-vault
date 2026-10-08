"""Encrypted backups of the vault's database to S3 (0.39).

What is uploaded. A logical dump of every application table (DB-agnostic: the same file restores into SQLite or
PostgreSQL), gzip, then sealed to the backup recipient's PUBLIC key with the vault's sealed envelope — by default the
post-quantum hybrid (X25519 + ML-KEM-768; GOST hybrid on a GOST vault). The server never holds the private key: a
copy of the vault host, of the database or of the bucket does not open a backup. Secret values inside the dump stay
what they are in the database — ciphertext under the folder keys — so a restored dump still needs the master password.

Not in the dump: UI sessions, WebAuthn challenges, lock-outs, TOTP replay steps, update jobs and the backup's own
bookkeeping — runtime state, not data.

When. Mode `change` (default): every tick (60 s) a replica that holds the lease dumps the database and hashes the
*state* — without the audit log, token-watch counters and read counters, so reads do not cause uploads — and uploads
only when the hash moved; bursts of edits coalesce into one object per tick. Mode `hourly`: at most once an hour, only
when changed. In every mode one full copy a day is uploaded even without changes (it carries the audit log and proves
the pipeline is alive).

S3 credentials come from the environment (VAULT_BACKUP_S3_*; *_FILE works), not from the database: they are needed
while the vault is locked, and a database dump must not carry the key to the bucket. Ideally the key may only PutObject
(no Get/Delete/List) and the bucket keeps versions or an object lock — then even a compromised vault host cannot
destroy old backups.

Command line (inside the backend image, `python -m backup …`): `fetch KEY`, `list`, `decrypt --key FILE IN`,
`restore DUMP` — see docs/BACKUP.md."""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

import db
import netutil
import sealed
import settings as cfgmod

FORMAT, VERSION = "aps-vault-backup", 1
DUMP_FORMAT = "aps-vault-dump"
SKIP_TABLES = {"ui_sessions", "webauthn_challenges", "lockdown", "totp_steps", "update_state", "update_agents", "update_jobs",
               "backup_runs"}
# 0.40: backup_state is IN the dump (a restored vault keeps backing up to the same key) but not in the change hash —
# every upload changes it (state_hash, last_ok_at), which would trigger the next upload
HASH_SKIP_TABLES = {"audit_log", "token_profiles", "token_alerts", "backup_state"}
ENV_PREFIXES = ("VAULT_", "OIDC_")
HASH_SKIP_COLUMNS = {"last_accessed", "access_count", "last_used", "last_seen", "uses"}
MODES = ("change", "hourly", "daily")
LEASE = dt.timedelta(minutes=10)
FULL_EVERY = dt.timedelta(hours=24)


class BackupError(Exception):
    pass


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def node() -> str:
    return socket.gethostname()[:64]


# ── configuration ──────────────────────────────────────────────────────────
def s3_config() -> dict:
    st = cfgmod.SETTINGS
    return {"endpoint": st.backup_s3_endpoint, "bucket": st.backup_s3_bucket, "prefix": st.backup_s3_prefix,
            "region": st.backup_s3_region, "access_key": st.backup_s3_access_key, "secret_key": st.backup_s3_secret_key}


def s3_missing() -> list[str]:
    c = s3_config()
    names = {"endpoint": "VAULT_BACKUP_S3_ENDPOINT", "bucket": "VAULT_BACKUP_S3_BUCKET", "access_key": "VAULT_BACKUP_S3_ACCESS_KEY",
             "secret_key": "VAULT_BACKUP_S3_SECRET_KEY"}
    return [v for k, v in names.items() if not c[k]]


def endpoint_allowed(url: str) -> bool:
    st = cfgmod.SETTINGS
    u = urllib.parse.urlparse(url or "")
    if u.scheme != "https" and not (u.scheme == "http" and (st.webhook_allow_private or st.dev)):
        return False
    return bool(u.hostname) and (st.webhook_allow_private or netutil.address_is_public(u.hostname))


def fingerprint(pk_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(pk_b64)).hexdigest()[:16]


def state_row(s) -> "db.BackupState":
    row = s.get(db.BackupState, 1)
    if row is None:
        row = db.BackupState(id=1, enabled=False, mode="change")
        s.add(row)
        s.commit()
    return row


# ── dump ───────────────────────────────────────────────────────────────────
def _enc(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"$b64": base64.b64encode(bytes(v)).decode()}
    if isinstance(v, dt.datetime):
        return {"$dt": v.isoformat()}
    if isinstance(v, dt.date):
        return {"$d": v.isoformat()}
    return v


def _dec(v):
    if isinstance(v, dict) and len(v) == 1:
        if "$b64" in v:
            return base64.b64decode(v["$b64"])
        if "$dt" in v:
            return dt.datetime.fromisoformat(v["$dt"])
        if "$d" in v:
            return dt.date.fromisoformat(v["$d"])
    return v


def environment() -> dict:
    """0.40: the settings that live outside the database — every VAULT_* / OIDC_* variable of this process, with
    VAULT_<NAME>_FILE indirections resolved to their values (the file path alone restores nothing), plus the content of
    files that are settings by themselves (the Yandex KMS service-account key). This is where the S3 keys, the SSO and
    rotation keys, KMS / HSM / OIDC credentials live; it only ever leaves the process inside the sealed payload."""
    env = cfgmod._env_with_files()
    names = {k for k in env if k.startswith(ENV_PREFIXES)}
    out = {k: env[k] for k in sorted(names)
           if not (k.endswith("_FILE") and k not in cfgmod._PATH_VARS and env.get(k[:-5]))}   # the value is in VAULT_<NAME>
    files = {}
    for k in sorted(cfgmod._PATH_VARS & names):
        try:
            with open(env[k], encoding="utf-8") as f:
                files[k] = f.read(65536)
        except OSError:
            pass
    return {"captured_on": node(), "vars": out, "files": files}


def dump(s, include_env: bool | None = None) -> dict:
    import main
    out = {"format": DUMP_FORMAT, "v": 1, "vault_version": main.VERSION, "created_at": now().isoformat() + "Z", "tables": {}}
    if include_env is None:
        include_env = bool(getattr(state_row(s), "include_env", True))
    if include_env:
        out["environment"] = environment()
    for t in db.Base.metadata.sorted_tables:
        if t.name in SKIP_TABLES:
            continue
        cols = [c.name for c in t.columns]
        order = [c for c in t.primary_key.columns] or [t.columns[cols[0]]]
        out["tables"][t.name] = [{k: _enc(r[k]) for k in cols} for r in s.execute(t.select().order_by(*order)).mappings()]
    return out


def state_hash(d: dict) -> str:
    view = {name: [{k: v for k, v in row.items() if k not in HASH_SKIP_COLUMNS} for row in rows]
            for name, rows in d["tables"].items() if name not in HASH_SKIP_TABLES}
    if "environment" in d:                          # a restart with changed settings is a change too
        view["$environment"] = {"vars": d["environment"]["vars"], "files": d["environment"]["files"]}
    return hashlib.sha256(json.dumps(view, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ── encryption ─────────────────────────────────────────────────────────────
def _aad(header: dict) -> str:
    return f"{FORMAT}/v{VERSION}|{header['created_at']}|{header['recipient']}|{header['vault_version']}|{header['plain_sha256']}"


def seal_dump(d: dict, recipient_pk: str, reason: str) -> bytes:
    plain = gzip.compress(json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), compresslevel=6)
    header = {"format": FORMAT, "v": VERSION, "created_at": d["created_at"], "vault_version": d["vault_version"], "node": node(),
              "reason": reason, "recipient": fingerprint(recipient_pk), "recipient_kind": sealed.key_kind(recipient_pk),
              "plain_sha256": hashlib.sha256(plain).hexdigest(), "rows": sum(len(r) for r in d["tables"].values())}
    env = sealed.seal({"gz": base64.b64encode(plain).decode()}, recipient_pk, _aad(header))
    return json.dumps({**header, "sealed": env}, separators=(",", ":")).encode()


def open_backup(blob: bytes, private_key_b64: str) -> dict:
    """The decrypted dump; raises ValueError on a wrong key or any change to the header or the ciphertext."""
    obj = json.loads(blob.decode("utf-8"))
    if obj.get("format") != FORMAT or obj.get("v") != VERSION:
        raise ValueError("not an APS Vault backup")
    try:
        payload = sealed.unseal(obj["sealed"], base64.b64decode(private_key_b64.strip()), _aad(obj))
    except Exception as e:
        raise ValueError(f"cannot open the backup (wrong key, or the file was changed): {e.__class__.__name__}")
    plain = base64.b64decode(payload["gz"])
    if hashlib.sha256(plain).hexdigest() != obj["plain_sha256"]:
        raise ValueError("checksum mismatch")
    d = json.loads(gzip.decompress(plain).decode("utf-8"))
    if d.get("format") != DUMP_FORMAT:
        raise ValueError("not an APS Vault dump")
    return d


# ── S3 ─────────────────────────────────────────────────────────────────────
def _s3(method: str, key: str = "", body: bytes = b"", query: str = "", content_type: str = "application/octet-stream") -> bytes:
    import kms
    c = s3_config()
    if s3_missing():
        raise BackupError("S3 is not configured: " + ", ".join(s3_missing()))
    if not endpoint_allowed(c["endpoint"]):
        raise BackupError("VAULT_BACKUP_S3_ENDPOINT must be https:// to a public address (private only with VAULT_WEBHOOK_ALLOW_PRIVATE=1)")
    path = "/" + urllib.parse.quote(c["bucket"]) + ("/" + urllib.parse.quote(key, safe="/-_.~") if key else "")
    url = c["endpoint"].rstrip("/") + path + (("?" + query) if query else "")
    headers = {"x-amz-content-sha256": hashlib.sha256(body).hexdigest()}
    if method == "PUT":
        headers["content-type"] = content_type
    signed = kms._sigv4(method, url, c["region"], "s3", body, headers, c["access_key"], c["secret_key"], None)
    req = urllib.request.Request(url, data=body if method == "PUT" else None, method=method, headers=signed)
    try:
        with netutil.urlopen_noredirect(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:400].decode("utf-8", "replace")
        code = detail.split("<Code>")[1].split("</Code>")[0] if "<Code>" in detail else e.reason
        raise BackupError(f"S3 {method} {e.code}: {code}")
    except Exception as e:
        raise BackupError(f"S3 unreachable: {e.__class__.__name__}: {str(e)[:160]}")


def object_key(created_at: str) -> str:
    """prefix/YYYY/MM/DD/aps-vault-YYYYMMDDTHHMMSS.mmm-<node>-<random>.vbak — unique even for two backups in the same
    second (a manual run next to a scheduled one, two replicas): an existing object is never overwritten."""
    base, _, frac = created_at.rstrip("Z").partition(".")
    t = base.replace(":", "").replace("-", "")                                      # 20261005T181500
    prefix = s3_config()["prefix"]
    return f"{prefix}{t[:4]}/{t[4:6]}/{t[6:8]}/aps-vault-{t}.{(frac + '000')[:3]}-{node()}-{os.urandom(3).hex()}.vbak"


# ── one run ────────────────────────────────────────────────────────────────
def _take_lease(s) -> bool:
    n = s.query(db.BackupState).filter(db.BackupState.id == 1,
                                       (db.BackupState.lease_until.is_(None)) | (db.BackupState.lease_until < now())
                                       ).update({"lease_until": now() + LEASE, "lease_node": node()}, synchronize_session=False)
    s.commit()
    return bool(n)


def _release(s) -> None:
    s.query(db.BackupState).filter_by(id=1, lease_node=node()).update({"lease_until": None}, synchronize_session=False)
    s.commit()


def run(reason: str, emit=None) -> dict | None:
    """Make one backup. `reason`: change | hourly | daily | manual. Returns the run, or None when nothing was due
    (unchanged state, another replica holds the lease)."""
    with db.get_session() as s:
        st = state_row(s)
        if reason != "manual" and not st.enabled:
            return None
        if not st.recipient_pk:
            if reason == "manual":
                raise BackupError("no backup key: set the recipient's public key first")
            return None
        if not _take_lease(s):
            if reason == "manual":
                raise BackupError("another replica is making a backup right now — try again in a minute")
            return None
        try:
            d = dump(s)
            h = state_hash(d)
            st = state_row(s)
            if reason in ("change", "hourly") and h == st.state_hash:
                return None
            r = db.BackupRun(started_at=now(), state="running", reason=reason, node=node())
            s.add(r); s.commit(); s.refresh(r)
            try:
                blob = seal_dump(d, st.recipient_pk, reason)
                key = object_key(d["created_at"])
                _s3("PUT", key, blob, content_type="application/vnd.aps-vault.backup+json")
                r.state, r.object_key, r.size, r.sha256 = "ok", key, len(blob), hashlib.sha256(blob).hexdigest()
                st.state_hash, st.last_ok_at, st.last_error = h, now(), ""
                if reason in ("daily", "manual"):
                    st.last_full_at = now()
            except Exception as e:                                  # keep the reason on the page and in the audit
                r.state, r.error = "failed", str(e)[:500]
                st.last_error = r.error
            r.finished_at = now()
            s.commit()
            out = run_dict(r)
            if emit:
                emit(out)
            return out
        finally:
            _release(s)


def tick(emit=None) -> dict | None:
    with db.get_session() as s:
        st = state_row(s)
        if not st.enabled or not st.recipient_pk:
            return None
        full_due = st.last_full_at is None or now() - st.last_full_at > FULL_EVERY
        hour_due = st.last_ok_at is None or now() - st.last_ok_at > dt.timedelta(hours=1)
        mode = st.mode if st.mode in MODES else "change"
    if full_due:
        return run("daily", emit)
    if mode == "change" or (mode == "hourly" and hour_due):
        return run(mode, emit)
    return None


def run_dict(r) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None
    return {"id": r.id, "started_at": iso(r.started_at), "finished_at": iso(r.finished_at), "state": r.state, "reason": r.reason,
            "object_key": r.object_key or "", "size": r.size or 0, "sha256": r.sha256 or "", "error": r.error or "", "node": r.node or ""}


def status() -> dict:
    c = s3_config()
    with db.get_session() as s:
        st = state_row(s)
        runs = [run_dict(r) for r in s.query(db.BackupRun).order_by(db.BackupRun.id.desc()).limit(20)]
        iso = lambda d: d.isoformat() + "Z" if d else None
        return {"s3": {"configured": not s3_missing(), "missing": s3_missing(), "endpoint": c["endpoint"], "bucket": c["bucket"],
                       "prefix": c["prefix"], "region": c["region"]},
                "enabled": bool(st.enabled), "mode": st.mode or "change", "include_env": st.include_env is not False,
                "env_names": sorted(environment()["vars"]) + sorted(environment()["files"]),
                "key": {"set": bool(st.recipient_pk), "fingerprint": st.recipient_fp or "", "kind": st.recipient_kind or "",
                        "set_at": iso(st.recipient_set_at)},
                "last_ok_at": iso(st.last_ok_at), "last_full_at": iso(st.last_full_at), "last_error": st.last_error or "",
                "tick_sec": cfgmod.SETTINGS.backup_tick_sec, "runs": runs}


def set_recipient(pk_b64: str) -> dict:
    pk = sealed.normalize_public_key(pk_b64)
    with db.get_session() as s:
        st = state_row(s)
        st.recipient_pk, st.recipient_fp, st.recipient_kind, st.recipient_set_at = pk, fingerprint(pk), sealed.key_kind(pk), now()
        st.state_hash = ""                                          # the next tick uploads under the new key
        s.commit()
    return status()["key"]


# ── restore ────────────────────────────────────────────────────────────────
def restore(d: dict, force: bool = False) -> dict:
    """Load a dump into the database this process points at (VAULT_DATABASE_URL / VAULT_DB_PATH). The target must be
    empty (not initialised) unless force=True, which wipes the dumped tables first."""
    from sqlalchemy import text
    if d.get("format") != DUMP_FORMAT:
        raise ValueError("not an APS Vault dump")
    engine = db.get_engine()
    tables = {t.name: t for t in db.Base.metadata.sorted_tables}
    counts = {}
    with engine.begin() as conn:
        if conn.execute(tables["vault_config"].select().limit(1)).first() is not None and not force:
            raise ValueError("the target database is already initialised — restore into an empty one (or --force to wipe it)")
        for t in reversed(db.Base.metadata.sorted_tables):
            if t.name in d["tables"]:
                conn.execute(t.delete())
        for t in db.Base.metadata.sorted_tables:
            rows = d["tables"].get(t.name)
            if not rows:
                continue
            cols = {c.name for c in t.columns}
            conn.execute(t.insert(), [{k: _dec(v) for k, v in row.items() if k in cols} for row in rows])
            counts[t.name] = len(rows)
        if "backup_state" in counts:                              # the scheduler starts from scratch on the new host
            conn.execute(tables["backup_state"].update().values(lease_until=None, lease_node="", state_hash=""))
        if engine.dialect.name == "postgresql":                    # serial columns continue after the restored ids
            for t in db.Base.metadata.sorted_tables:
                for c in t.primary_key.columns:
                    if c.autoincrement is not False and str(c.type).upper().startswith("INTEGER") and t.name in counts:
                        conn.execute(text(f"SELECT setval(pg_get_serial_sequence('{t.name}', '{c.name}'), "
                                          f"COALESCE((SELECT MAX({c.name}) FROM {t.name}), 1))"))
    return counts


def env_file_text(envd: dict) -> str:
    """KEY=value lines for docker compose's .env. Plain values stay bare; anything with spaces, quotes, $, # goes in
    single quotes (literal: no escapes, no interpolation); a value holding a single quote or a newline goes in double
    quotes with \\, \", \n escaped and $ doubled. Round-trip checked with `docker compose config` (tests)."""
    import re as _re
    lines = [f"# APS Vault settings captured on {envd.get('captured_on', '?')} — restore next to docker-compose.yml, mode 0600"]
    for k, v in envd.get("vars", {}).items():
        if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", str(k)):  # 0.41.15: a newline in a name would add lines to .env
            continue
        v = str(v)
        if _re.fullmatch(r"[A-Za-z0-9_./:@%+,=-]+", v):
            out = v
        elif "'" not in v and "\n" not in v:
            out = "'" + v + "'"
        else:
            out = '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$").replace("\n", "\\n") + '"'
        lines.append(f"{k}={out}")
    return "\n".join(lines) + "\n"


def _cli(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="python -m backup", description="APS Vault backups: fetch, list, decrypt, restore")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="objects under VAULT_BACKUP_S3_PREFIX (needs List permission)")
    f = sub.add_parser("fetch", help="download one object to stdout"); f.add_argument("key")
    dcr = sub.add_parser("decrypt", help="decrypt a .vbak into the JSON dump on stdout")
    dcr.add_argument("file"); dcr.add_argument("--key", required=True, help="file with the recipient's private key (base64)")
    e = sub.add_parser("env", help="the environment from a decrypted dump as a .env file (stdout); --files-dir writes key files")
    e.add_argument("dump"); e.add_argument("--files-dir", default="")
    r = sub.add_parser("restore", help="load a decrypted dump into the configured database")
    r.add_argument("dump"); r.add_argument("--force", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "list":
        import re
        xml = _s3("GET", query="list-type=2&max-keys=1000&prefix=" + urllib.parse.quote(s3_config()["prefix"], safe="")).decode()
        for k, size in zip(re.findall(r"<Key>([^<]+)</Key>", xml), re.findall(r"<Size>(\d+)</Size>", xml)):
            print(size.rjust(10), k)
        return 0
    if a.cmd == "fetch":
        sys.stdout.buffer.write(_s3("GET", a.key))
        return 0
    if a.cmd == "decrypt":
        d = open_backup(open(a.file, "rb").read(), open(a.key).read())
        json.dump(d, sys.stdout, ensure_ascii=False)
        return 0
    if a.cmd == "env":
        d = json.load(open(a.dump, encoding="utf-8"))
        envd = d.get("environment")
        if not envd:
            print("this backup has no environment (made with 'include settings' off, or before 0.40)", file=sys.stderr)
            return 1
        sys.stdout.write(env_file_text(envd))
        if a.files_dir:
            os.makedirs(a.files_dir, mode=0o700, exist_ok=True)
            import re as _re
            for k, content in envd.get("files", {}).items():
                if not _re.fullmatch(r"[A-Za-z0-9_]{1,128}", k):          # 0.41.15: a name from the dump is data, not a path
                    print(f"{k!r}: not a variable name — skipped", file=sys.stderr)
                    continue
                p = os.path.join(a.files_dir, k.lower() + ".json")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                os.chmod(p, 0o600)
                print(f"{k}: written to {p} — point {k} at it", file=sys.stderr)
        return 0
    if a.cmd == "restore":
        counts = restore(json.load(open(a.dump, encoding="utf-8")), force=a.force)
        print(json.dumps({"restored": counts}, ensure_ascii=False), file=sys.stderr)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
