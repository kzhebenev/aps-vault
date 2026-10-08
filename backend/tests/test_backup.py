"""Encrypted backups to S3 (0.39): what goes in, when it goes, who can read it, and that it restores into a vault."""
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import db
import netutil
import settings
from conftest import MASTER, unlock

AK, SK = "TESTAKIDEXAMPLE", "test-secret-key-0123456789"


class FakeS3:
    """S3 PutObject/GetObject on 127.0.0.1 that verifies SigV4 with its OWN implementation (not kms._sigv4) and
    answers like Ceph RGW / AWS: SignatureDoesNotMatch, AccessDenied, NoSuchKey."""

    def __init__(self):
        self.objects, self.requests, self.deny = {}, [], False
        s3 = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _err(self, code, name):
                b = f"<?xml version='1.0'?><Error><Code>{name}</Code></Error>".encode()
                self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

            def _verify(self, body: bytes) -> bool:
                auth = self.headers.get("Authorization", "")
                try:
                    cred = auth.split("Credential=")[1].split(",")[0]; signed = auth.split("SignedHeaders=")[1].split(",")[0]
                    sig = auth.split("Signature=")[1].strip()
                except IndexError:
                    return False
                ak, date, region, service, _ = cred.split("/")
                if ak != AK or self.headers.get("x-amz-content-sha256") != hashlib.sha256(body).hexdigest():
                    return False
                u = urllib.parse.urlsplit(self.path)
                hdrs = "".join(f"{h}:{self.headers.get(h, '').strip()}\n" for h in signed.split(";"))
                canon = "\n".join([self.command, u.path, u.query, hdrs, signed, hashlib.sha256(body).hexdigest()])
                scope = f"{date}/{region}/{service}/aws4_request"
                sts = "\n".join(["AWS4-HMAC-SHA256", self.headers.get("x-amz-date", ""), scope, hashlib.sha256(canon.encode()).hexdigest()])
                k = ("AWS4" + SK).encode()
                for part in (date, region, service, "aws4_request"):
                    k = hmac.new(k, part.encode(), hashlib.sha256).digest()
                return hmac.compare_digest(hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), sig)

            def do_PUT(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                s3.requests.append(("PUT", self.path))
                if not self._verify(body): return self._err(403, "SignatureDoesNotMatch")
                if s3.deny: return self._err(403, "AccessDenied")
                s3.objects[urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)] = body
                self.send_response(200); self.send_header("ETag", '"x"'); self.send_header("Content-Length", "0"); self.end_headers()

            def do_GET(self):
                s3.requests.append(("GET", self.path))
                if not self._verify(b""): return self._err(403, "SignatureDoesNotMatch")
                b = s3.objects.get(urllib.parse.unquote(urllib.parse.urlsplit(self.path).path))
                if b is None: return self._err(404, "NoSuchKey")
                self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.endpoint = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture
def s3(monkeypatch):
    f = FakeS3()
    for k, v in {"backup_s3_endpoint": f.endpoint, "backup_s3_bucket": "vault-backups", "backup_s3_prefix": "test/",
                 "backup_s3_region": "ru-1", "backup_s3_access_key": AK, "backup_s3_secret_key": SK}.items():
        monkeypatch.setattr(settings.SETTINGS, k, v)
    with db.get_session() as s:                       # every test starts from a clean backup state
        s.query(db.BackupRun).delete(); s.query(db.BackupState).delete(); s.commit()
    yield f
    f.srv.shutdown()


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "bk-folder"}, headers=hdr).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "bk-secret", "value": "value-to-survive", "notes": "n"}, headers=hdr).json()["id"]
    return {"hdr": hdr, "fid": fid, "sid": sid}


def _keygen(client, hdr, kind=""):
    r = client.post("/api/backup/keygen", json={"master_password": MASTER, "kind": kind}, headers=hdr)
    assert r.status_code == 200, r.text
    return r.json()


def _objects(s3):
    return {k: v for k, v in s3.objects.items()}


def test_settings_are_the_owners_and_the_key_needs_the_master_password(client, world, s3, monkeypatch):
    import main
    from fastapi.testclient import TestClient
    from test_security_review_2026_10_05 import ORIGIN, _login, _user
    hdr = world["hdr"] = unlock(client)
    assert TestClient(main.app, base_url=ORIGIN).get("/api/backup/status").status_code == 401
    st = client.get("/api/backup/status", headers=hdr).json()
    assert st["s3"]["configured"] and not st["key"]["set"] and st["enabled"] is False
    r = client.put("/api/backup/config", json={"enabled": True}, headers=hdr)
    assert r.status_code == 409 and "key" in r.text, "no recipient — nothing to encrypt to"
    netutil.clear_fails("testclient")
    assert client.post("/api/backup/keygen", json={"master_password": "wrong wrong wrong"}, headers=hdr).status_code == 401
    assert client.put("/api/backup/key", json={"public_key": "A" * 44, "master_password": "wrong wrong"}, headers=hdr).status_code == 401
    netutil.clear_fails("testclient")
    assert client.put("/api/backup/key", json={"public_key": "not-a-key-" * 5, "master_password": MASTER}, headers=hdr).status_code == 422
    k = _keygen(client, hdr)
    import suite
    want = ("gost-pqc", 1248) if suite.active() == "gost" else ("pqc", 1216)    # the post-quantum hybrid of the vault's suite
    assert (k["kind"], len(base64.b64decode(k["public_key"]))) == want, (k["kind"], want)
    st = client.get("/api/backup/status", headers=hdr).json()
    assert st["key"] == {**st["key"], "set": True, "fingerprint": k["fingerprint"], "kind": want[0]}
    assert k["private_key"] not in json.dumps(st)
    with db.get_session() as s:
        row = s.get(db.BackupState, 1)
        assert row.recipient_pk == k["public_key"] and k["private_key"] not in (row.recipient_pk or ""), "the server keeps only the public half"
    assert client.put("/api/backup/config", json={"enabled": True, "mode": "change"}, headers=hdr).json()["enabled"] is True
    assert client.put("/api/backup/config", json={"mode": "weekly"}, headers=hdr).status_code == 422
    # without S3 settings it cannot be turned on
    client.put("/api/backup/config", json={"enabled": False}, headers=hdr)
    monkeypatch.setattr(settings.SETTINGS, "backup_s3_secret_key", "")
    r = client.put("/api/backup/config", json={"enabled": True}, headers=hdr)
    assert r.status_code == 409 and "VAULT_BACKUP_S3_SECRET_KEY" in r.text
    # a person who is not the owner
    uid = _user(client, hdr, "bk-reader@example.com", world["fid"])
    c, rr = _login("bk-reader@example.com")
    assert c.get("/api/backup/status").status_code == 403
    assert c.post("/api/backup/run", headers={"X-CSRF-Token": rr.json()["csrf_token"]}).status_code == 403


def test_a_backup_is_encrypted_to_the_recipient_and_only_its_key_opens_it(client, world, s3):
    import backup
    hdr = world["hdr"] = unlock(client)
    k = _keygen(client, hdr)
    r = client.post("/api/backup/run", headers=hdr)
    assert r.status_code == 200 and r.json()["state"] == "ok", r.text
    key = r.json()["object_key"]
    assert key.startswith("test/") and key.endswith(".vbak")
    blob = s3.objects["/vault-backups/" + key]
    assert r.json()["sha256"] == hashlib.sha256(blob).hexdigest()
    raw = blob.decode()
    for leak in ("bk-secret", "bk-folder", "value-to-survive", "audit_log", "vault_config"):
        assert leak not in raw, f"{leak} is visible in the uploaded object"
    d = backup.open_backup(blob, k["private_key"])
    assert {"secrets", "folders", "vault_config", "audit_log", "users"} <= set(d["tables"])
    assert not set(d["tables"]) & backup.SKIP_TABLES, "sessions, challenges, lock-outs are not backed up"
    row = next(x for x in d["tables"]["secrets"] if x["name"] == "bk-secret")
    assert "$b64" in row["value_enc"] and "value-to-survive" not in json.dumps(d), "values stay ciphertext inside the dump"
    # the wrong key, a changed header, a changed ciphertext
    other_sk, _ = __import__("sealed").generate_keypair("pqc")
    with pytest.raises(ValueError, match="cannot open"):
        backup.open_backup(blob, other_sk)
    obj = json.loads(blob)
    for field, val in (("created_at", "2020-01-01T00:00:00Z"), ("vault_version", "0.0.1")):
        with pytest.raises(ValueError, match="cannot open"):
            backup.open_backup(json.dumps({**obj, field: val}).encode(), k["private_key"])
    env = dict(obj["sealed"]); ct = bytearray(base64.b64decode(env["ct"])); ct[10] ^= 1; env["ct"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(ValueError, match="cannot open"):
        backup.open_backup(json.dumps({**obj, "sealed": env}).encode(), k["private_key"])
    # the classic X25519 recipient works too
    k2 = _keygen(client, hdr, "x25519")
    r2 = client.post("/api/backup/run", headers=hdr).json()
    assert backup.open_backup(s3.objects["/vault-backups/" + r2["object_key"]], k2["private_key"])["tables"]["secrets"]


def test_change_mode_uploads_on_writes_not_on_reads_and_a_daily_copy_always(client, world, s3):
    import backup
    hdr = world["hdr"] = unlock(client)
    _keygen(client, hdr)
    client.put("/api/backup/config", json={"enabled": True, "mode": "change"}, headers=hdr)
    first = backup.tick()
    assert first and first["state"] == "ok" and first["reason"] == "daily", "the first tick makes the daily full copy"
    n = len(s3.objects)
    assert backup.tick() is None and len(s3.objects) == n, "nothing changed — nothing uploaded"
    for _ in range(3):                                            # reads bump counters and write audit rows
        assert client.get(f"/api/secrets/{world['sid']}", headers=hdr).json()["value"] == "value-to-survive"
    assert backup.tick() is None and len(s3.objects) == n, "reads are not changes"
    client.patch(f"/api/secrets/{world['sid']}", json={"notes": "changed"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": world["fid"], "name": "bk-second", "value": "v2"}, headers=hdr)
    r = backup.tick()
    assert r and r["reason"] == "change" and len(s3.objects) == n + 1, "two edits within a tick → one object"
    assert backup.tick() is None
    # hourly: a change waits for the hour
    client.put("/api/backup/config", json={"mode": "hourly"}, headers=hdr)
    client.patch(f"/api/secrets/{world['sid']}", json={"notes": "changed again"}, headers=hdr)
    assert backup.tick() is None, "hourly mode: the last upload is minutes old"
    with db.get_session() as s:
        s.get(db.BackupState, 1).last_ok_at = backup.now() - dt.timedelta(hours=2); s.commit()
    assert backup.tick()["reason"] == "hourly"
    # daily copy even without changes
    with db.get_session() as s:
        s.get(db.BackupState, 1).last_full_at = backup.now() - dt.timedelta(hours=25); s.commit()
    assert backup.tick()["reason"] == "daily"
    # disabled: nothing
    client.put("/api/backup/config", json={"enabled": False}, headers=hdr)
    client.patch(f"/api/secrets/{world['sid']}", json={"notes": "while off"}, headers=hdr)
    assert backup.tick() is None


def test_one_replica_at_a_time_and_failures_are_visible(client, world, s3, monkeypatch):
    import backup
    hdr = world["hdr"] = unlock(client)
    _keygen(client, hdr)
    client.put("/api/backup/config", json={"enabled": True}, headers=hdr)
    with db.get_session() as s:
        st = s.get(db.BackupState, 1); st.lease_until, st.lease_node = backup.now() + dt.timedelta(minutes=5), "other-replica"; s.commit()
    assert backup.tick() is None, "another replica holds the lease"
    r = client.post("/api/backup/run", headers=hdr)
    assert r.status_code == 409 and "another replica" in r.text
    with db.get_session() as s:
        s.get(db.BackupState, 1).lease_until = None; s.commit()
    monkeypatch.setattr(settings.SETTINGS, "backup_s3_secret_key", "wrong-secret")
    r = client.post("/api/backup/run", headers=hdr).json()
    assert r["state"] == "failed" and "SignatureDoesNotMatch" in r["error"]
    monkeypatch.setattr(settings.SETTINGS, "backup_s3_secret_key", SK)
    s3.deny = True
    r = client.post("/api/backup/run", headers=hdr).json()
    assert r["state"] == "failed" and "AccessDenied" in r["error"]
    st = client.get("/api/backup/status", headers=hdr).json()
    assert "AccessDenied" in st["last_error"] and st["runs"][0]["state"] == "failed"
    acts = [a["action"] for a in client.get("/api/audit", params={"limit": 40}, headers=hdr).json()]
    assert "backup:failed" in acts and "backup:keygen" in acts
    s3.deny = False
    with db.get_session() as s:
        assert s.get(db.BackupState, 1).lease_until is None, "the lease is released after a failure"
    # http to a public address is refused (https only), as for every outbound call
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", False)
    monkeypatch.setattr(settings.SETTINGS, "backup_s3_endpoint", "http://s3.example.com")
    r = client.post("/api/backup/run", headers=hdr)
    assert r.json()["state"] == "failed" and "https" in r.json()["error"]


RESTORE = r'''
import json, os, sys
sys.path.insert(0, os.getcwd())
import backup, db
d = backup.open_backup(open(sys.argv[1], "rb").read(), open(sys.argv[2]).read())
print(json.dumps(backup.restore(d)))
from fastapi.testclient import TestClient
import main
c = TestClient(main.app, base_url="https://vault.test")
r = c.post("/api/auth/unlock", json={"master_password": sys.argv[3]})
assert r.status_code == 200, r.text
h = {"X-CSRF-Token": r.json()["csrf_token"]}
sid = next(x["id"] for x in c.get("/api/secrets").json() if x["name"] == "bk-secret")
print("VALUE=" + c.get(f"/api/secrets/{sid}").json()["value"])
bs = c.get("/api/backup/status").json()
print("BACKUPKEY=" + bs["key"]["fingerprint"] + " ENABLED=" + str(bs["enabled"]))
with db.get_session() as s:
    st = s.get(db.BackupState, 1); print("LEASE=" + str(st.lease_until) + " HASH=" + repr(st.state_hash))
try:
    backup.restore(d)
    print("SECOND-RESTORE-ALLOWED")
except ValueError as e:
    print("SECOND-RESTORE-REFUSED " + str(e)[:40])
'''


def test_a_backup_restores_into_an_empty_vault_that_opens_with_the_master_password(client, world, s3, tmp_path):
    hdr = world["hdr"] = unlock(client)
    k = _keygen(client, hdr)
    key = client.post("/api/backup/run", headers=hdr).json()["object_key"]
    (tmp_path / "b.vbak").write_bytes(s3.objects["/vault-backups/" + key])
    (tmp_path / "k").write_text(k["private_key"])
    (tmp_path / "restore.py").write_text(RESTORE)
    env = {k2: v for k2, v in os.environ.items() if not k2.startswith(("VAULT_DATABASE_URL", "TEST_DATABASE_URL"))}
    env.update(VAULT_DATA_DIR=str(tmp_path / "data"), VAULT_DB_PATH=str(tmp_path / "data" / "restored.db"), VAULT_BACKUP_TICK_SEC="0",
               VAULT_ROTATION_TICK_SEC="0")
    p = subprocess.run([sys.executable, str(tmp_path / "restore.py"), str(tmp_path / "b.vbak"), str(tmp_path / "k"), MASTER],
                       capture_output=True, text=True, env=env, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), timeout=300)
    assert p.returncode == 0, p.stdout[-800:] + p.stderr[-1500:]
    assert "VALUE=value-to-survive" in p.stdout, p.stdout[-500:]
    assert "SECOND-RESTORE-REFUSED" in p.stdout, "an initialised database is not overwritten without --force"
    assert f"BACKUPKEY={k['fingerprint']}" in p.stdout, "0.40: the restored vault keeps backing up to the same recipient"
    assert "LEASE=None HASH=''" in p.stdout, "the lease and the change hash start fresh on the new host"


def test_the_environment_goes_into_the_sealed_backup_only(client, world, s3, monkeypatch, tmp_path):
    """0.40: VAULT_* / OIDC_* settings (resolved *_FILE values, key files) travel inside the sealed payload; the object
    and the status page never show a value; a changed environment is a change; the switch turns it off."""
    import backup
    hdr = world["hdr"] = unlock(client)
    k = _keygen(client, hdr)
    tricky = "env-secret-0510 it's $HOME \"q\" #x"
    monkeypatch.setenv("VAULT_TEST_TRICKY_SETTING", tricky)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "oidc-secret-0510")
    (tmp_path / "sso").write_text("sso-key-from-file-0510\n")
    monkeypatch.setenv("VAULT_TEST_FROMFILE_FILE", str(tmp_path / "sso"))
    monkeypatch.delenv("VAULT_TEST_FROMFILE", raising=False)
    (tmp_path / "ya.json").write_text('{"id": "ajexyz", "private_key": "PRIVATE-0510"}')
    monkeypatch.setenv("VAULT_KMS_YANDEX_KEY_FILE", str(tmp_path / "ya.json"))
    st = client.get("/api/backup/status", headers=hdr).json()
    assert st["include_env"] is True and "VAULT_TEST_TRICKY_SETTING" in st["env_names"] and "OIDC_CLIENT_SECRET" in st["env_names"]
    page = json.dumps(st)
    assert "env-secret-0510" not in page and "oidc-secret-0510" not in page and "PRIVATE-0510" not in page, "names only on the page"
    r = client.post("/api/backup/run", headers=hdr).json()
    blob = s3.objects["/vault-backups/" + r["object_key"]]
    for leak in (b"env-secret-0510", b"oidc-secret-0510", b"sso-key-from-file", b"PRIVATE-0510", b"VAULT_TEST_TRICKY"):
        assert leak not in blob, leak
    env = backup.open_backup(blob, k["private_key"])["environment"]
    assert env["vars"]["VAULT_TEST_TRICKY_SETTING"] == tricky and env["vars"]["OIDC_CLIENT_SECRET"] == "oidc-secret-0510"
    assert env["vars"]["VAULT_TEST_FROMFILE"] == "sso-key-from-file-0510" and "VAULT_TEST_FROMFILE_FILE" not in env["vars"], "the value, not the path"
    assert "PRIVATE-0510" in env["files"]["VAULT_KMS_YANDEX_KEY_FILE"], "a key file that is a setting by itself is carried"
    assert not any(n.startswith(("PATH", "HOME", "HOSTNAME")) for n in env["vars"]), "only VAULT_* / OIDC_*"
    text = backup.env_file_text(env)
    assert "VAULT_TEST_FROMFILE=sso-key-from-file-0510\n" in text and "OIDC_CLIENT_SECRET=oidc-secret-0510\n" in text
    assert "VAULT_TEST_TRICKY_SETTING=\"env-secret-0510 it's $$HOME \\\"q\\\" #x\"\n" in text, text   # single quote inside → double quotes, $ doubled
    # a changed environment is a change (a restart with a new key must reach the bucket without waiting a day)
    client.put("/api/backup/config", json={"enabled": True, "mode": "change"}, headers=hdr)
    backup.tick()
    assert backup.tick() is None
    monkeypatch.setenv("VAULT_TEST_TRICKY_SETTING", "rotated-value")
    assert backup.tick()["reason"] == "change"
    # off: the database only
    assert client.put("/api/backup/config", json={"include_env": False}, headers=hdr).json()["include_env"] is False
    r = client.post("/api/backup/run", headers=hdr).json()
    assert "environment" not in backup.open_backup(s3.objects["/vault-backups/" + r["object_key"]], k["private_key"])
    client.put("/api/backup/config", json={"include_env": True, "enabled": False}, headers=hdr)
