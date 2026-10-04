"""Rotation in target systems (0.24): the vault changes the credential in the target, proves it,
and only then stores it. HTTP receiver (signed, value inside), PostgreSQL role (ALTER ROLE +
login with the new password — negative: the old password must stop working), roles, the
scheduler's atomic claim and the automation cell that it needs."""
import hashlib
import hmac
import json
import os
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

import db
import netutil
import settings
from conftest import unlock

PG_DSN = os.environ.get("TEST_ROTATION_PG_DSN", "")


class _Receiver(BaseHTTPRequestHandler):
    """The target side of an http rotation: records the body, answers what the test says."""
    received = []
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        _Receiver.received.append((dict(self.headers), body))
        self.send_response(_Receiver.status); self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def receiver():
    srv = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/rotate"
    srv.shutdown()


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "rot-apps"}, headers=hdr).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "broker-pass", "value": "old-broker-pw", "login": "app_broker"}, headers=hdr).json()["id"]
    return {"hdr": hdr, "fid": fid, "sid": sid}


def _user(client, hdr, email, grants, pw="rotation user password!"):
    r = client.post("/api/users", json={"email": email, "grants": grants}, headers=hdr).json()
    import main
    with TestClient(main.app, base_url="https://vault.test") as anon:
        assert anon.post(f"/api/invite/{r['invite_url'].rsplit('/', 1)[-1]}", json={"password": pw}).status_code == 200
    c = TestClient(main.app, base_url="https://vault.test")
    netutil.clear_fails("testclient")
    lr = c.post("/api/auth/login", json={"email": email, "password": pw}); assert lr.status_code == 200, lr.text
    return c, {"X-CSRF-Token": lr.json()["csrf_token"]}, r["id"]


# ─── http target ─────────────────────────────────────────────────────────────
def test_http_target_applies_then_stores_and_signs(client, world, receiver):
    hdr, sid = world["hdr"], world["sid"]
    _Receiver.received.clear(); _Receiver.status = 200
    r = client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": receiver, "headers": {"X-Env": "test"}}, "interval_days": 0}, headers=hdr)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target"] == "http" and body["interval_days"] == 0 and body["scheduler"] == "manual"
    signing = body["signing_secret"]
    assert len(signing) == 64 and body["config"]["has_signing_secret"] is True and "signing_secret" not in body["config"]
    # the card shows the rotation without exposing the config
    item = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    assert item["rotation"]["target"] == "http" and item["rotation"]["last_status"] == "" and "config" not in item["rotation"]
    # run: receiver gets the NEW value, signed; the vault stores exactly that value as version 2
    run = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
    assert run.status_code == 200, run.text
    assert run.json()["version"] == 2 and run.json()["previous_version"] == 1
    assert len(_Receiver.received) == 1
    headers, raw = _Receiver.received[0]
    payload = json.loads(raw)
    assert payload["event"] == "rotation" and payload["secret"] == "broker-pass" and payload["folder"] == "rot-apps" and payload["login"] == "app_broker" and payload["version"] == 2
    assert headers["X-Vault-Signature"] == "sha256=" + hmac.new(signing.encode(), raw, hashlib.sha256).hexdigest(), "the receiver can verify the body"
    assert headers["X-Env"] == "test" and headers["X-Vault-Event"] == "rotation"
    now = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    assert now["value"] == payload["value"] != "old-broker-pw" and len(payload["value"]) >= 32
    hist = client.get(f"/api/secrets/{sid}/history", headers=hdr).json()["history"]
    assert hist[0]["value"] == "old-broker-pw" and hist[0]["changed_by"] == "master:rotate"
    assert now["rotation"]["last_status"] == "ok" and now["rotation"]["runs"] == 1
    acts = client.get("/api/audit", params={"limit": 30}, headers=hdr).json()
    assert any(a["action"] == "rotation:run" and a["target"] == "rot-apps/broker-pass" for a in acts)
    # a second save keeps the signing secret (no new one in the answer), and the receiver still verifies
    r2 = client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": receiver}, "interval_days": 0}, headers=hdr).json()
    assert "signing_secret" not in r2
    _Receiver.received.clear()
    assert client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr).status_code == 200
    headers, raw = _Receiver.received[0]
    assert headers["X-Vault-Signature"] == "sha256=" + hmac.new(signing.encode(), raw, hashlib.sha256).hexdigest()


def test_http_receiver_failure_keeps_the_old_value(client, world, receiver):
    hdr, sid = world["hdr"], world["sid"]
    before = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    _Receiver.received.clear(); _Receiver.status = 500
    try:
        run = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
        assert run.status_code == 502 and "HTTP 500" in run.json()["detail"], run.text
    finally:
        _Receiver.status = 200
    acts = client.get("/api/audit", params={"limit": 10}, headers=hdr).json()
    assert acts[0]["action"] == "rotation:fail"
    after = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    assert after["value"] == before["value"] and after["version"] == before["version"], "nothing stored, nothing archived"
    assert after["rotation"]["last_status"] == "err" and "HTTP 500" in after["rotation"]["last_error"]


def test_http_url_rules(client, world, receiver, monkeypatch):
    hdr, fid = world["hdr"], world["fid"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "url-rules", "value": "v"}, headers=hdr).json()["id"]
    bad = lambda cfg: client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": cfg}, headers=hdr)
    assert bad({"url": "ftp://x"}).status_code == 422
    assert bad({"url": "https://example.com", "method": "DELETE"}).status_code == 422
    assert bad({"url": "https://example.com", "headers": {"Content-Type": "x"}}).status_code == 422, "the signature headers cannot be overridden"
    assert client.put(f"/api/secrets/{sid}/rotation", json={"target": "nope", "config": {}}, headers=hdr).status_code == 422
    # outside the test environment: plain http and private addresses are refused — the request carries the value
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", False)
    r = bad({"url": receiver})
    assert r.status_code == 422 and "https" in r.json()["detail"]
    r = bad({"url": "https://127.0.0.1:9/x"})
    assert r.status_code == 422 and "not allowed" in r.json()["detail"]
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", True)
    assert client.delete(f"/api/secrets/{sid}", headers=hdr).status_code == 200


# ─── roles ───────────────────────────────────────────────────────────────────
def test_roles_reader_writer_manager(client, world, receiver):
    hdr, fid, sid = world["hdr"], world["fid"], world["sid"]
    _Receiver.status = 200
    rc, rh, _ = _user(client, hdr, "rot-reader@example.com", [{"folder_id": fid, "role": "reader"}])
    wc, wh, _ = _user(client, hdr, "rot-writer@example.com", [{"folder_id": fid, "role": "writer"}])
    mc, mh, _ = _user(client, hdr, "rot-manager@example.com", [{"folder_id": fid, "role": "manager"}])
    body = {"target": "http", "config": {"url": receiver}}
    assert rc.put(f"/api/secrets/{sid}/rotation", json=body, headers=rh).status_code == 403
    assert rc.post(f"/api/secrets/{sid}/rotation/run", headers=rh).status_code == 403
    assert wc.put(f"/api/secrets/{sid}/rotation", json=body, headers=wh).status_code == 403, "configuring is a manager's job"
    assert wc.post(f"/api/secrets/{sid}/rotation/run", headers=wh).status_code == 200, "running it is a writer's"
    assert mc.put(f"/api/secrets/{sid}/rotation", json=body, headers=mh).status_code == 200
    # everyone with the folder sees the status; the list of rotations is scoped to granted folders
    assert rc.get(f"/api/secrets/{sid}", headers=rh).json()["rotation"]["target"] == "http"
    assert [x["secret_name"] for x in rc.get("/api/rotations").json()] == ["broker-pass"]
    assert rc.get("/api/rotations/status").json()["total"] == 1
    # the owner's write cells button is the owner's
    assert mc.post("/api/rotations/cells", headers=mh).status_code == 403
    acts = client.get("/api/audit", params={"limit": 10}, headers=hdr).json()
    assert any(a["action"] == "rotation:run" and a["actor"] == "rot-writer@example.com" for a in acts)


# ─── scheduler ───────────────────────────────────────────────────────────────
def test_scheduler_needs_the_server_key_and_claims_each_due_row_once(client, world, receiver, monkeypatch):
    import main
    hdr, fid, sid = world["hdr"], world["fid"], world["sid"]
    _Receiver.status = 200
    # no server key: the schedule is saved but honestly reported as unavailable; the tick does nothing
    monkeypatch.setattr(settings.SETTINGS, "rotation_key", b"")
    r = client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": receiver}, "interval_days": 30}, headers=hdr).json()
    assert r["interval_days"] == 30 and r["next_at"] and "VAULT_ROTATION_KEY" in r["scheduler"] and r["cells_written"] == 0
    st = client.get("/api/rotations/status", headers=hdr).json()
    assert st["configured"] is False and st["scheduled"] == 1 and st["cells_missing"] == ["rot-apps"]
    assert client.post("/api/rotations/cells", headers=hdr).status_code == 409
    with db.get_session() as s:
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first(); rot.next_at = db.utcnow().replace(tzinfo=None) - timedelta(minutes=1); s.commit()
    assert main._rotation_tick_sync() == 0
    # with the key: cells are written by the owner, the due row is claimed once and rotated by "scheduler"
    monkeypatch.setattr(settings.SETTINGS, "rotation_key", os.urandom(32))
    assert client.post("/api/rotations/cells", headers=hdr).json()["folders"] == 1
    st = client.get("/api/rotations/status", headers=hdr).json()
    assert st["configured"] is True and st["cells_missing"] == [] and st["due"] == 1
    before = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    _Receiver.received.clear()
    assert main._rotation_tick_sync() == 1
    assert main._rotation_tick_sync() == 0, "claimed rows are not due any more"
    after = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    assert after["version"] == before["version"] + 1 and after["value"] == json.loads(_Receiver.received[0][1])["value"]
    nxt = db.utcnow().replace(tzinfo=None) + timedelta(days=30)
    from datetime import datetime
    assert abs((datetime.fromisoformat(after["rotation"]["next_at"]) - nxt).total_seconds()) < 120, after["rotation"]["next_at"]
    acts = client.get("/api/audit", params={"limit": 10}, headers=hdr).json()
    assert any(a["action"] == "rotation:run" and a["actor"] == "scheduler" for a in acts)
    # a failing scheduled run is retried in an hour, not every tick
    with db.get_session() as s:
        rot = s.query(db.Rotation).filter_by(secret_id=sid).first(); rot.next_at = db.utcnow().replace(tzinfo=None) - timedelta(minutes=1); s.commit()
    _Receiver.status = 500
    try:
        assert main._rotation_tick_sync() == 0
    finally:
        _Receiver.status = 200
    row = client.get(f"/api/secrets/{sid}", headers=hdr).json()["rotation"]
    assert row["last_status"] == "err" and 50 * 60 < (datetime.fromisoformat(row["next_at"]) - db.utcnow().replace(tzinfo=None)).total_seconds() < 70 * 60
    # deleting the rotation drops the folder's automation cell (least privilege)
    assert client.delete(f"/api/secrets/{sid}/rotation", headers=hdr).status_code == 200
    with db.get_session() as s:
        assert not s.get(db.Folder, fid).automation_key_enc
    assert client.get(f"/api/secrets/{sid}", headers=hdr).json()["rotation"] is None


def test_move_keeps_the_rotation_working(client, world, receiver):
    hdr, fid, sid = world["hdr"], world["fid"], world["sid"]
    _Receiver.status = 200
    other = client.post("/api/folders", json={"name": "rot-moved"}, headers=hdr).json()["id"]
    assert client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": receiver}}, headers=hdr).status_code == 200
    assert client.patch(f"/api/secrets/{sid}", json={"folder_id": other}, headers=hdr).status_code == 200
    r = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
    assert r.status_code == 200, r.text
    assert json.loads(_Receiver.received[-1][1])["folder"] == "rot-moved", "the config was re-wrapped under the new folder's key"
    assert client.patch(f"/api/secrets/{sid}", json={"folder_id": fid}, headers=hdr).status_code == 200


# ─── postgres target ─────────────────────────────────────────────────────────
@pytest.mark.skipif(not PG_DSN, reason="НЕ НАСТРОЕНО: TEST_ROTATION_PG_DSN is not set — no PostgreSQL to rotate a role in")
def test_postgres_role_password_is_changed_verified_and_the_old_one_stops_working(client, world):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    hdr, fid = world["hdr"], world["fid"]
    role, old_pw = "rot_app_user", "old-pg-password-1"
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(old_pw)))
    dsn_folder = client.post("/api/folders", json={"name": "rot-pg-admin"}, headers=hdr).json()["id"]
    dsn_sid = client.post("/api/secrets", json={"folder_id": dsn_folder, "name": "pg-admin-dsn", "value": PG_DSN, "machine_only": True}, headers=hdr).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "pg-app-password", "value": old_pw, "login": role}, headers=hdr).json()["id"]
    # a wrong DSN secret id is refused at save time
    assert client.put(f"/api/secrets/{sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": 999999}}, headers=hdr).status_code == 422
    assert client.put(f"/api/secrets/{sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": dsn_sid, "role": "bad role;"}}, headers=hdr).status_code == 422
    r = client.put(f"/api/secrets/{sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": dsn_sid}, "generate": "alnum:40"}, headers=hdr)
    assert r.status_code == 200, r.text
    run = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
    assert run.status_code == 200, run.text
    new_pw = client.get(f"/api/secrets/{sid}", headers=hdr).json()["value"]
    assert new_pw != old_pw and len(new_pw) == 40
    host_dsn = conninfo_to_dict(PG_DSN)
    def login(pw):
        d = dict(host_dsn); d.update(user=role, password=pw)
        with psycopg.connect(make_conninfo(**d), connect_timeout=5) as c:
            return c.execute("SELECT current_user").fetchone()[0]
    assert login(new_pw) == role, "the new password works in PostgreSQL"
    with pytest.raises(psycopg.OperationalError):
        login(old_pw)
    # a role that cannot log in: ALTER succeeds, the probe fails, the previous password is restored, the vault keeps it
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(role)))
    run2 = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
    assert run2.status_code == 502 and "old password restored" in run2.json()["detail"], run2.text
    assert client.get(f"/api/secrets/{sid}", headers=hdr).json()["value"] == new_pw
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(role)))
    assert login(new_pw) == role, "the restored password is the one the vault holds"
    # a broken administrator DSN: refused, nothing changes
    client.patch(f"/api/secrets/{dsn_sid}", json={"value": PG_DSN.replace("vault:vault@", "vault:wrong@")}, headers=hdr)
    run3 = client.post(f"/api/secrets/{sid}/rotation/run", headers=hdr)
    assert run3.status_code == 502 and "administrator connection failed" in run3.json()["detail"]
    assert login(new_pw) == role
    # scheduled: the DSN folder gets an automation cell too, and the scheduler rotates with no session at all
    client.patch(f"/api/secrets/{dsn_sid}", json={"value": PG_DSN}, headers=hdr)
    import main
    saved = settings.SETTINGS.rotation_key
    settings.SETTINGS.rotation_key = os.urandom(32)
    try:
        r = client.put(f"/api/secrets/{sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": dsn_sid}, "interval_days": 7}, headers=hdr).json()
        assert r["cells_written"] == 2
        with db.get_session() as s:
            rot = s.query(db.Rotation).filter_by(secret_id=sid).first(); rot.next_at = db.utcnow().replace(tzinfo=None) - timedelta(minutes=1); s.commit()
        assert main._rotation_tick_sync() == 1
        pw3 = client.get(f"/api/secrets/{sid}", headers=hdr).json()["value"]
        assert pw3 != new_pw and login(pw3) == role
        with pytest.raises(psycopg.OperationalError):
            login(new_pw)
    finally:
        settings.SETTINGS.rotation_key = saved
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
