"""Approval workflow (0.12): a secret flagged `require_approval` is read by a person only after
a second person — the approver, with a password of their own — confirms a request. The
approver gets a link through a configurable notifier (any webhook: Telegram, Slack, ntfy, a
company gateway) and never sees the value. Machines are unaffected."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import netutil
import settings
from conftest import MASTER, unlock

APPROVER = "approver password 2026 ok"


@pytest.fixture
def notify_sink(monkeypatch):
    """A tiny HTTP receiver standing in for Telegram/Slack/our gateway."""
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": self.rfile.read(n).decode()})
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass

    srv = HTTPServer(("127.0.0.1", 0), H); th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
    url = f"http://127.0.0.1:{srv.server_port}/notify"
    monkeypatch.setenv("VAULT_APPROVAL_NOTIFY_URL", url)
    monkeypatch.setenv("VAULT_APPROVAL_NOTIFY_HEADERS", "X-API-Key: sink-key; X-Extra: 1")
    monkeypatch.setenv("VAULT_APPROVAL_NOTIFY_BODY", '{"service": "aps-vault", "level": "crit", "text": "{text}", "link": "{url}"}')
    settings.reload()
    yield got
    srv.shutdown()
    for k in ("VAULT_APPROVAL_NOTIFY_URL", "VAULT_APPROVAL_NOTIFY_HEADERS", "VAULT_APPROVAL_NOTIFY_BODY"):
        monkeypatch.delenv(k, raising=False)
    settings.reload()


def _approve_token(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[1]


def test_approval_flow_end_to_end(client, session, notify_sink):
    from fastapi.testclient import TestClient
    import main
    # approver: needs the master password to set, is not the master password
    assert client.get("/api/approvals/settings").json()["approver_set"] is False
    assert client.post("/api/approvals/approver", json={"master_password": "nope nope nope nope", "approver_password": APPROVER}, headers=session).status_code == 401
    netutil.clear_fails("testclient")
    assert client.post("/api/approvals/approver", json={"master_password": MASTER, "approver_password": APPROVER}, headers=session).status_code == 200
    st = client.get("/api/approvals/settings").json()
    assert st["approver_set"] is True and st["notify_configured"] is True
    fid = client.post("/api/folders", json={"name": "guarded"}, headers=session).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "root-pw", "value": "top-secret", "require_approval": True}, headers=session).json()["id"]
    item = next(x for x in client.get("/api/secrets").json() if x["id"] == sid)
    assert item["require_approval"] is True
    # reading without approval: 403 with a machine-readable marker, nothing in the value
    r = client.get(f"/api/secrets/{sid}")
    assert r.status_code == 403 and r.headers.get("x-approval-required") == "1" and "approval required" in r.json()["detail"] and "top-secret" not in r.text
    # history / export / share are closed too; the machine API is not involved
    assert client.get(f"/api/secrets/{sid}/history").json()["hidden"] is True
    exp = next(x for f in client.get("/api/export").json()["folders"] if f["name"] == "guarded" for x in f["secrets"])
    assert exp["value"] is None and exp["require_approval"] is True
    assert client.post("/api/share", json={"secret_id": sid, "ttl_minutes": 5, "max_uses": 1}, headers=session).status_code == 403
    tok = client.post("/api/tokens", json={"name": "svc", "folder_id": fid}, headers=session).json()["raw_token"]
    assert client.get("/api/v1/m/secret/root-pw", headers={"Authorization": f"Bearer {tok}"}).json()["value"] == "top-secret"
    # request: the approver is notified through the configured webhook with the link
    r = client.post(f"/api/secrets/{sid}/approvals", json={"reason": "incident 4711"}, headers=session)
    assert r.status_code == 200, r.text
    req = r.json()
    assert req["status"] == "pending" and req["notified"] is True and "/approve/" in req["approve_url"]
    assert len(notify_sink) == 1
    body = json.loads(notify_sink[0]["body"])
    assert body["service"] == "aps-vault" and body["level"] == "crit" and "guarded/root-pw" in body["text"] and "incident 4711" in body["text"]
    assert body["link"] == req["approve_url"] and notify_sink[0]["headers"]["x-api-key"] == "sink-key" and notify_sink[0]["headers"]["x-extra"] == "1"
    assert "top-secret" not in notify_sink[0]["body"]
    token = _approve_token(req["approve_url"])
    # the approver's side is public (no session) and shows only metadata
    with TestClient(main.app, base_url="https://vault.test") as approver:
        info = approver.get(f"/api/approve/{token}").json()
        assert info["secret"] == "guarded/root-pw" and info["reason"] == "incident 4711" and info["status"] == "pending" and "value" not in info
        assert approver.get("/api/approve/not-a-token").status_code == 404
        # wrong approver password is a counted failure; master password is NOT the approver password
        assert approver.post(f"/api/approve/{token}", json={"approver_password": "wrong wrong wrong", "decision": "approve"}).status_code == 401
        assert approver.post(f"/api/approve/{token}", json={"approver_password": MASTER, "decision": "approve"}).status_code == 401
        netutil.clear_fails("testclient")
        assert client.get(f"/api/approvals/{req['id']}").json()["status"] == "pending"
        ok = approver.post(f"/api/approve/{token}", json={"approver_password": APPROVER, "decision": "approve"}).json()
        assert ok["status"] == "approved"
        assert approver.post(f"/api/approve/{token}", json={"approver_password": APPROVER, "decision": "approve"}).status_code == 409, "decided once"
    assert client.get(f"/api/approvals/{req['id']}").json()["status"] == "approved"
    # the requester reads with the ticket; TOTP refresh and repeated reads within the window work
    full = client.get(f"/api/secrets/{sid}", params={"approval": req["id"]}).json()
    assert full["value"] == "top-secret"
    assert client.get(f"/api/secrets/{sid}", params={"approval": req["id"]}).status_code == 200
    # another session cannot ride on this approval
    with TestClient(main.app, base_url="https://vault.test") as other:
        netutil.clear_fails("testclient")
        other.post("/api/auth/unlock", json={"master_password": MASTER})
        assert other.get(f"/api/secrets/{sid}", params={"approval": req["id"]}).status_code == 403
    # a denied request stays closed
    r2 = client.post(f"/api/secrets/{sid}/approvals", json={"reason": "again"}, headers=session).json()
    with TestClient(main.app, base_url="https://vault.test") as approver:
        assert approver.post(f"/api/approve/{_approve_token(r2['approve_url'])}", json={"approver_password": APPROVER, "decision": "deny"}).json()["status"] == "denied"
    assert client.get(f"/api/secrets/{sid}", params={"approval": r2["id"]}).status_code == 403
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 60}).json()]
    assert {"approval:requested", "approval:approved", "approval:denied", "approval:approver_set"} <= set(actions)
    # listing for the settings page
    lst = client.get("/api/approvals").json()
    assert len(lst) >= 2 and lst[0]["secret"] == "guarded/root-pw"
    # removing the approver closes approval-required secrets until flags are cleared
    assert client.delete("/api/approvals/approver", headers=session).status_code == 200
    assert client.get(f"/api/secrets/{sid}").status_code == 409


def test_approval_without_notifier_still_returns_link(client, session):
    """No notify URL configured: the requester gets the link to hand over by any means."""
    netutil.clear_fails("testclient")
    client.post("/api/approvals/approver", json={"master_password": MASTER, "approver_password": APPROVER}, headers=session)
    fid = client.post("/api/folders", json={"name": "guarded-2"}, headers=session).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "k", "value": "v", "require_approval": True}, headers=session).json()["id"]
    req = client.post(f"/api/secrets/{sid}/approvals", json={}, headers=session).json()
    assert req["notified"] is False and req["approve_url"].startswith("https://vault.test/approve/")
    client.delete("/api/approvals/approver", headers=session)
