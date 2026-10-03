"""One-time share links and webhook delivery."""
import hashlib
import hmac
import json
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import db


def test_share_link_once_then_dead(client, session):
    fid = client.post("/api/folders", json={"name": "share"}, headers=session).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "pw", "value": "shh", "login": "ops@example.com"}, headers=session).json()["id"]
    r = client.post("/api/share", json={"secret_id": sid, "ttl_minutes": 5, "max_uses": 1, "note": "после входа смени"}, headers=session).json()
    token = r["url"].rsplit("/", 1)[1]
    # public: no cookies, vault may even be locked
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app, base_url="https://vault.test") as anon:
        got = anon.get(f"/api/share/{token}")
        assert got.status_code == 200 and got.json()["value"] == "shh" and got.json()["uses_left"] == 0
        assert got.json()["login"] == "ops@example.com" and got.json()["note"] == "после входа смени", "a human recipient gets login and the sender's message" 
        assert anon.get(f"/api/share/{token}").status_code == 410
        assert anon.get("/api/share/not-a-token").status_code == 404
    # expiry
    r2 = client.post("/api/share", json={"secret_id": sid, "ttl_minutes": 5, "max_uses": 3}, headers=session).json()
    with db.get_session() as s:
        link = s.get(db.ShareLink, r2["id"])
        link.expires_at = db.utcnow().replace(tzinfo=None) - timedelta(minutes=1)
        s.commit()
    assert client.get(f"/api/share/{r2['url'].rsplit('/', 1)[1]}").status_code == 410
    # revoke
    r3 = client.post("/api/share", json={"secret_id": sid, "ttl_minutes": 5}, headers=session).json()
    assert client.delete(f"/api/shares/{r3['id']}", headers=session).status_code == 200
    assert client.get(f"/api/share/{r3['url'].rsplit('/', 1)[1]}").status_code == 404


class _Sink(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        _Sink.received.append((dict(self.headers), body))
        self.send_response(200); self.end_headers()

    def log_message(self, *a):
        pass


def test_webhook_is_delivered_signed_and_without_values(client, session):
    srv = HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/hook"
        w = client.post("/api/webhooks", json={"name": "t", "url": url, "event_filter": "secret:*"}, headers=session).json()
        secret = w["signing_secret"]
        fid = client.post("/api/folders", json={"name": "hooked"}, headers=session).json()["id"]
        client.post("/api/secrets", json={"folder_id": fid, "name": "hooked-secret", "value": "TOP-SECRET-VALUE"}, headers=session)
        deadline = time.time() + 5
        while not _Sink.received and time.time() < deadline:
            time.sleep(0.05)
        assert _Sink.received, "webhook was not delivered"
        headers, body = _Sink.received[0]
        payload = json.loads(body)
        assert payload["event"] == "secret:create" and payload["data"]["name"] == "hooked-secret"
        assert b"TOP-SECRET-VALUE" not in body
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert headers.get("X-Vault-Signature") == expected
        # token events do not match 'secret:*'
        _Sink.received.clear()
        client.post("/api/tokens", json={"name": "tk", "folder_id": fid}, headers=session)
        time.sleep(0.5)
        assert not _Sink.received
    finally:
        srv.shutdown()


def test_webhook_rejects_non_http_url(client, session):
    r = client.post("/api/webhooks", json={"name": "bad", "url": "file:///etc/passwd"}, headers=session)
    assert r.status_code == 422
