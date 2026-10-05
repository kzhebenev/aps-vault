"""The official HashiCorp client (hvac) against APS Vault's KV v2 facade — the same calls a
service written for HashiCorp Vault / Deckhouse Stronghold makes."""
import os
import socket
import sys
import threading
import urllib.error
import time

import hvac
import pytest
import uvicorn

import main
from conftest import unlock


@pytest.fixture(scope="module")
def live(initialized, client):
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning", http="h11"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "hvac"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "app/db", "value": "pw", "login": "svc"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "app/smtp", "value": "s"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "top", "value": "t"}, headers=hdr)
    ro = client.post("/api/tokens", json={"name": "hvac-ro", "folder_id": fid}, headers=hdr).json()["raw_token"]
    rw = client.post("/api/tokens", json={"name": "hvac-rw", "folder_id": fid, "can_write": True}, headers=hdr).json()["raw_token"]
    yield f"http://127.0.0.1:{port}", ro, rw
    server.should_exit = True


def test_lookup_self_reports_expiry_for_an_expiring_token(client, live):
    import main
    from conftest import unlock
    url, _, _ = live
    hdr = unlock(client)
    fid = next(f["id"] for f in client.get("/api/folders", headers=hdr).json() if f["name"] == "hvac")
    tok = client.post("/api/tokens", json={"name": "hvac-expiring", "folder_id": fid, "expires_days": 3}, headers=hdr).json()["raw_token"]
    info = hvac.Client(url=url, token=tok).auth.token.lookup_self()["data"]
    assert info["expire_time"] and info["expire_time"].endswith("Z") and 2 * 86400 < info["ttl"] <= 3 * 86400, info
    # the machine API itself works with an expiring token (it answered 500 before 0.25) …
    import db
    import urllib.request
    r = urllib.request.urlopen(urllib.request.Request(f"{url}/api/v1/m/health", headers={"Authorization": f"Bearer {tok}"}), timeout=5)
    assert r.status == 200
    # … and refuses it the moment it has expired
    from datetime import timedelta
    with db.get_session() as s:
        row = s.query(db.ServiceToken).filter_by(name="hvac-expiring").first()
        row.expires_at = db.utcnow().replace(tzinfo=None) - timedelta(minutes=1); s.commit()
    assert hvac.Client(url=url, token=tok).is_authenticated() is False
    try:
        urllib.request.urlopen(urllib.request.Request(f"{url}/api/v1/m/health", headers={"Authorization": f"Bearer {tok}"}), timeout=5)
        assert False, "expired token accepted"
    except urllib.error.HTTPError as e:
        assert e.code == 401 and "expired" in e.read().decode()


def test_hvac_read_list_lookup(live):
    url, ro, _ = live
    c = hvac.Client(url=url, token=ro)
    assert c.is_authenticated()                         # auth/token/lookup-self
    info = c.auth.token.lookup_self()["data"]
    assert "expire_time" in info and info["expire_time"] is None and info["ttl"] == 0, "no expiry: null + 0, and the key must be present (ESO)"
    assert c.sys.is_sealed() is False                   # sys/seal-status → we answer via health? see below
    r = c.secrets.kv.v2.read_secret_version(path="app/db", mount_point="hvac", raise_on_deleted_version=True)
    assert r["data"]["data"] == {"value": "pw", "login": "svc"} and r["data"]["metadata"]["version"] == 1
    lst = c.secrets.kv.v2.list_secrets(path="", mount_point="hvac")
    assert sorted(lst["data"]["keys"]) == ["app/", "top"]
    lst2 = c.secrets.kv.v2.list_secrets(path="app", mount_point="hvac")
    assert sorted(lst2["data"]["keys"]) == ["db", "smtp"]
    meta = c.secrets.kv.v2.read_secret_metadata(path="app/db", mount_point="hvac")
    assert meta["data"]["current_version"] == 1


def test_hvac_write_requires_can_write(live):
    url, ro, rw = live
    with pytest.raises(hvac.exceptions.Forbidden):
        hvac.Client(url=url, token=ro).secrets.kv.v2.create_or_update_secret(path="new", secret={"value": "x"}, mount_point="hvac")
    c = hvac.Client(url=url, token=rw)
    w = c.secrets.kv.v2.create_or_update_secret(path="new", secret={"value": "x", "login": "u"}, mount_point="hvac")
    assert w["data"]["version"] == 1
    w2 = c.secrets.kv.v2.create_or_update_secret(path="new", secret={"value": "y"}, mount_point="hvac")
    assert w2["data"]["version"] == 2
    assert c.secrets.kv.v2.read_secret_version(path="new", mount_point="hvac", raise_on_deleted_version=True)["data"]["data"]["value"] == "y"
    # 0.8: older versions by number, exactly as HashiCorp serves them
    old = c.secrets.kv.v2.read_secret_version(path="new", version=1, mount_point="hvac", raise_on_deleted_version=True)
    assert old["data"]["data"]["value"] == "x" and old["data"]["metadata"]["version"] == 1
    meta = c.secrets.kv.v2.read_secret_metadata(path="new", mount_point="hvac")["data"]
    assert meta["current_version"] == 2 and set(meta["versions"]) == {"1", "2"}
    with pytest.raises(hvac.exceptions.InvalidPath):
        c.secrets.kv.v2.read_secret_version(path="new", version=7, mount_point="hvac", raise_on_deleted_version=True)


def test_hvac_wrong_mount_and_bad_token(live):
    url, ro, _ = live
    with pytest.raises(hvac.exceptions.Forbidden):
        hvac.Client(url=url, token=ro).secrets.kv.v2.read_secret_version(path="app/db", mount_point="other", raise_on_deleted_version=True)
    assert hvac.Client(url=url, token="vlt_nope").is_authenticated() is False
