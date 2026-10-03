"""The official HashiCorp client (hvac) against APS Vault's KV v2 facade — the same calls a
service written for HashiCorp Vault / Deckhouse Stronghold makes."""
import os
import socket
import sys
import threading
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


def test_hvac_read_list_lookup(live):
    url, ro, _ = live
    c = hvac.Client(url=url, token=ro)
    assert c.is_authenticated()                         # auth/token/lookup-self
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
