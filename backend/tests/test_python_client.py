"""The Python client (clients/python) against a real server: uvicorn in a thread on a free
port, folder/secret/token prepared through the human API, then everything goes through the
stdlib client only."""
import os
import socket
import sys
import threading
import time

import pytest
import uvicorn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clients", "python"))
from aps_vault import Vault, VaultError  # noqa: E402

import main  # noqa: E402
from conftest import unlock  # noqa: E402


@pytest.fixture(scope="module")
def live_url(initialized):
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning", http="h11"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


@pytest.fixture(scope="module")
def token(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-client"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "db-password", "value": "s3cr3t",
                                      "login": "app", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr)
    return client.post("/api/tokens", json={"name": "py-rw", "folder_id": fid, "can_write": True,
                                            "can_read_totp": True}, headers=hdr).json()["raw_token"]


def test_rejects_master_password_as_token(live_url):
    with pytest.raises(ValueError):
        Vault(live_url, "correct horse battery staple")


def test_get_full_put_totp_and_404(live_url, token):
    v = Vault(live_url, token, cache_ttl=0)
    assert v.get("db-password") == "s3cr3t"
    full = v.get_full("db-password")
    assert full["login"] == "app" and len(full["totp"]) == 6
    assert len(v.totp("db-password")) == 6
    assert v.put("fresh", "val", login="u")["created"] is True
    assert v.get("fresh") == "val"
    assert [s["name"] for s in v.list()] == ["db-password", "fresh"]
    assert v.health()["scope_folder"] == "py-client"
    with pytest.raises(VaultError) as e:
        v.get("nope")
    assert e.value.status == 404


def test_cache_and_fail_open(live_url, token, monkeypatch):
    v = Vault(live_url, token, cache_ttl=0.2, max_retries=0)
    assert v.get("db-password") == "s3cr3t"
    time.sleep(0.3)
    # point the client at a dead port: the stale cached value must still come back
    v._base = "http://127.0.0.1:9"
    assert v.get("db-password") == "s3cr3t"
    with pytest.raises(OSError):
        v.get("never-cached")


def test_wrong_token_is_401(live_url):
    with pytest.raises(VaultError) as e:
        Vault(live_url, "vlt_nope", max_retries=0).get("db-password")
    assert e.value.status == 401
