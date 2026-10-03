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
    # 0.8: versions
    assert v.put("fresh", "val-2")["version"] == 2
    assert v.get("fresh") == "val-2" and v.get("fresh", version=1) == "val"
    vers = v.versions("fresh")
    assert vers["current_version"] == 2 and [x["version"] for x in vers["versions"]] == [2, 1]
    with pytest.raises(VaultError) as e:
        v.get("fresh", version=5)
    assert e.value.status == 404
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


def test_sealed_token_end_to_end(live_url, client, initialized):
    """0.17: a token bound to the app's X25519 key — the wire carries ciphertext only; the stdlib
    client (with the optional `cryptography` extra) decrypts in-process."""
    import json
    import urllib.request
    from aps_vault import generate_keypair
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-sealed"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "api-key", "value": "sealed-value-7", "login": "svc", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr)
    sk, pk = generate_keypair()
    tok = client.post("/api/tokens", json={"name": "py-sealed", "folder_id": fid, "can_read_totp": True, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    # raw wire: no plaintext anywhere
    req = urllib.request.Request(f"{live_url}/api/v1/m/secret/api-key", headers={"Authorization": f"Bearer {tok}"})
    raw = urllib.request.urlopen(req, timeout=5).read().decode()
    assert "sealed-value-7" not in raw and '"value"' not in raw and "svc" not in raw and json.loads(raw)["sealed"]["alg"] == "X25519-HKDF-SHA256-AES256GCM"
    v = Vault(live_url, tok, cache_ttl=0, client_private_key=sk)
    assert v.get("api-key") == "sealed-value-7"
    full = v.get_full("api-key")
    assert full["login"] == "svc" and len(full["totp"]) == 6 and "sealed" not in full and full["version"] == 1
    assert len(v.totp("api-key")) == 6
    # without the private key the client refuses rather than returning the envelope as a value
    with pytest.raises(VaultError, match="sealed values"):
        Vault(live_url, tok, cache_ttl=0).get("api-key")
    # another key: refused with a clear message, no partial data
    other_sk, _ = generate_keypair()
    with pytest.raises(VaultError, match="does not open"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=other_sk).get("api-key")
