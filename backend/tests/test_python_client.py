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


def test_fail_open_stops_after_max_stale(live_url, token):
    """0.41.1: a stale value is served through an outage only within max_stale of its fetch — after
    that the outage surfaces, so a revoked or rotated secret cannot live on in the cache forever."""
    v = Vault(live_url, token, cache_ttl=0.1, max_stale=600, max_retries=0)
    assert v.get("db-password") == "s3cr3t"
    v._base = "http://127.0.0.1:9"
    e = v._cache["db-password"]
    e.expires_at = 0                                 # expired; the age is moved by hand, no sleeps (stable under load)
    e.fetched_at -= 300
    assert v.get("db-password") == "s3cr3t"          # outage, 5 min old, within max_stale
    e.fetched_at -= 360
    with pytest.raises(OSError):                     # 11 min old, past max_stale: the outage is not hidden any more
        v.get("db-password")
    # max_stale=None keeps the old unlimited behaviour for those who chose it
    u = Vault(live_url, token, cache_ttl=0.1, max_stale=None, max_retries=0)
    assert u.get("db-password") == "s3cr3t"
    u._base = "http://127.0.0.1:9"
    u._cache["db-password"].expires_at = 0
    u._cache["db-password"].fetched_at -= 10 * 365 * 86400
    assert u.get("db-password") == "s3cr3t"
    # the default is a day: a value fetched 25 h ago is not served
    d = Vault(live_url, token, cache_ttl=0.1, max_retries=0)
    assert d.get("db-password") == "s3cr3t"
    d._base = "http://127.0.0.1:9"
    d._cache["db-password"].expires_at = 0
    d._cache["db-password"].fetched_at -= 25 * 3600
    with pytest.raises(OSError):
        d.get("db-password")


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


def test_pqc_sealed_token_end_to_end(live_url, client, initialized):
    """0.27: a token bound to the hybrid X25519+ML-KEM-768 key — the stdlib client with kyber-py opens it."""
    import json
    import urllib.request
    from aps_vault import generate_keypair, pqc_public_from_private
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-pqc"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "api-key", "value": "pqc-value-9", "login": "svc"}, headers=hdr)
    sk, pk = generate_keypair("pqc")
    assert pqc_public_from_private(sk) == pk
    tok = client.post("/api/tokens", json={"name": "py-pqc", "folder_id": fid, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    raw = urllib.request.urlopen(urllib.request.Request(f"{live_url}/api/v1/m/secret/api-key", headers={"Authorization": f"Bearer {tok}"}), timeout=5).read().decode()
    assert "pqc-value-9" not in raw and json.loads(raw)["sealed"]["alg"] == "X25519MLKEM768-HKDF-SHA256-AES256GCM" and "kem" in json.loads(raw)["sealed"]
    v = Vault(live_url, tok, cache_ttl=0, client_private_key=sk)
    assert v.get("api-key") == "pqc-value-9" and v.get_full("api-key")["login"] == "svc"
    other_sk, _ = generate_keypair("pqc")
    with pytest.raises(VaultError, match="does not open"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=other_sk).get("api-key")
    with pytest.raises(VaultError, match="96 bytes"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=generate_keypair()[0]).get("api-key")
    # enrolment with a hybrid pair
    code = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "pqc"}, headers=hdr).json()["code"]
    from aps_vault import enroll
    e = enroll(live_url, code, name="n1", kind="pqc")
    assert len(__import__("base64").b64decode(e["private_key"])) == 96
    assert Vault(live_url, e["token"], cache_ttl=0, client_private_key=e["private_key"]).get("api-key") == "pqc-value-9"


def test_gost_sealed_token_end_to_end(live_url, client, initialized):
    """0.19: a GOST key pair from the client (gostcrypto extra) → the server seals with VKO GOST R 34.10-2012 +
    Kuznyechik-MGM → the client opens it; and the client's vendored GOST module is byte-identical to the server's."""
    import subprocess
    import json
    import urllib.request
    from aps_vault import generate_keypair
    assert subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "..", "ops", "sync-client-gost.py"), "--check"]).returncode == 0, \
        "clients/python/aps_vault/gost.py drifted from backend/gost.py + gostec.py — run ops/sync-client-gost.py"
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-gost"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "gost-key", "value": "kuznyechik-value", "login": "svc"}, headers=hdr)
    sk, pk = generate_keypair("gost")
    tok = client.post("/api/tokens", json={"name": "py-gost", "folder_id": fid, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    raw = urllib.request.urlopen(urllib.request.Request(f"{live_url}/api/v1/m/secret/gost-key", headers={"Authorization": f"Bearer {tok}"}), timeout=5).read().decode()
    assert "kuznyechik-value" not in raw and json.loads(raw)["sealed"]["alg"] == "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM"
    v = Vault(live_url, tok, cache_ttl=0, client_private_key=sk)
    assert v.get("gost-key") == "kuznyechik-value" and v.get_full("gost-key")["login"] == "svc"
    other_sk, _ = generate_keypair("gost")
    with pytest.raises(VaultError, match="does not open"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=other_sk).get("gost-key")


def test_enroll_end_to_end(live_url, client, initialized):
    """0.21: the client enrols with a one-time code — key pair made locally, token sealed to it."""
    from aps_vault import enroll
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-enrol"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "enrolled-secret", "value": "hello-node"}, headers=hdr)
    code = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "py", "max_uses": 1}, headers=hdr).json()["code"]
    r = enroll(live_url, code, name="host-7")
    assert r["token"].startswith("vlt_") and r["token_name"] == "py-host-7" and r["folder_name"] == "py-enrol"
    v = Vault(live_url, r["token"], cache_ttl=0, client_private_key=r["private_key"])
    assert v.get("enrolled-secret") == "hello-node"
    with pytest.raises(VaultError, match="sealed values"):
        Vault(live_url, r["token"], cache_ttl=0).get("enrolled-secret")
    with pytest.raises(VaultError) as e:
        enroll(live_url, code, name="host-8")
    assert e.value.status == 410, "single-use code"
    netutil_clear = __import__("netutil").clear_fails("testclient")


def test_p256_software_and_pkcs11_hardware_key(live_url, client, initialized):
    """0.22: the P-256 envelope — in software from a scalar, and with the private key INSIDE a PKCS#11 token
    (SoftHSM2 in the test container, the same path a TPM 2.0 takes through tpm2-pkcs11). Skipped as
    'НЕ НАСТРОЕНО' without a module."""
    from aps_vault import Pkcs11Key, generate_keypair, enroll
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-p256"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "tpm-key", "value": "held-in-hardware"}, headers=hdr)
    sk, pk = generate_keypair("p256")
    tok = client.post("/api/tokens", json={"name": "py-p256-sw", "folder_id": fid, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    assert Vault(live_url, tok, cache_ttl=0, client_private_key=sk).get("tpm-key") == "held-in-hardware"
    with pytest.raises(VaultError, match="does not open"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=generate_keypair("p256")[0]).get("tpm-key")
    module = os.environ.get("VAULT_PKCS11_MODULE")
    if not module or not os.path.exists(module):
        pytest.skip("НЕ НАСТРОЕНО: VAULT_PKCS11_MODULE не задан — SoftHSM2 нет в контуре тестов")
    pin = os.environ.get("TEST_PKCS11_PIN", "1234")
    hw = Pkcs11Key.generate(module, os.environ.get("VAULT_PKCS11_TOKEN_LABEL", "aps-vault"), pin, key_label="py-node-p256")
    assert len(hw.public_bytes()) == 65 and hw.public_bytes()[0] == 0x04
    with pytest.raises(RuntimeError):
        Pkcs11Key.generate(module, os.environ.get("VAULT_PKCS11_TOKEN_LABEL", "aps-vault"), pin, key_label="py-node-p256")   # exists
    # enrol with the hardware key: the private key never leaves the token
    code = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "tpm"}, headers=hdr).json()["code"]
    r = enroll(live_url, code, name="node-hw", hardware_key=hw)
    assert r["token_name"] == "tpm-node-hw" and r["public_key"] == hw.public_b64() and isinstance(r["private_key"], Pkcs11Key)
    v = Vault(live_url, r["token"], cache_ttl=0, client_private_key=hw)
    assert v.get("tpm-key") == "held-in-hardware", "ECDH done inside the token (CKM_ECDH1_DERIVE)"
    # the same token with a different hardware key fails, and a hardware key cannot open an X25519 envelope
    other = Pkcs11Key.generate(module, os.environ.get("VAULT_PKCS11_TOKEN_LABEL", "aps-vault"), pin, key_label="py-node-p256-other")
    with pytest.raises(VaultError, match="does not open"):
        Vault(live_url, r["token"], cache_ttl=0, client_private_key=other).get("tpm-key")
    xsk, xpk = generate_keypair()
    xtok = client.post("/api/tokens", json={"name": "py-x25519-for-hw", "folder_id": fid, "client_public_key": xpk}, headers=hdr).json()["raw_token"]
    with pytest.raises(VaultError, match="P-256 envelope"):
        Vault(live_url, xtok, cache_ttl=0, client_private_key=hw).get("tpm-key")


def test_gost_pqc_sealed_token_end_to_end(live_url, client, initialized):
    """0.32: a token bound to the GOST hybrid key (GOST R 34.10-2012 ‖ ML-KEM-768) — the client with the gostcrypto
    and kyber-py extras opens the VKO + ML-KEM → KDF_TREE → Kuznyechik-MGM envelope; wrong halves do not."""
    import base64
    import json
    import urllib.request
    from aps_vault import generate_keypair, gost_pqc_public_from_private, enroll
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "py-gost-pqc"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "api-key", "value": "gost-pqc-value-9", "login": "svc"}, headers=hdr)
    sk, pk = generate_keypair("gost-pqc")
    assert len(base64.b64decode(sk)) == 96 and len(base64.b64decode(pk)) == 1248 and gost_pqc_public_from_private(sk) == pk
    tok = client.post("/api/tokens", json={"name": "py-gost-pqc", "folder_id": fid, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    raw = urllib.request.urlopen(urllib.request.Request(f"{live_url}/api/v1/m/secret/api-key", headers={"Authorization": f"Bearer {tok}"}), timeout=5).read().decode()
    env = json.loads(raw)["sealed"]
    assert "gost-pqc-value-9" not in raw and env["alg"] == "VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM" and "kem" in env and "ukm" in env
    v = Vault(live_url, tok, cache_ttl=0, client_private_key=sk)
    assert v.get("api-key") == "gost-pqc-value-9" and v.get_full("api-key")["login"] == "svc"
    other_sk, _ = generate_keypair("gost-pqc")
    for wrong in (other_sk, base64.b64encode(base64.b64decode(sk)[:32] + base64.b64decode(other_sk)[32:]).decode()):
        with pytest.raises(VaultError, match="does not open"):
            Vault(live_url, tok, cache_ttl=0, client_private_key=wrong).get("api-key")
    with pytest.raises(VaultError, match="96 bytes"):
        Vault(live_url, tok, cache_ttl=0, client_private_key=generate_keypair("gost")[0]).get("api-key")
    code = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "gpqc"}, headers=hdr).json()["code"]
    e = enroll(live_url, code, name="n1", kind="gost-pqc")
    assert len(base64.b64decode(e["private_key"])) == 96 and len(base64.b64decode(e["public_key"])) == 1248
    assert Vault(live_url, e["token"], cache_ttl=0, client_private_key=e["private_key"]).get("api-key") == "gost-pqc-value-9"


def test_client_with_a_key_refuses_plaintext(live_url, token):
    """0.37: a client configured with a private key does not accept a plaintext answer (a tampering proxy could drop the
    envelope and put its own value in); the AAD is the requested name."""
    from aps_vault import generate_keypair
    sk, _ = generate_keypair()
    with pytest.raises(VaultError, match="not sealed"):
        Vault(live_url, token, cache_ttl=0, client_private_key=sk).get("db-password")
