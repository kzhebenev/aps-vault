"""Init, unlock, lock, brute-force budget, CSRF, CORS, recovery."""
import os

import netutil
import settings
from conftest import MASTER, unlock


def test_init_requires_token(client):
    # fresh instance: without the token nobody can claim it
    r = client.post("/api/init", json={"master_password": MASTER})
    assert r.status_code == 403
    r = client.post("/api/init", json={"master_password": MASTER, "init_token": "wrong"})
    assert r.status_code == 403


def test_init_once(client, initialized):
    r = client.post("/api/init", json={"master_password": MASTER, "init_token": "test-init-token"})
    assert r.status_code == 409
    h = client.get("/api/health").json()
    assert h["initialized"] is True and h["version"] == "0.5.1"


def test_unlock_sets_cookies_and_health_is_per_client(client, initialized):
    hdr = unlock(client)
    assert "X-CSRF-Token" in hdr
    assert client.cookies.get("vault_session") and client.cookies.get("vault_csrf")
    assert client.get("/api/health").json()["unlocked"] is True
    # a client without the cookie sees the vault as locked even though the key is in RAM
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app, base_url="https://vault.test") as other:
        assert other.get("/api/health").json()["unlocked"] is False
        assert other.get("/api/folders").status_code == 401


def test_wrong_password_budget_cannot_be_reset_by_forwarded_for(client, initialized):
    netutil.clear_fails("testclient")
    for i in range(5):
        r = client.post("/api/auth/unlock", json={"master_password": "wrong password!!"},
                        headers={"X-Forwarded-For": f"203.0.113.{i}"})   # spoof attempt
        assert r.status_code == 401
    # 6th attempt — even with the right password — is refused
    r = client.post("/api/auth/unlock", json={"master_password": MASTER},
                    headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 429
    netutil.clear_fails("testclient")
    assert client.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 200


def test_global_budget(client, initialized, monkeypatch):
    monkeypatch.setenv("VAULT_FAIL_LIMIT_GLOBAL", "3")
    settings.reload()
    try:
        for ip in ("a", "b", "c"):
            netutil.record_fail(ip)
        assert netutil.is_locked("someone-else") is True
    finally:
        for ip in ("a", "b", "c"):
            netutil.clear_fails(ip)
        monkeypatch.setenv("VAULT_FAIL_LIMIT_GLOBAL", "50")
        settings.reload()
    assert netutil.is_locked("someone-else") is False


def test_csrf_required_for_writes(client, session):
    r = client.post("/api/folders", json={"name": "no-csrf"})
    assert r.status_code == 403 and "CSRF" in r.text
    r = client.post("/api/folders", json={"name": "no-csrf"}, headers={"X-CSRF-Token": "bogus"})
    assert r.status_code == 403
    r = client.post("/api/folders", json={"name": "with-csrf"}, headers=session)
    assert r.status_code == 200


def test_cors_only_configured_origins(client, initialized):
    ok = client.options("/api/folders", headers={"Origin": "https://vault.test",
                                                  "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://vault.test"
    for bad in ("chrome-extension://abcdefghijklmnop", "http://localhost:3000", "https://evil.example"):
        r = client.options("/api/folders", headers={"Origin": bad, "Access-Control-Request-Method": "GET"})
        assert r.headers.get("access-control-allow-origin") is None, bad


def test_security_headers(client):
    h = client.get("/api/health").headers
    assert h["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff" and "max-age" in h["strict-transport-security"]


def test_lock_drops_key_when_last_session(client, initialized):
    hdr = unlock(client)
    r = client.post("/api/auth/lock", headers=hdr)
    assert r.status_code == 200
    assert client.get("/api/folders").status_code == 401


def test_recover_changes_password_and_keeps_data(client, initialized):
    hdr = unlock(client)
    f = client.post("/api/folders", json={"name": "recover-test"}, headers=hdr).json()
    sid = client.post("/api/secrets", json={"folder_id": f["id"], "name": "k", "value": "v-before"}, headers=hdr).json()["id"]
    new_pw = "another very long master password"
    r = client.post("/api/auth/recover", json={"recovery_code": initialized, "new_master_password": new_pw})
    assert r.status_code == 200
    new_code = r.json()["new_recovery_code"]
    assert client.get("/api/folders").status_code == 401, "all sessions must be dropped"
    netutil.clear_fails("testclient")
    assert client.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 401
    hdr = unlock(client, new_pw)
    assert client.get(f"/api/secrets/{sid}").json()["value"] == "v-before"
    # old recovery code is dead
    assert client.post("/api/auth/recover", json={"recovery_code": initialized, "new_master_password": MASTER}).status_code == 401
    # restore the original password for the rest of the suite
    r = client.post("/api/auth/recover", json={"recovery_code": new_code, "new_master_password": MASTER})
    assert r.status_code == 200
    unlock(client)
