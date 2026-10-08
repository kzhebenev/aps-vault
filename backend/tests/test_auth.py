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
    assert h["initialized"] is True and h["version"] == "0.41.10"


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
        # 0.37: over the global budget, an address that has failed itself is stopped after its first miss…
        netutil.record_fail("someone-else")
        assert netutil.is_locked("someone-else") is True
        # …but an address with no failures (the owner at their desk) is NOT locked out by others (it was a DoS)
        assert netutil.is_locked("clean-owner-ip") is False
    finally:
        for ip in ("a", "b", "c", "someone-else"):
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
    client.post("/api/secrets", json={"folder_id": f["id"], "name": "pw", "value": "v1"}, headers=hdr)
    tok = client.post("/api/tokens", json={"name": "survives-recovery", "folder_id": f["id"]}, headers=hdr).json()["raw_token"]
    new_pw = "another very long master password"
    r = client.post("/api/auth/recover", json={"recovery_code": initialized, "new_master_password": new_pw})
    assert r.status_code == 200
    new_code = r.json()["new_recovery_code"]
    assert client.get("/api/folders").status_code == 401, "all sessions must be dropped"
    # service tokens have their own key chain and must survive the rewrap (regression: the
    # token key is salted with the folder nonce; a new nonce broke every token)
    assert client.get("/api/v1/m/secret/pw", headers={"Authorization": f"Bearer {tok}"}).json()["value"] == "v1"
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


def test_change_password_rewraps_and_drops_sessions(client, initialized):
    hdr = unlock(client)
    f = client.post("/api/folders", json={"name": "chpw"}, headers=hdr).json()
    client.post("/api/secrets", json={"folder_id": f["id"], "name": "k", "value": "keep-me"}, headers=hdr)
    tok = client.post("/api/tokens", json={"name": "chpw-tok", "folder_id": f["id"]}, headers=hdr).json()["raw_token"]
    # wrong current password is a counted failure
    r = client.post("/api/auth/change-password", json={"current_password": "nope nope nope nope", "new_password": "a brand new master password"}, headers=hdr)
    assert r.status_code == 401
    netutil.clear_fails("testclient")
    new_pw = "a brand new master password"
    r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": new_pw}, headers=hdr)
    assert r.status_code == 200 and len(r.json()["new_recovery_code"]) == 24
    assert client.get("/api/folders").status_code == 401, "every session is dropped"
    assert client.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 401
    hdr = unlock(client, new_pw)
    sec = next(x for x in client.get("/api/secrets").json() if x["name"] == "k" and x["folder_name"] == "chpw")
    assert client.get(f"/api/secrets/{sec['id']}").json()["value"] == "keep-me"
    assert client.get("/api/v1/m/secret/k", headers={"Authorization": f"Bearer {tok}"}).json()["value"] == "keep-me", "tokens survive"
    # the new recovery code works, the password is restored for the rest of the suite
    r = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER})
    assert r.status_code == 200
    unlock(client)


def test_sso_unlock_cell_lifecycle(client, initialized, monkeypatch):
    """0.10: with VAULT_SSO_UNLOCK_KEY set, the administrator can make the vault openable by
    an OIDC login on any replica; the cell survives a password change, and is unusable without
    the server key."""
    import crypto
    import settings
    import main as _m
    hdr = unlock(client)
    assert client.get("/api/auth/sso-unlock/status").json() == {"available": False, "enabled": False, "source": "none"}
    assert client.post("/api/auth/sso-unlock/enable", json={"master_password": MASTER}, headers=hdr).status_code == 409, "no server key → refused"
    monkeypatch.setenv("VAULT_SSO_UNLOCK_KEY", "0011223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"); settings.reload()
    try:
        netutil.clear_fails("testclient")
        assert client.post("/api/auth/sso-unlock/enable", json={"master_password": "wrong wrong wrong"}, headers=hdr).status_code == 401
        netutil.clear_fails("testclient")
        assert client.post("/api/auth/sso-unlock/enable", json={"master_password": MASTER}, headers=hdr).json()["enabled"] is True
        st = client.get("/api/auth/sso-unlock/status").json()
        assert st["available"] and st["enabled"]
        cfg = crypto.load_config()
        # the cell opens with the server key and yields the real master key; a wrong key yields nothing
        assert crypto.sso_cell_open(cfg, settings.SETTINGS.sso_unlock_key) == crypto.verify_master_password(MASTER, cfg)
        assert crypto.sso_cell_open(cfg, b"x" * 32) is None
        _m.STATE.lock()
        assert _m.sso_unlock_source() == "cell", "a replica without a node cache would still serve SSO logins"
        # password change re-wraps the cell under the new master key
        new_pw = "sso cell survives password change"
        r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": new_pw}, headers=hdr)
        assert r.status_code == 200
        cfg2 = crypto.load_config()
        assert crypto.sso_cell_open(cfg2, settings.SETTINGS.sso_unlock_key) == crypto.verify_master_password(new_pw, cfg2)
        # restore the suite's password through recovery — the cell follows again
        r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER})
        assert r2.status_code == 200
        cfg3 = crypto.load_config()
        assert crypto.sso_cell_open(cfg3, settings.SETTINGS.sso_unlock_key) == crypto.verify_master_password(MASTER, cfg3)
        hdr = unlock(client)
        assert client.post("/api/auth/sso-unlock/disable", headers=hdr).json()["enabled"] is False
        assert not crypto.load_config().sso_master_enc and _m.sso_unlock_source() in ("none", "node")
        actions = [a["action"] for a in client.get("/api/audit", params={"limit": 60}).json()]
        assert "auth:sso_unlock_enabled" in actions and "auth:sso_unlock_disabled" in actions
    finally:
        monkeypatch.delenv("VAULT_SSO_UNLOCK_KEY"); settings.reload()


def test_sso_unlock_key_must_be_strong(monkeypatch):
    import settings
    monkeypatch.setenv("VAULT_SSO_UNLOCK_KEY", "short"); assert settings.load().sso_unlock_key == b""
    monkeypatch.setenv("VAULT_SSO_UNLOCK_KEY", "a" * 64); assert len(settings.load().sso_unlock_key) == 32          # hex
    monkeypatch.setenv("VAULT_SSO_UNLOCK_KEY", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"); assert len(settings.load().sso_unlock_key) >= 32   # base64



def test_bearer_session_without_cookie_needs_no_csrf(client, initialized):
    """A native client keeps the session id in Authorization: Bearer and has no cookies — no
    cross-site form can reuse it, so writes must work without the CSRF header. A browser
    client (cookie present) keeps the double-submit requirement."""
    from fastapi.testclient import TestClient
    import main
    hdr = unlock(client)
    sid = client.cookies.get("vault_session")
    with TestClient(main.app, base_url="https://vault.test") as native:   # no cookies at all
        H = {"Authorization": f"Bearer {sid}"}
        assert native.get("/api/folders", headers=H).status_code == 200
        r = native.post("/api/folders", json={"name": "from-native-app"}, headers=H)
        assert r.status_code == 200, r.text
        assert native.post("/api/folders", json={"name": "x"}).status_code in (401, 403), "no session at all → refused"
    # browser-style client with the cookie but without the header → still blocked
    assert client.post("/api/folders", json={"name": "no-csrf"}).status_code == 403
