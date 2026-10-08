"""0.23: a named user's security key (PRF → one-touch sign-in; without PRF → second factor on the
password) and SSO sign-in for users through the per-user SSO cell. The owner's keys and cells are
untouched by any of it."""
import base64
import os

import pytest
from fastapi.testclient import TestClient

import netutil
import settings
from conftest import unlock
from test_webauthn import ORIGIN, SoftKey, b64u

PW = "webauthn user password!!"


def _user(client, hdr, email, fid):
    r = client.post("/api/users", json={"email": email, "grants": [{"folder_id": fid, "role": "reader"}]}, headers=hdr).json()
    tok = r["invite_url"].rsplit("/", 1)[-1]
    import main
    with TestClient(main.app, base_url=ORIGIN) as anon:
        assert anon.post(f"/api/invite/{tok}", json={"password": PW}).status_code == 200
    return r["id"]


def _login(email, pw=PW, webauthn=None):
    import main
    c = TestClient(main.app, base_url=ORIGIN)
    netutil.clear_fails("testclient")
    body = {"email": email, "password": pw}
    if webauthn:
        body["webauthn"] = webauthn
    r = c.post("/api/auth/login", json=body)
    return c, r


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "wa-users"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "wa-secret", "value": "touch-me"}, headers=hdr)
    return {"hdr": hdr, "fid": fid}


def test_user_prf_key_signs_in_without_password_and_owner_is_unaffected(client, world):
    hdr, fid = world["hdr"], world["fid"]
    _user(client, hdr, "wa@example.com", fid)
    c, r = _login("wa@example.com"); assert r.status_code == 200
    uh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert c.get("/api/auth/webauthn/credentials").json()["credentials"] == []
    key = SoftKey(prf=True)
    opts = c.post("/api/auth/webauthn/register/options", json={"name": "user key"}, headers=uh).json()
    assert opts["user"]["name"] == "wa@example.com", "the credential is registered to the person, not to the owner"
    assert c.post("/api/auth/webauthn/register/finish", json={"name": "user key", "credential": key.register(opts), "prf_output": b64u(key.prf_output), "transports": ["usb"], "master_password": "wrong wrong wrong!"}, headers=uh).status_code == 401
    netutil.clear_fails("testclient")
    opts = c.post("/api/auth/webauthn/register/options", json={"name": "user key"}, headers=uh).json()
    r = c.post("/api/auth/webauthn/register/finish", json={"name": "user key", "credential": key.register(opts), "prf_output": b64u(key.prf_output), "transports": ["usb"], "master_password": PW}, headers=uh)
    assert r.status_code == 200 and r.json()["prf"] is True, r.text
    # the owner's view: no new key, status unchanged
    assert client.get("/api/auth/webauthn/status").json()["credentials"] == 0
    assert client.get("/api/auth/webauthn/credentials", headers=hdr).json()["credentials"] == []
    st = client.get("/api/auth/webauthn/status", params={"email": "wa@example.com"}).json()
    assert st["credentials"] == 1 and st["prf_unlock"] is True and st["second_factor"] is False
    # one touch, no password: a user session
    import main
    with TestClient(main.app, base_url=ORIGIN) as anon:
        assert anon.post("/api/auth/webauthn/options", params={"purpose": "unlock"}).status_code == 404, "the owner has no PRF key here"
        o = anon.post("/api/auth/webauthn/options", params={"purpose": "unlock", "email": "wa@example.com"}).json()
        assert any(x["id"] == b64u(key.cred_id) for x in o["allowCredentials"])
        bad = anon.post("/api/auth/webauthn/unlock", json={"credential": key.assertion(o), "prf_output": b64u(os.urandom(32))})
        assert bad.status_code == 401
        netutil.clear_fails("testclient")
        o = anon.post("/api/auth/webauthn/options", params={"purpose": "unlock", "email": "wa@example.com"}).json()
        ok = anon.post("/api/auth/webauthn/unlock", json={"credential": key.assertion(o), "prf_output": b64u(key.prf_output)})
        assert ok.status_code == 200 and ok.json()["kind"] == "user" and ok.json()["email"] == "wa@example.com", ok.text
        me = anon.get("/api/me").json()
        assert me["kind"] == "user" and me["email"] == "wa@example.com"
        secs = anon.get("/api/secrets").json()
        assert [x["name"] for x in secs] == ["wa-secret"], "a user session, scoped by grants"
        assert anon.get("/api/users").status_code == 403, "still not the owner"
    # the owner's password change does not touch the user's key
    r = client.post("/api/auth/change-password", json={"current_password": __import__("conftest").MASTER, "new_password": "owner temp password 2026"}, headers=hdr)
    assert r.status_code == 200
    r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": __import__("conftest").MASTER}); assert r2.status_code == 200
    with TestClient(main.app, base_url=ORIGIN) as anon:
        netutil.clear_fails("testclient")
        o = anon.post("/api/auth/webauthn/options", params={"purpose": "unlock", "email": "wa@example.com"}).json()
        assert anon.post("/api/auth/webauthn/unlock", json={"credential": key.assertion(o), "prf_output": b64u(key.prf_output)}).status_code == 200
    world["hdr"] = unlock(client)


def test_user_second_factor_and_cleanup(client, world):
    hdr, fid = world["hdr"], world["fid"]
    uid = _user(client, hdr, "2fa@example.com", fid)
    c, r = _login("2fa@example.com"); uh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert c.post("/api/auth/webauthn/second-factor", json={"enabled": True}, headers=uh).status_code == 409, "no key yet"
    plain = SoftKey(prf=False)
    opts = c.post("/api/auth/webauthn/register/options", json={"name": "old token"}, headers=uh).json()
    assert c.post("/api/auth/webauthn/register/finish", json={"name": "old token", "credential": plain.register(opts), "master_password": PW}, headers=uh).json()["prf"] is False
    assert c.post("/api/auth/webauthn/second-factor", json={"enabled": True}, headers=uh).json()["second_factor"] is True
    # password alone is no longer enough
    c2, r2 = _login("2fa@example.com")
    assert r2.status_code == 401 and r2.headers.get("x-webauthn-required") == "1"
    import main
    with TestClient(main.app, base_url=ORIGIN) as anon:
        o = anon.post("/api/auth/webauthn/options", params={"purpose": "second_factor", "email": "2fa@example.com"}).json()
        assert len(o["allowCredentials"]) == 1 and "extensions" not in o
        netutil.clear_fails("testclient")
        r3 = anon.post("/api/auth/login", json={"email": "2fa@example.com", "password": PW, "webauthn": plain.assertion(o)})
        assert r3.status_code == 200 and r3.json()["kind"] == "user"
        # someone else's key does not count
        other_uid = _user(client, hdr, "other@example.com", fid)
        oc, orr = _login("other@example.com"); oh = {"X-CSRF-Token": orr.json()["csrf_token"]}
        okey = SoftKey(prf=False)
        oo = oc.post("/api/auth/webauthn/register/options", json={"name": "k"}, headers=oh).json()
        assert oc.post("/api/auth/webauthn/register/finish", json={"name": "k", "credential": okey.register(oo), "master_password": PW}, headers=oh).status_code == 200
        netutil.clear_fails("testclient")
        o2 = anon.post("/api/auth/webauthn/options", params={"purpose": "second_factor", "email": "other@example.com"}).json()
        assert anon.post("/api/auth/login", json={"email": "2fa@example.com", "password": PW, "webauthn": okey.assertion(o2)}).status_code == 401
        netutil.clear_fails("testclient")
    # deleting the only key switches the second factor off (never lock the person out); the owner cannot delete a user's key
    lst = c.get("/api/auth/webauthn/credentials").json()["credentials"]
    assert client.delete(f"/api/auth/webauthn/credentials/{lst[0]['id']}", headers=hdr).status_code == 404
    assert c.delete(f"/api/auth/webauthn/credentials/{lst[0]['id']}", headers=uh).status_code == 200
    assert c.get("/api/auth/webauthn/credentials").json()["second_factor"] is False
    _, r4 = _login("2fa@example.com"); assert r4.status_code == 200
    # a password reset by the owner drops the user's keys (the key pair changed)
    c3, r5 = _login("other@example.com"); assert r5.status_code == 200
    assert len(c3.get("/api/auth/webauthn/credentials").json()["credentials"]) == 1
    client.post(f"/api/users/{other_uid}/invite", headers=hdr)
    import db
    with db.get_session() as s:
        assert s.query(db.WebauthnCredential).filter_by(user_id=other_uid).count() == 0


def test_user_sso_through_the_sso_cell(client, world, monkeypatch):
    hdr, fid = world["hdr"], world["fid"]
    _user(client, hdr, "sso@example.com", fid)
    import main
    import oidc
    # no server SSO key → the user has no cell → an OIDC login for them is refused honestly
    monkeypatch.setattr(oidc, "exchange_code", lambda request: {"email": "sso@example.com", "name": "S"})
    with TestClient(main.app, base_url=ORIGIN) as anon:
        assert anon.get("/api/auth/oidc/callback", follow_redirects=False).status_code == 503
    # with the key: the cell is written on the next password sign-in, then OIDC mints a USER session
    monkeypatch.setattr(settings.SETTINGS, "sso_unlock_key", os.urandom(32))
    _login("sso@example.com")
    with TestClient(main.app, base_url=ORIGIN) as anon:
        r = anon.get("/api/auth/oidc/callback", follow_redirects=False)
        assert r.status_code == 302 and anon.cookies.get("vault_session"), r.text
        me = anon.get("/api/me").json()
        assert me["kind"] == "user" and me["email"] == "sso@example.com"
        assert [x["name"] for x in anon.get("/api/secrets").json()] == ["wa-secret"]
        assert anon.get("/api/users").status_code == 403
    # a deactivated user cannot come in through SSO either
    uid = next(u["id"] for u in client.get("/api/users", headers=hdr).json() if u["email"] == "sso@example.com")
    client.delete(f"/api/users/{uid}", headers=hdr)
    with TestClient(main.app, base_url=ORIGIN) as anon:
        assert anon.get("/api/auth/oidc/callback", follow_redirects=False).status_code != 302
    acts = client.get("/api/audit", params={"limit": 60}, headers=hdr).json()
    assert any(a["action"] == "oidc:login" and a["actor"] == "sso@example.com" for a in acts)
