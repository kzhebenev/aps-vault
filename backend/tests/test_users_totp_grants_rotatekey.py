"""0.30: TOTP for named users (seed under the private key; login demands the code; reset clears it),
managers granting on their own folders (and nothing beyond), and folder key rotation (everything
re-encrypted, grants re-wrapped, tokens and codes of the folder revoked)."""
import base64

import pyotp
import pytest
from fastapi.testclient import TestClient

import db
import netutil
import sealed
from conftest import unlock

PW = "totp user password!!"


def _user(client, hdr, email, grants, pw=PW):
    import main
    r = client.post("/api/users", json={"email": email, "grants": grants}, headers=hdr).json()
    with TestClient(main.app, base_url="https://vault.test") as anon:
        assert anon.post(f"/api/invite/{r['invite_url'].rsplit('/', 1)[-1]}", json={"password": pw}).status_code == 200
    return r["id"]


def _login(email, pw=PW, **extra):
    import main
    c = TestClient(main.app, base_url="https://vault.test")
    netutil.clear_fails("testclient")
    r = c.post("/api/auth/login", json={"email": email, "password": pw, **extra})
    return c, r


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "t30-apps"}, headers=hdr).json()["id"]
    other = client.post("/api/folders", json={"name": "t30-other"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "db", "value": "pw-1", "login": "app", "notes": "n", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": other, "name": "x", "value": "o"}, headers=hdr)
    return {"hdr": hdr, "fid": fid, "other": other}


def test_user_totp_enable_login_disable(client, world):
    hdr, fid = world["hdr"], world["fid"]
    _user(client, hdr, "totp@example.com", [{"folder_id": fid, "role": "reader"}])
    c, r = _login("totp@example.com"); assert r.status_code == 200
    uh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert c.get("/api/me/totp").json()["enabled"] is False
    setup = c.post("/api/me/totp/setup", headers=uh).json()
    assert setup["otpauth_url"].startswith("otpauth://totp/") and "totp%40example.com" in setup["otpauth_url"] and len(setup["secret_base32"]) >= 16
    sec = setup["secret_base32"]
    assert c.post("/api/me/totp/verify", json={"secret_base32": sec, "code": "000000", "password": PW}, headers=uh).status_code == 400, "wrong code"
    assert c.post("/api/me/totp/verify", json={"secret_base32": sec, "code": pyotp.TOTP(sec).now(), "password": "not it"}, headers=uh).status_code == 401, "the password is re-checked"
    netutil.clear_fails("testclient")
    assert c.post("/api/me/totp/verify", json={"secret_base32": sec, "code": pyotp.TOTP(sec).now(), "password": PW}, headers=uh).status_code == 200
    assert c.get("/api/me/totp").json()["enabled"] is True and c.get("/api/me").json().get("totp_enabled") is True
    # the password alone is no longer enough; a wrong code is refused and counted
    _, r2 = _login("totp@example.com")
    assert r2.status_code == 401 and r2.headers.get("x-totp-required") == "1"
    _, r3 = _login("totp@example.com", totp_code="123456")
    assert r3.status_code == 401 and "wrong TOTP" in r3.json()["detail"]
    c4, r4 = _login("totp@example.com", totp_code=pyotp.TOTP(sec).now())
    assert r4.status_code == 200 and r4.json()["kind"] == "user"
    acts = client.get("/api/audit", params={"limit": 20}, headers=hdr).json()
    assert any(a["action"] == "auth:unlock" and "totp" in (a["meta"] or {}).get("how", "") for a in acts) or any(a["action"].startswith("auth:") and "totp" in str(a.get("meta")) for a in acts)
    assert any(a["action"] == "auth:totp_fail" and a["actor"] == "totp@example.com" for a in acts)
    # the owner cannot read the seed: it is under the user's key, nowhere else
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email="totp@example.com").first()
        assert u.totp_secret_enc and sec.encode() not in u.totp_secret_enc
    # disable needs a valid code
    uh4 = {"X-CSRF-Token": r4.json()["csrf_token"]}
    assert c4.post("/api/me/totp/disable", json={"code": "000000"}, headers=uh4).status_code == 401
    assert c4.post("/api/me/totp/disable", json={"code": pyotp.TOTP(sec).now()}, headers=uh4).status_code == 200
    _, r5 = _login("totp@example.com"); assert r5.status_code == 200
    # a password reset by the owner (new key pair) drops the seed too
    c5, r5 = _login("totp@example.com"); uh5 = {"X-CSRF-Token": r5.json()["csrf_token"]}
    setup2 = c5.post("/api/me/totp/setup", headers=uh5).json()
    c5.post("/api/me/totp/verify", json={"secret_base32": setup2["secret_base32"], "code": pyotp.TOTP(setup2["secret_base32"]).now(), "password": PW}, headers=uh5)
    uid = next(u["id"] for u in client.get("/api/users", headers=hdr).json() if u["email"] == "totp@example.com")
    client.post(f"/api/users/{uid}/invite", headers=hdr)
    with db.get_session() as s:
        assert not s.get(db.User, uid).totp_secret_enc
    # the owner's endpoints are not for users and vice versa
    assert client.get("/api/me/totp", headers=hdr).status_code == 400


def test_manager_grants_on_own_folder_only(client, world):
    hdr, fid, other = world["hdr"], world["fid"], world["other"]
    mgr = _user(client, hdr, "mgr30@example.com", [{"folder_id": fid, "role": "manager"}])
    bob = _user(client, hdr, "bob30@example.com", [])
    mc, mr = _login("mgr30@example.com"); mh = {"X-CSRF-Token": mr.json()["csrf_token"]}
    # the directory a manager sees: active people, roles on managed folders only, no keys
    lst = mc.get("/api/users").json()
    assert {u["email"] for u in lst} >= {"mgr30@example.com", "bob30@example.com"} and all("public_key" not in u for u in lst)
    # grant reader on the managed folder → Bob sees the folder's secret
    assert mc.put(f"/api/users/{bob}/grants", json={"folder_id": fid, "role": "writer"}, headers=mh).status_code == 200
    bc, br = _login("bob30@example.com"); assert br.status_code == 200
    names = [x["name"] for x in bc.get("/api/secrets").json()]
    assert names == ["db"] and bc.get("/api/secrets").json()[0]["folder_id"] == fid
    assert bc.get(f"/api/secrets/{bc.get('/api/secrets').json()[0]['id']}").json()["value"] == "pw-1", "the grant wrapped from the manager's key opens the folder"
    # not on another folder, not their own grant
    assert mc.put(f"/api/users/{bob}/grants", json={"folder_id": other, "role": "reader"}, headers=mh).status_code == 403
    assert mc.put(f"/api/users/{mgr}/grants", json={"folder_id": fid, "role": "reader"}, headers=mh).status_code == 403
    assert mc.delete(f"/api/users/{mgr}/grants/{fid}", headers=mh).status_code == 403
    # revoke works on the managed folder
    assert mc.delete(f"/api/users/{bob}/grants/{fid}", headers=mh).status_code == 200
    assert bc.get("/api/secrets").json() == []
    # a reader cannot grant at all; a user without any manager role cannot read the directory
    rdr = _user(client, hdr, "rdr30@example.com", [{"folder_id": fid, "role": "reader"}])
    rc, rr = _login("rdr30@example.com"); rh = {"X-CSRF-Token": rr.json()["csrf_token"]}
    assert rc.put(f"/api/users/{bob}/grants", json={"folder_id": fid, "role": "reader"}, headers=rh).status_code == 403
    assert rc.get("/api/users").status_code == 403
    acts = client.get("/api/audit", params={"limit": 30}, headers=hdr).json()
    assert any(a["action"] == "user:grant" and a["actor"] == "mgr30@example.com" for a in acts)


def test_folder_key_rotation(client, world):
    hdr, fid = world["hdr"], world["fid"]
    # a token, an enrolment code, a user grant and a rotation config live on the folder
    tok = client.post("/api/tokens", json={"name": "t30-token", "folder_id": fid, "can_read_totp": True}, headers=hdr).json()["raw_token"]
    code = client.post("/api/enrollments", json={"folder_id": fid}, headers=hdr).json()["code"]
    uid = _user(client, hdr, "rot30@example.com", [{"folder_id": fid, "role": "reader"}])
    sid = next(x["id"] for x in client.get("/api/secrets", params={"folder_id": fid}, headers=hdr).json() if x["name"] == "db")
    client.patch(f"/api/secrets/{sid}", json={"value": "pw-2"}, headers=hdr)                       # a history row
    client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": "https://rot.example.com/x"}}, headers=hdr)
    before = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    import main
    with TestClient(main.app, base_url="https://vault.test") as m:
        assert m.get("/api/v1/m/secret/db", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    r = client.post(f"/api/folders/{fid}/rotate-key", headers=hdr)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["secrets"] == 1 and res["history"] >= 1 and res["grants"] >= 1 and res["tokens_revoked"] == ["t30-token"] and res["enrollments_revoked"] == 1
    # the owner still reads everything, including history, TOTP and the rotation config
    after = client.get(f"/api/secrets/{sid}", headers=hdr).json()
    assert after["value"] == "pw-2" and after["login"] == "app" and after["notes"] == "n" and len(after["totp"]) == 6 and after["version"] == before["version"]
    hist = client.get(f"/api/secrets/{sid}/history", headers=hdr).json()["history"]
    assert hist[0]["value"] == "pw-1"
    assert client.get(f"/api/secrets/{sid}/rotation", headers=hdr).json()["config"]["url"] == "https://rot.example.com/x"
    # the user's grant was re-wrapped: they still read
    uc, ur = _login("rot30@example.com"); assert ur.status_code == 200
    assert uc.get(f"/api/secrets/{sid}").json()["value"] == "pw-2"
    # the old token and the enrolment code are dead — the key they carried is gone
    with TestClient(main.app, base_url="https://vault.test") as m:
        assert m.get("/api/v1/m/secret/db", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
        sk, pk = sealed.generate_keypair()
        assert m.post("/api/enroll", json={"code": code, "public_key": pk}).status_code == 404
        netutil.clear_fails("testclient")
    # a new token works
    tok2 = client.post("/api/tokens", json={"name": "t30-token-2", "folder_id": fid}, headers=hdr).json()["raw_token"]
    with TestClient(main.app, base_url="https://vault.test") as m:
        assert m.get("/api/v1/m/secret/db", headers={"Authorization": f"Bearer {tok2}"}).json()["value"] == "pw-2"
    # not for users
    uh = {"X-CSRF-Token": ur.json()["csrf_token"]}
    assert uc.post(f"/api/folders/{fid}/rotate-key", headers=uh).status_code == 403
    acts = client.get("/api/audit", params={"limit": 30}, headers=hdr).json()
    assert any(a["action"] == "folder:rotate_key" and a["target"] == "t30-apps" for a in acts)
