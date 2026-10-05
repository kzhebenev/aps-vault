"""Named users with per-folder roles (0.20): invitation → password → login; what each role may
and may not do (403s are the proof); filtering of folders/secrets; audit by e-mail; re-invite
regenerates the key pair and keeps the grants working; deactivation closes sessions; the owner's
endpoints stay the owner's."""
import pytest
from fastapi.testclient import TestClient

import netutil
from conftest import MASTER, unlock

ORIGIN = "https://vault.test"
PW = "reader password 2026!!"


def _login(email, pw=PW):
    import main
    c = TestClient(main.app, base_url=ORIGIN)
    netutil.clear_fails("testclient")
    r = c.post("/api/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return c, {"X-CSRF-Token": r.json()["csrf_token"]}


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fa = client.post("/api/folders", json={"name": "team-a"}, headers=hdr).json()["id"]
    fb = client.post("/api/folders", json={"name": "team-b"}, headers=hdr).json()["id"]
    sa = client.post("/api/secrets", json={"folder_id": fa, "name": "a-secret", "value": "alpha", "login": "a", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr).json()["id"]
    sb = client.post("/api/secrets", json={"folder_id": fb, "name": "b-secret", "value": "bravo"}, headers=hdr).json()["id"]
    return {"hdr": hdr, "fa": fa, "fb": fb, "sa": sa, "sb": sb}


def test_invite_flow_and_reader_role(client, world):
    hdr = world["hdr"]
    assert client.get("/api/me").json()["kind"] == "owner"
    r = client.post("/api/users", json={"email": "Reader@Example.com", "name": "Ria", "grants": [{"folder_id": world["fa"], "role": "reader"}]}, headers=hdr)
    assert r.status_code == 200, r.text
    inv = r.json()["invite_url"]
    assert inv.startswith("/invite/") and r.json()["email"] == "reader@example.com"
    assert client.post("/api/users", json={"email": "reader@example.com"}, headers=hdr).status_code == 400, "duplicate e-mail"
    assert client.post("/api/users", json={"email": "nope"}, headers=hdr).status_code == 400
    token = inv.rsplit("/", 1)[-1]
    with TestClient(__import__("main").app, base_url=ORIGIN) as anon:
        assert anon.get(f"/api/invite/{token}").json() == {"email": "reader@example.com", "name": "Ria"}
        assert anon.get("/api/invite/garbage").status_code == 404
        assert anon.post(f"/api/invite/{token}", json={"password": "short"}).status_code == 422
        assert anon.post("/api/auth/login", json={"email": "reader@example.com", "password": PW}).status_code == 401, "no password yet"
        netutil.clear_fails("testclient")
        assert anon.post(f"/api/invite/{token}", json={"password": PW}).status_code == 200
        assert anon.post(f"/api/invite/{token}", json={"password": PW}).status_code == 400, "an invitation is single-use"
        netutil.clear_fails("testclient")
        assert anon.post("/api/auth/login", json={"email": "reader@example.com", "password": PW + "x"}).status_code == 401
        netutil.clear_fails("testclient")
    lst = client.get("/api/users", headers=hdr).json()
    me = next(u for u in lst if u["email"] == "reader@example.com")
    assert me["has_password"] is True and me["invite_pending"] is False and me["grants"] == [{"folder_id": world["fa"], "folder_name": "team-a", "role": "reader"}]
    # ── as the reader ──
    c, uh = _login("reader@example.com")
    me = c.get("/api/me").json()
    assert me["kind"] == "user" and me["email"] == "reader@example.com" and me["grants"] == {str(world["fa"]): "reader"} or me["grants"] == {world["fa"]: "reader"}
    folders = c.get("/api/folders").json()
    assert [f["name"] for f in folders] == ["team-a"] and folders[0]["role"] == "reader", "only the granted folder is visible"
    secrets = c.get("/api/secrets").json()
    assert [x["name"] for x in secrets] == ["a-secret"]
    full = c.get(f"/api/secrets/{world['sa']}").json()
    assert full["value"] == "alpha" and full["login"] == "a" and len(full["totp"]) == 6
    assert c.get(f"/api/secrets/{world['sa']}/totp").status_code == 200
    assert c.get(f"/api/secrets/{world['sa']}/history").status_code == 200
    assert c.post(f"/api/secrets/{world['sa']}/favorite", headers=uh).status_code == 200
    # the other folder does not exist for this user
    assert c.get(f"/api/secrets/{world['sb']}").status_code == 403
    assert c.get("/api/secrets", params={"folder_id": world["fb"]}).json() == []
    # a reader may not write, delete, rotate, issue tokens or share
    assert c.post("/api/secrets", json={"folder_id": world["fa"], "name": "x", "value": "y"}, headers=uh).status_code == 403
    assert c.patch(f"/api/secrets/{world['sa']}", json={"value": "changed"}, headers=uh).status_code == 403
    assert c.delete(f"/api/secrets/{world['sa']}", headers=uh).status_code == 403
    assert c.post(f"/api/secrets/{world['sa']}/rotate", json={"generate": "hex:32"}, headers=uh).status_code == 403
    assert c.post("/api/tokens", json={"name": "t", "folder_id": world["fa"]}, headers=uh).status_code == 403
    assert c.post("/api/share", json={"secret_id": world["sa"], "ttl_minutes": 10, "max_uses": 1, "note": ""}, headers=uh).status_code == 403
    assert c.get("/api/tokens").json() == [] and c.get("/api/shares").json() == []
    # owner-only surfaces are closed with 403, not 401
    for m, p in (("GET", "/api/users"), ("POST", "/api/folders"), ("GET", "/api/audit"), ("GET", "/api/export"), ("GET", "/api/stats"),
                 ("GET", "/api/webhooks"), ("POST", "/api/auth/change-password"), ("GET", "/api/auth/sso-unlock/status")):
        r = c.request(m, p, json={} if m == "POST" else None, headers=uh)
        assert r.status_code == 403, (m, p, r.status_code, r.text)
    assert c.post("/api/auth/lock", params={"all": 1}, headers=uh).status_code == 403
    # the reader's own password change and lock
    assert c.post("/api/me/password", json={"current_password": "wrong wrong wrong!", "new_password": PW + "new"}, headers=uh).status_code == 400
    assert c.post("/api/me/password", json={"current_password": PW, "new_password": PW + "new"}, headers=uh).status_code == 200
    assert c.post("/api/auth/lock", headers=uh).status_code == 200
    assert c.get("/api/me").status_code == 401
    c2, _ = _login("reader@example.com", PW + "new")
    assert c2.get("/api/me").json()["email"] == "reader@example.com"
    # audit names the person
    acts = client.get("/api/audit", params={"limit": 100}, headers=hdr).json()
    assert any(a["action"] == "secret:read" and a["actor"] == "reader@example.com" for a in acts)
    assert any(a["action"] == "auth:login" and a["actor"] == "reader@example.com" for a in acts)


def test_writer_and_manager_roles(client, world):
    hdr = world["hdr"]
    r = client.post("/api/users", json={"email": "ops@example.com", "name": "Ops"}, headers=hdr).json()
    uid, token = r["id"], r["invite_url"].rsplit("/", 1)[-1]
    with TestClient(__import__("main").app, base_url=ORIGIN) as anon:
        assert anon.post(f"/api/invite/{token}", json={"password": PW}).status_code == 200
    assert client.put(f"/api/users/{uid}/grants", json={"folder_id": world["fa"], "role": "writer"}, headers=hdr).status_code == 200
    assert client.put(f"/api/users/{uid}/grants", json={"folder_id": world["fb"], "role": "manager"}, headers=hdr).status_code == 200
    assert client.put(f"/api/users/{uid}/grants", json={"folder_id": world["fb"], "role": "god"}, headers=hdr).status_code == 422
    c, uh = _login("ops@example.com")
    # writer on team-a: create, update (new version), rotate, delete; but no tokens/shares there
    sid = c.post("/api/secrets", json={"folder_id": world["fa"], "name": "deploy-key", "value": "v1"}, headers=uh).json()["id"]
    assert c.patch(f"/api/secrets/{sid}", json={"value": "v2"}, headers=uh).status_code == 200
    hist = c.get(f"/api/secrets/{sid}/history").json()
    assert hist["current_version"] == 2 and hist["history"][0]["changed_by"] == "ops@example.com"
    assert c.post(f"/api/secrets/{sid}/rotate", json={"generate": "hex:32"}, headers=uh).status_code == 200
    assert c.post("/api/tokens", json={"name": "t-a", "folder_id": world["fa"]}, headers=uh).status_code == 403
    # moving a secret into a folder where the user is only a reader/none is refused
    assert c.patch(f"/api/secrets/{sid}", json={"folder_id": world["fb"]}, headers=uh).status_code == 200, "manager ⊇ writer on team-b"
    assert c.delete(f"/api/secrets/{sid}", headers=uh).status_code == 200
    # manager on team-b: issue a token (it must read the secret), share, see and revoke them
    t = c.post("/api/tokens", json={"name": "b-node", "folder_id": world["fb"]}, headers=uh)
    assert t.status_code == 200, t.text
    m = client.get("/api/v1/m/secret/b-secret", headers={"Authorization": f"Bearer {t.json()['raw_token']}"})
    assert m.status_code == 200 and m.json()["value"] == "bravo", "a token issued by a manager opens the folder exactly like the owner's"
    assert [x["name"] for x in c.get("/api/tokens").json()] == ["b-node"]
    sh = c.post("/api/share", json={"secret_id": world["sb"], "ttl_minutes": 10, "max_uses": 1, "note": "for you"}, headers=uh)
    assert sh.status_code == 200 and len(c.get("/api/shares").json()) == 1
    assert c.delete(f"/api/shares/{sh.json()['id']}", headers=uh).status_code == 200
    assert c.delete(f"/api/tokens/{t.json()['id']}", headers=uh).status_code == 200
    # the owner sees everything the user did, by name
    acts = client.get("/api/audit", params={"limit": 100}, headers=hdr).json()
    assert any(a["action"] == "token:create" and a["actor"] == "ops@example.com" for a in acts)
    # revoking a grant takes the folder away at once
    assert client.delete(f"/api/users/{uid}/grants/{world['fb']}", headers=hdr).status_code == 200
    assert c.get(f"/api/secrets/{world['sb']}").status_code == 403
    assert [f["name"] for f in c.get("/api/folders").json()] == ["team-a"]


def test_reinvite_and_deactivate(client, world):
    hdr = world["hdr"]
    uid = next(u["id"] for u in client.get("/api/users", headers=hdr).json() if u["email"] == "ops@example.com")
    c, uh = _login("ops@example.com")
    assert c.get("/api/me").status_code == 200
    # re-invite: old password dead, sessions closed, grants re-created to the NEW key pair
    r = client.post(f"/api/users/{uid}/invite", headers=hdr)
    assert r.status_code == 200
    assert c.get("/api/me").status_code == 401, "sessions revoked"
    netutil.clear_fails("testclient")
    assert TestClient(__import__("main").app, base_url=ORIGIN).post("/api/auth/login", json={"email": "ops@example.com", "password": PW}).status_code == 401
    netutil.clear_fails("testclient")
    token = r.json()["invite_url"].rsplit("/", 1)[-1]
    with TestClient(__import__("main").app, base_url=ORIGIN) as anon:
        assert anon.post(f"/api/invite/{token}", json={"password": PW + "again"}).status_code == 200
    c, uh = _login("ops@example.com", PW + "again")
    secs = c.get("/api/secrets").json()
    assert [x["name"] for x in secs] == ["a-secret"]
    assert c.get(f"/api/secrets/{world['sa']}").json()["value"] == "alpha", "the re-created grant opens the folder"
    # deactivate: 401 on the next request, login refused, grants gone
    assert client.delete(f"/api/users/{uid}", headers=hdr).status_code == 200
    assert c.get("/api/me").status_code == 401
    netutil.clear_fails("testclient")
    assert TestClient(__import__("main").app, base_url=ORIGIN).post("/api/auth/login", json={"email": "ops@example.com", "password": PW + "again"}).status_code == 401
    netutil.clear_fails("testclient")
    assert next(u for u in client.get("/api/users", headers=hdr).json() if u["id"] == uid)["is_active"] is False
    # the owner's own view is unchanged: both folders, all secrets
    assert len(client.get("/api/folders", headers=hdr).json()) >= 2


def test_login_lockout_counts_like_the_master_password(client, world):
    import main
    with TestClient(main.app, base_url=ORIGIN) as anon:
        netutil.clear_fails("testclient")
        for _ in range(5):
            anon.post("/api/auth/login", json={"email": "reader@example.com", "password": "nope nope nope nope"})
        r = anon.post("/api/auth/login", json={"email": "reader@example.com", "password": PW + "new"})
        assert r.status_code == 429, "the per-IP budget is shared with the master password"
    netutil.clear_fails("testclient")
