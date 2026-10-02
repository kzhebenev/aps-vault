"""Folders, secrets, URL validation, service-token scope and machine API."""
from conftest import unlock


def _folder(client, hdr, name):
    r = client.post("/api/folders", json={"name": name}, headers=hdr)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_secret_crud_history_and_totp(client, session):
    fid = _folder(client, session, "crud")
    r = client.post("/api/secrets", json={"folder_id": fid, "name": "db", "value": "p1", "login": "app",
                                          "notes": "n", "totp_seed": "JBSWY3DPEHPK3PXP", "url": "https://db.example"}, headers=session)
    sid = r.json()["id"]
    full = client.get(f"/api/secrets/{sid}").json()
    assert full["value"] == "p1" and full["login"] == "app" and full["notes"] == "n"
    assert full["totp"] and len(full["totp"]) == 6
    lst = client.get("/api/secrets", params={"folder_id": fid}).json()
    assert lst[0]["name"] == "db" and "value" not in lst[0]
    assert client.patch(f"/api/secrets/{sid}", json={"value": "p2"}, headers=session).status_code == 200
    hist = client.get(f"/api/secrets/{sid}/history").json()
    assert hist["count"] == 1 and hist["history"][0]["value"] == "p1"
    assert client.get(f"/api/secrets/{sid}").json()["value"] == "p2"
    assert client.delete(f"/api/secrets/{sid}", headers=session).status_code == 200
    assert client.get(f"/api/secrets/{sid}").status_code == 404


def test_url_must_be_http(client, session):
    fid = _folder(client, session, "urls")
    bad = client.post("/api/secrets", json={"folder_id": fid, "name": "x", "value": "v", "url": "javascript:alert(1)"}, headers=session)
    assert bad.status_code == 422
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "x", "value": "v"}, headers=session).json()["id"]
    assert client.patch(f"/api/secrets/{sid}", json={"url": "data:text/html,x"}, headers=session).status_code == 422
    assert client.patch(f"/api/secrets/{sid}", json={"url": "https://ok.example"}, headers=session).status_code == 200


def test_token_is_scoped_to_one_folder_and_works_while_locked(client, session):
    fa = _folder(client, session, "scope-a")
    fb = _folder(client, session, "scope-b")
    client.post("/api/secrets", json={"folder_id": fa, "name": "mine", "value": "A", "notes": "secret notes",
                                      "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=session)
    client.post("/api/secrets", json={"folder_id": fb, "name": "theirs", "value": "B"}, headers=session)
    tok = client.post("/api/tokens", json={"name": "svc-a", "folder_id": fa}, headers=session).json()["raw_token"]
    assert tok.startswith("vlt_")
    H = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/v1/m/health", headers=H).json()["scope_folder"] == "scope-a"
    r = client.get("/api/v1/m/secret/mine", headers=H).json()
    assert r["value"] == "A" and "notes" not in r and "totp" not in r, "notes/totp need explicit grants"
    assert client.get("/api/v1/m/secret/theirs", headers=H).status_code == 404, "other folder is invisible"
    names = [s["name"] for s in client.get("/api/v1/m/secrets", headers=H).json()]
    assert names == ["mine"]
    # read-only by default
    assert client.post("/api/v1/m/secret/mine", json={"value": "hack"}, headers=H).status_code == 403
    # garbage token
    assert client.get("/api/v1/m/secret/mine", headers={"Authorization": "Bearer vlt_nope"}).status_code == 401
    # lock the vault — machine API must keep working
    client.post("/api/auth/lock", headers=session)
    assert client.get("/api/folders").status_code == 401
    assert client.get("/api/v1/m/secret/mine", headers=H).json()["value"] == "A"
    unlock(client)


def test_token_with_grants_and_revocation(client, session):
    fid = _folder(client, session, "grants")
    client.post("/api/secrets", json={"folder_id": fid, "name": "s", "value": "v1", "notes": "nn",
                                      "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=session)
    t = client.post("/api/tokens", json={"name": "rw", "folder_id": fid, "can_read_notes": True,
                                         "can_read_totp": True, "can_write": True}, headers=session).json()
    H = {"Authorization": f"Bearer {t['raw_token']}"}
    r = client.get("/api/v1/m/secret/s", headers=H).json()
    assert r["notes"] == "nn" and len(r["totp"]) == 6
    # upsert: update existing → history; create new
    assert client.post("/api/v1/m/secret/s", json={"value": "v2"}, headers=H).json()["created"] is False
    assert client.post("/api/v1/m/secret/new", json={"value": "n", "url": "javascript:x"}, headers=H).status_code == 422
    assert client.post("/api/v1/m/secret/new", json={"value": "n"}, headers=H).json()["created"] is True
    sid = next(s["id"] for s in client.get("/api/secrets", params={"folder_id": fid}).json() if s["name"] == "s")
    assert client.get(f"/api/secrets/{sid}/history").json()["history"][0]["changed_by"] == f"token:{t['id']}"
    # revoke → 401 immediately
    assert client.delete(f"/api/tokens/{t['id']}", headers=session).status_code == 200
    assert client.get("/api/v1/m/secret/s", headers=H).status_code == 401
    # audit saw the machine reads
    actions = {a["action"] for a in client.get("/api/audit", params={"limit": 200}).json()}
    assert {"m:secret:read", "m:secret:put", "token:revoke"} <= actions


def test_folder_delete_rules(client, session):
    fid = _folder(client, session, "to-delete")
    client.post("/api/secrets", json={"folder_id": fid, "name": "s", "value": "v"}, headers=session)
    assert client.delete(f"/api/folders/{fid}", headers=session).status_code == 400
    sid = client.get("/api/secrets", params={"folder_id": fid}).json()[0]["id"]
    client.delete(f"/api/secrets/{sid}", headers=session)
    assert client.delete(f"/api/folders/{fid}", headers=session).status_code == 200
    assert client.post("/api/folders", json={"name": "to-delete"}, headers=session).status_code == 200  # name free again


def test_export_import_roundtrip(client, session):
    fid = _folder(client, session, "exp")
    client.post("/api/secrets", json={"folder_id": fid, "name": "e1", "value": "val", "login": "u"}, headers=session)
    dump = client.get("/api/export").json()
    fld = next(f for f in dump["folders"] if f["name"] == "exp")
    assert fld["secrets"][0]["value"] == "val"
    fld["name"] = "exp-imported"
    r = client.post("/api/import", json={"folders": [fld]}, headers=session).json()
    assert r["created_folders"] == 1 and r["created_secrets"] == 1
    imp = next(f for f in client.get("/api/folders").json() if f["name"] == "exp-imported")
    sid = client.get("/api/secrets", params={"folder_id": imp["id"]}).json()[0]["id"]
    assert client.get(f"/api/secrets/{sid}").json()["login"] == "u"


def test_hashicorp_kv2_compat_facade(client, session):
    """A HashiCorp KV v2 client (X-Vault-Token, /v1/<mount>/data/<name>) works unchanged."""
    fid = _folder(client, session, "hashi")
    client.post("/api/secrets", json={"folder_id": fid, "name": "app/db", "value": "pw", "login": "svc"}, headers=session)
    tok = client.post("/api/tokens", json={"name": "kv", "folder_id": fid}, headers=session).json()["raw_token"]
    r = client.get("/v1/hashi/data/app/db", headers={"X-Vault-Token": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["data"] == {"value": "pw", "login": "svc"}
    assert body["data"]["metadata"]["version"] == 1 and body["lease_id"] == "" and body["auth"] is None
    # wrong mount for this token → 403 in HashiCorp's error shape; unknown path → 404
    assert client.get("/v1/other/data/app/db", headers={"X-Vault-Token": tok}).status_code == 403
    assert client.get("/v1/hashi/data/nope", headers={"X-Vault-Token": tok}).status_code == 404
    assert client.get("/v1/hashi/data/app/db").status_code == 401
    h = client.get("/v1/sys/health").json()
    assert h["sealed"] is False and h["initialized"] is True
