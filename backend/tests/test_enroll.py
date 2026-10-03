"""Node enrolment (0.21): a code made by the owner or a folder manager; the node brings its own
public key and gets a sealed token; spent / expired / revoked / foreign codes fail and count."""
import base64

import pytest
from fastapi.testclient import TestClient

import netutil
import sealed
from conftest import unlock


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "enrol-scope"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "node-key", "value": "k-2026", "login": "svc", "notes": "n", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr)
    return {"hdr": hdr, "fid": fid}


def _anon():
    import main
    return TestClient(main.app, base_url="https://vault.test")


def test_enrol_issues_a_sealed_token(client, world):
    hdr, fid = world["hdr"], world["fid"]
    r = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "core", "ttl_minutes": 30, "max_uses": 2, "can_read_notes": True}, headers=hdr)
    assert r.status_code == 200, r.text
    code = r.json()["code"]
    assert code.startswith("enr_") and "aps_vault enroll" in r.json()["command"] and r.json()["max_uses"] == 2
    lst = client.get("/api/enrollments", headers=hdr).json()
    assert lst[0]["active"] is True and lst[0]["used_count"] == 0 and lst[0]["created_by"] == "master" and lst[0]["options"]["can_read_notes"] is True
    # the node, with no session: X25519 pair → sealed token
    sk, pk = sealed.generate_keypair()
    with _anon() as node:
        bad = node.post("/api/enroll", json={"code": "enr_nope-nope-nope-nope-nope", "public_key": pk, "name": "x"})
        assert bad.status_code == 404
        netutil.clear_fails("testclient")
        assert node.post("/api/enroll", json={"code": code, "public_key": "AAAA", "name": "x"}).status_code == 422, "malformed key"
        e = node.post("/api/enroll", json={"code": code, "public_key": pk, "name": "app-01"})
        assert e.status_code == 200, e.text
        j = e.json()
        assert j["token_name"] == "core-app-01" and j["folder_name"] == "enrol-scope" and j["sealed"] is True and j["raw_token"].startswith("vlt_")
        tok = j["raw_token"]
        got = node.get("/api/v1/m/secret/node-key", headers={"Authorization": f"Bearer {tok}"}).json()
        assert "value" not in got and got["sealed"]["alg"] == sealed.ALG
        pt = sealed.unseal(got["sealed"], base64.b64decode(sk), "node-key")
        assert pt["value"] == "k-2026" and pt["notes"] == "n" and "totp" not in pt, "options of the code shape the token (notes yes, totp no)"
        # second node with the same code and the same host name gets a distinct token name; a GOST key is fine too
        gsk, gpk = sealed.generate_keypair("gost")
        e2 = node.post("/api/enroll", json={"code": code, "public_key": gpk, "name": "app-01"})
        assert e2.status_code == 200 and e2.json()["token_name"] == "core-app-01-2"
        g = node.get("/api/v1/m/secret/node-key", headers={"Authorization": f"Bearer {e2.json()['raw_token']}"}).json()
        assert g["sealed"]["alg"] == sealed.ALG_GOST and sealed.unseal(g["sealed"], base64.b64decode(gsk), "node-key")["value"] == "k-2026"
        # third use: spent → 410, counted as a failure
        e3 = node.post("/api/enroll", json={"code": code, "public_key": pk, "name": "app-02"})
        assert e3.status_code == 410
        netutil.clear_fails("testclient")
    lst = client.get("/api/enrollments", headers=hdr).json()
    assert lst[0]["used_count"] == 2 and lst[0]["active"] is False
    toks = client.get("/api/tokens", headers=hdr).json()
    assert {t["name"] for t in toks} >= {"core-app-01", "core-app-01-2"} and all(t["sealed"] for t in toks if t["name"].startswith("core-"))
    acts = client.get("/api/audit", params={"limit": 50}, headers=hdr).json()
    assert {"enroll:create", "enroll:issue", "enroll:fail"} <= {a["action"] for a in acts}


def test_enrol_revoked_expired_and_roles(client, world):
    hdr, fid = world["hdr"], world["fid"]
    r = client.post("/api/enrollments", json={"folder_id": fid, "max_uses": 5}, headers=hdr).json()
    assert client.delete(f"/api/enrollments/{r['id']}", headers=hdr).status_code == 200
    sk, pk = sealed.generate_keypair()
    with _anon() as node:
        assert node.post("/api/enroll", json={"code": r["code"], "public_key": pk}).status_code == 404, "revoked = unknown"
        netutil.clear_fails("testclient")
    # expired: shortest TTL, then move the clock
    import db
    r2 = client.post("/api/enrollments", json={"folder_id": fid, "ttl_minutes": 1}, headers=hdr).json()
    with db.get_session() as s:
        e = s.get(db.Enrollment, r2["id"]); e.expires_at = db.utcnow().replace(tzinfo=None); s.commit()
    with _anon() as node:
        assert node.post("/api/enroll", json={"code": r2["code"], "public_key": pk}).status_code == 404
        netutil.clear_fails("testclient")
    # source-address policy on the code: the test client is not an IP → refused
    r3 = client.post("/api/enrollments", json={"folder_id": fid, "allowed_cidrs": "10.0.0.0/8"}, headers=hdr).json()
    with _anon() as node:
        assert node.post("/api/enroll", json={"code": r3["code"], "public_key": pk}).status_code == 403
        netutil.clear_fails("testclient")
    # a reader may not create codes; a manager may, only on their folder
    u = client.post("/api/users", json={"email": "enrol@example.com", "grants": [{"folder_id": fid, "role": "reader"}]}, headers=hdr).json()
    with _anon() as anon:
        assert anon.post(f"/api/invite/{u['invite_url'].rsplit('/', 1)[-1]}", json={"password": "enrol user password!"}).status_code == 200
    import main
    uc = TestClient(main.app, base_url="https://vault.test")
    netutil.clear_fails("testclient")
    lr = uc.post("/api/auth/login", json={"email": "enrol@example.com", "password": "enrol user password!"}); uh = {"X-CSRF-Token": lr.json()["csrf_token"]}
    assert uc.post("/api/enrollments", json={"folder_id": fid}, headers=uh).status_code == 403
    assert client.put(f"/api/users/{u['id']}/grants", json={"folder_id": fid, "role": "manager"}, headers=hdr).status_code == 200
    rm = uc.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "mgr"}, headers=uh)
    assert rm.status_code == 200 and rm.json()["code"].startswith("enr_")
    assert any(x["created_by"] == "enrol@example.com" for x in uc.get("/api/enrollments").json())
    other = client.post("/api/folders", json={"name": "not-mine"}, headers=hdr).json()["id"]
    assert uc.post("/api/enrollments", json={"folder_id": other}, headers=uh).status_code == 403
    with _anon() as node:
        e = node.post("/api/enroll", json={"code": rm.json()["code"], "public_key": pk, "name": "n1"})
        assert e.status_code == 200 and e.json()["token_name"] == "mgr-n1"
