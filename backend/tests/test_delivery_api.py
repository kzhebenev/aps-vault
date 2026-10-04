"""0.30.1 delivery additions: an enrolment code can grant can_write; a can_write token can delete
its secrets and read the audit of its own folder only; read-only tokens get 403 for all three."""
import base64
import pytest
import db
import sealed
from conftest import unlock


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "deliv-app"}, headers=hdr).json()["id"]
    other = client.post("/api/folders", json={"name": "deliv-other"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "app-key", "value": "k1"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": other, "name": "other-key", "value": "o1"}, headers=hdr)
    return {"hdr": hdr, "fid": fid, "other": other}


def _enrol_token(client, hdr, fid, **opts):
    code = client.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "n", "max_uses": 1, **opts}, headers=hdr).json()["code"]
    sk, pk = sealed.generate_keypair()
    e = client.post("/api/enroll", json={"code": code, "public_key": pk, "name": "node"})
    assert e.status_code == 200, e.text
    return e.json()["raw_token"], base64.b64decode(sk)


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_enrolment_code_can_grant_write(client, world):
    ro, _ = _enrol_token(client, world["hdr"], world["fid"])
    rw, _ = _enrol_token(client, world["hdr"], world["fid"], can_write=True)
    assert client.post("/api/v1/m/secret/new-one", json={"value": "v"}, headers=_auth(ro)).status_code == 403, "default stays read-only"
    r = client.post("/api/v1/m/secret/new-one", json={"value": "v"}, headers=_auth(rw))
    assert r.status_code == 200, r.text
    with db.get_session() as s:
        flags = sorted(bool(t.can_write) for t in s.query(db.ServiceToken).filter_by(folder_id=world["fid"]).all())
    assert flags == [False, True]


def test_delete_by_token_needs_write_and_stays_in_scope(client, world):
    ro, _ = _enrol_token(client, world["hdr"], world["fid"])
    rw, _ = _enrol_token(client, world["hdr"], world["fid"], can_write=True)
    assert client.delete("/api/v1/m/secret/app-key", headers=_auth(ro)).status_code == 403
    assert client.delete("/api/v1/m/secret/other-key", headers=_auth(rw)).status_code == 404, "another folder's secret is invisible"
    assert client.delete("/api/v1/m/secret/no-such", headers=_auth(rw)).status_code == 404
    assert client.post("/api/v1/m/secret/to-delete", json={"value": "x"}, headers=_auth(rw)).status_code == 200
    r = client.delete("/api/v1/m/secret/to-delete", headers=_auth(rw))
    assert r.status_code == 200 and r.json()["ok"] is True
    assert client.get("/api/v1/m/secret/to-delete", headers=_auth(rw)).status_code == 404
    with db.get_session() as s:
        assert s.query(db.Secret).filter_by(folder_id=world["fid"], name="to-delete").count() == 0
        assert s.query(db.Secret).filter_by(folder_id=world["other"], name="other-key").count() == 1


def test_audit_by_token_is_own_folder_only(client, world):
    ro, _ = _enrol_token(client, world["hdr"], world["fid"])
    rw, _ = _enrol_token(client, world["hdr"], world["fid"], can_write=True)
    assert client.get("/api/v1/m/audit", headers=_auth(ro)).status_code == 403
    client.post("/api/v1/m/secret/audited", json={"value": "a"}, headers=_auth(rw))
    client.get("/api/v1/m/secret/audited", headers=_auth(rw))
    # activity in the other folder through the human API
    client.get("/api/secrets", headers=world["hdr"])
    rows = client.get("/api/v1/m/audit?limit=50", headers=_auth(rw)).json()
    assert rows and all(r["target"].startswith("deliv-app/") for r in rows), rows[:3]
    actions = {r["action"] for r in rows}
    assert {"m:secret:put", "m:secret:read"} <= actions
    assert not any("deliv-other" in r["target"] for r in rows)
