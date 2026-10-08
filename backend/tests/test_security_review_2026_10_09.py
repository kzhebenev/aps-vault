"""Findings of the 09.10.2026 review (three independent reviewers after agent keys landed). Each test failed on 0.41.14
before its fix. Flags: machine_only — no person sees the value; require_approval — a second person approves each read
by a person. Machine access to a folder that holds flagged secrets is handed out by the owner in person (0.37)."""
import pytest
from fastapi.testclient import TestClient

import db
import main
import netutil
from conftest import MASTER, unlock


def _agent(client, owner, name):
    k = client.post("/api/agent-keys", json={"name": name}, headers=owner).json()
    c = TestClient(main.app, base_url="https://vault.test")
    netutil.clear_fails("testclient")
    lg = c.post("/api/auth/agent", json={"key": k["key"]})
    assert lg.status_code == 200, lg.text
    return k, c, {"X-CSRF-Token": lg.json()["csrf_token"]}


@pytest.fixture(scope="module")
def owner(client, initialized):
    return unlock(client)


# 1. machine access handed out by a non-owner BEFORE a flag appeared ─────────────────────────────────────────────────
def test_a_flag_is_refused_while_a_non_owner_holds_machine_access_to_the_folder(client, owner):
    fid = client.post("/api/folders", json={"name": "sr-flag-later"}, headers=owner).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-plain", "value": "v"}, headers=owner).json()["id"]
    k, c, h = _agent(client, owner, "sr-flag-later")
    tok = c.post("/api/tokens", json={"name": "sr-agent-token", "folder_id": fid}, headers=h).json()
    # the owner now flags a secret / creates a flagged one there — the agent's token would read it
    r = client.patch(f"/api/secrets/{sid}", json={"machine_only": True}, headers=owner)
    assert r.status_code == 409 and "sr-agent-token" in r.text, r.text
    r = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-flagged", "value": "secret-v", "require_approval": True}, headers=owner)
    assert r.status_code == 409, r.text
    assert client.get("/api/v1/m/secret/sr-flagged", headers={"Authorization": f"Bearer {tok['raw_token']}"}).status_code == 404
    # once that access is gone the owner flags freely
    client.delete(f"/api/tokens/{tok['id']}", headers=owner)
    assert client.patch(f"/api/secrets/{sid}", json={"machine_only": True}, headers=owner).status_code == 200


def test_an_enrolment_code_counts_too(client, owner):
    fid = client.post("/api/folders", json={"name": "sr-enrol-later"}, headers=owner).json()["id"]
    k, c, h = _agent(client, owner, "sr-enrol-later")
    assert c.post("/api/enrollments", json={"folder_id": fid}, headers=h).status_code == 200
    r = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-ef", "value": "v", "machine_only": True}, headers=owner)
    assert r.status_code == 409, r.text


def test_owner_issued_machine_access_does_not_block_a_flag(client, owner):
    fid = client.post("/api/folders", json={"name": "sr-owner-tok"}, headers=owner).json()["id"]
    assert client.post("/api/tokens", json={"name": "sr-owner-token", "folder_id": fid}, headers=owner).status_code == 200
    assert client.post("/api/secrets", json={"folder_id": fid, "name": "sr-of", "value": "v", "machine_only": True}, headers=owner).status_code == 200


# 2. TOTP of an approval-gated secret, and both flags together ───────────────────────────────────────────────────────
def test_totp_and_side_fields_of_an_approval_secret_need_the_approval(client, owner):
    fid = client.post("/api/folders", json={"name": "sr-totp"}, headers=owner).json()["id"]
    a = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-appr", "value": "v", "totp_seed": "JBSWY3DPEHPK3PXP",
                                          "require_approval": True}, headers=owner).json()["id"]
    b = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-both", "value": "v", "notes": "note-secret", "login": "root",
                                          "totp_seed": "JBSWY3DPEHPK3PXP", "require_approval": True, "machine_only": True}, headers=owner).json()["id"]
    r = client.get(f"/api/secrets/{a}/totp", headers=owner)
    assert r.status_code in (403, 409) and "code" not in r.json(), r.text
    r = client.get(f"/api/secrets/{b}", headers=owner)
    assert r.status_code in (403, 409) and "note-secret" not in r.text, r.text


# 3. agent keys: what an agent created goes with it; no takeover of people; no owner's e-mail ─────────────────────────
def test_revoking_an_agent_key_revokes_the_machine_access_it_handed_out(client, owner):
    fid = client.post("/api/folders", json={"name": "sr-agent-made"}, headers=owner).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "sr-am", "value": "v"}, headers=owner)
    k, c, h = _agent(client, owner, "sr-agent-made")
    raw = c.post("/api/tokens", json={"name": "sr-am-token", "folder_id": fid}, headers=h).json()["raw_token"]
    assert c.post("/api/enrollments", json={"folder_id": fid}, headers=h).status_code == 200
    assert client.get("/api/v1/m/secret/sr-am", headers={"Authorization": f"Bearer {raw}"}).status_code == 200
    r = client.delete(f"/api/agent-keys/{k['id']}", headers=owner)
    assert r.status_code == 200 and r.json().get("tokens_revoked") == 1 and r.json().get("enrollments_revoked") == 1, r.text
    assert client.get("/api/v1/m/secret/sr-am", headers={"Authorization": f"Bearer {raw}"}).status_code == 401


def test_an_agent_cannot_take_over_a_person_by_reinviting_them(client, owner):
    u = client.post("/api/users", json={"email": "sr-person@example.com", "name": "p"}, headers=owner).json()
    w = TestClient(main.app, base_url="https://vault.test")
    assert w.post(f"/api/invite/{u['invite_url'].rsplit('/', 1)[-1]}", json={"password": "a person's own password 1"}).status_code == 200
    k, c, h = _agent(client, owner, "sr-takeover")
    r = c.post(f"/api/users/{u['id']}/invite", headers=h)
    assert r.status_code == 403, r.text
    # the owner in person still resets a person's password
    assert client.post(f"/api/users/{u['id']}/invite", headers=owner).status_code == 200


def test_nobody_creates_a_user_with_an_owner_e_mail(client, owner, monkeypatch):
    monkeypatch.setenv("VAULT_OIDC_OWNERS", "boss@example.com")
    k, c, h = _agent(client, owner, "sr-owner-mail")
    assert c.post("/api/users", json={"email": "BOSS@example.com"}, headers=h).status_code == 422
    assert client.post("/api/users", json={"email": "boss@example.com"}, headers=owner).status_code == 422


def test_leak_check_is_the_owner_s_in_person(client, owner):
    k, c, h = _agent(client, owner, "sr-leak")
    assert c.post("/api/tokens/leak-check", json={"hashes": ["0" * 64]}, headers=h).status_code == 403


def test_an_agent_key_stops_at_a_master_password_change(client, owner):
    """The master key changes with the password; an agent key wraps the OLD one. A session from it would write folders
    under a dead key and break the next change or recovery. Change and recovery revoke agent keys, and a key that does
    not open this vault's master key is refused at sign-in."""
    k, c, h = _agent(client, owner, "sr-pwchange")
    new_pw = "sr temporary master password 2026"
    r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": new_pw}, headers=owner)
    assert r.status_code == 200, r.text
    try:
        netutil.clear_fails("testclient")
        assert TestClient(main.app, base_url="https://vault.test").post("/api/auth/agent", json={"key": k["key"]}).status_code == 401
        assert c.get("/api/folders", headers=h).status_code == 401
    finally:
        hdr = unlock(client, new_pw)
        assert client.post("/api/auth/change-password", json={"current_password": new_pw, "new_password": MASTER}, headers=hdr).status_code == 200
        owner.update(unlock(client))                     # a password change closes every session, the module's too


# 4. small ones ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_machine_audit_does_not_mix_folders_that_differ_in_case(client, owner):
    a = client.post("/api/folders", json={"name": "srcase"}, headers=owner).json()["id"]
    b = client.post("/api/folders", json={"name": "SRCASE"}, headers=owner).json()["id"]
    client.post("/api/secrets", json={"folder_id": b, "name": "other-folder-secret", "value": "v"}, headers=owner)
    raw = client.post("/api/tokens", json={"name": "sr-case", "folder_id": a, "can_write": True}, headers=owner).json()["raw_token"]
    rows = client.get("/api/v1/m/audit?limit=200", headers={"Authorization": f"Bearer {raw}"}).json()
    assert not [r for r in rows if (r.get("target") or "").startswith("SRCASE/")], rows[:3]


def test_backup_env_files_stay_inside_the_target_directory(tmp_path, monkeypatch):
    import backup
    import json as _json
    d = tmp_path / "dump.json"
    d.write_text(_json.dumps({"environment": {"vars": {"A": "1", "B\nINJECTED": "x"}, "files": {"../../escape": "x", "OK_FILE": "y"}}}))
    out = tmp_path / "keys"
    rc = backup._cli(["env", str(d), "--files-dir", str(out)])
    assert not (tmp_path / "escape.json").exists() and not list(tmp_path.parent.glob("escape.json"))
    assert (out / "ok_file.json").exists()
    assert rc in (0, 1)


def test_oidc_token_request_body_is_url_encoded():
    import oidc
    body = oidc.token_request_body("a&b=c", "https://v/cb", "id", "s&x", "ver")
    assert b"&b=c" not in body and b"a%26b%3Dc" in body and b"s%26x" in body


def test_legacy_machine_access_with_no_creator_is_the_owners(client, owner):
    """Tokens from before `created_by` existed (only the owner issued them then) carry an empty creator. They are the
    owner's: they must not block a flag (found on the production vault right after 0.41.15)."""
    fid = client.post("/api/folders", json={"name": "sr-legacy"}, headers=owner).json()["id"]
    tid = client.post("/api/tokens", json={"name": "sr-legacy-token", "folder_id": fid}, headers=owner).json()["id"]
    with db.get_session() as s:
        s.get(db.ServiceToken, tid).created_by = ""; s.commit()
    r = client.post("/api/secrets", json={"folder_id": fid, "name": "sr-legacy-flag", "value": "v", "machine_only": True}, headers=owner)
    assert r.status_code == 200, r.text
