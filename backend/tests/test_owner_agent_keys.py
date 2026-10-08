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
