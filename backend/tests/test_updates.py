"""Settings → Updates (0.38): release notes, the channel, the owner's request and the agent's side of the job."""
import io
import json
import os
import urllib.error

import pytest
from fastapi.testclient import TestClient

import netutil
import settings
from conftest import MASTER, unlock
from test_security_review_2026_10_05 import ORIGIN, _login, _user

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
AGENT = "agent-token-for-tests-0123456789abcdef0123456789"


def _bump(v: str) -> str:
    a, b, c = (int(x) for x in v.split("."))
    return f"{a}.{b}.{c + 1}"


def _channel_bytes(extra: list[dict]) -> bytes:
    """The real GitHub API answer (tests/fixtures/github-releases.json, captured 05.10.2026) plus releases on top."""
    real = json.load(open(os.path.join(HERE, "fixtures", "github-releases.json"), encoding="utf-8"))
    return json.dumps(extra + real).encode()


class _Resp(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


@pytest.fixture
def channel(monkeypatch):
    """Serve a channel answer through the real fetch path (urlopen_noredirect is the only thing replaced)."""
    import main
    import updates
    newer = _bump(main.VERSION)
    calls = []
    state = {"body": _channel_bytes([
        {"tag_name": f"v{newer}", "draft": False, "prerelease": False, "published_at": "2026-10-06T10:00:00Z",
         "html_url": f"https://github.com/kzhebenev/aps-vault/releases/tag/v{newer}", "body": "**Fresh release.**\n\n- one\n- two"},
        {"tag_name": "v99.0.0-rc1", "draft": False, "prerelease": True, "published_at": "2026-10-07T10:00:00Z", "body": "rc"},
        {"tag_name": "v98.0.0", "draft": True, "prerelease": False, "published_at": "2026-10-07T10:00:00Z", "body": "draft"},
    ]), "error": None}

    def fake_open(req, timeout=10):
        calls.append(req.full_url)
        if state["error"]:
            raise state["error"]
        return _Resp(state["body"])
    monkeypatch.setattr(netutil, "urlopen_noredirect", fake_open)
    monkeypatch.setattr(netutil, "address_is_public", lambda host: host == "api.github.com")
    monkeypatch.setattr(settings.SETTINGS, "update_channel", "https://api.github.com/repos/kzhebenev/aps-vault/releases?per_page=30")
    monkeypatch.setattr(settings.SETTINGS, "update_agent_token", AGENT)
    import db
    with db.get_session() as s:                           # each test starts from an unchecked channel and no jobs
        s.query(db.UpdateState).delete(); s.query(db.UpdateJob).delete(); s.query(db.UpdateAgent).delete(); s.commit()
    return {"newer": newer, "calls": calls, "state": state, "updates": updates}


def _agent(client, agent_id="host-1", token=AGENT, current=None):
    import main
    return client.get("/api/agent/update", params={"agent_id": agent_id, "mode": "images", "agent_version": main.VERSION,
                                                    "current": current or main.VERSION, "verify": "cosign", "host": "h"},
                      headers={"Authorization": f"Bearer {token}"})


def test_release_notes_json_is_generated_from_the_changelog():
    """The notes shipped in the image are exactly CHANGELOG.md (run ops/release-notes.py json after editing it)."""
    import changelog
    shipped = json.load(open(os.path.join(ROOT, "backend", "release_notes.json"), encoding="utf-8"))
    assert shipped == changelog.parse(open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()), \
        "backend/release_notes.json is stale: python3 ops/release-notes.py json > backend/release_notes.json"
    import main
    assert shipped[0]["version"] == main.VERSION and shipped[0]["notes"], "the installed version has its notes"
    assert changelog.section(open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read(), "9.9.9") is None


def test_status_is_the_owners_and_merges_shipped_notes_with_the_channel(client, initialized, channel):
    import main
    hdr = unlock(client)
    assert TestClient(main.app, base_url=ORIGIN).get("/api/update/status").status_code == 401
    st = client.get("/api/update/status", headers=hdr).json()
    assert st["installed"] == main.VERSION and st["latest"] == channel["newer"] and st["available"] == [channel["newer"]]
    hist = {h["version"]: h for h in st["history"]}
    assert hist[channel["newer"]]["state"] == "newer" and "Fresh release" in hist[channel["newer"]]["notes"]
    assert hist[main.VERSION]["state"] == "installed" and len(hist[main.VERSION]["notes"]) > 100, "installed notes come from the image, not 'Release X'"
    assert hist["0.36.0"]["state"] == "older" and "SLSA" in hist["0.36.0"]["notes"] and hist["0.36.0"]["url"].endswith("/v0.36.0")
    assert "99.0.0" not in hist and "98.0.0" not in hist, "pre-releases and drafts are not offered"
    assert st["channel"] == {**st["channel"], "enabled": True, "host": "api.github.com", "error": ""}
    assert len(channel["calls"]) == 1
    client.get("/api/update/status", headers=hdr)
    assert len(channel["calls"]) == 1, "a page view uses the cached look at the channel"
    # a person who is not the owner
    uid = _user(client, hdr, "upd-reader@example.com", client.post("/api/folders", json={"name": "upd-f"}, headers=hdr).json()["id"])
    c, r = _login("upd-reader@example.com")
    h = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert c.get("/api/update/status").status_code == 403
    assert c.post("/api/update/apply", json={"version": channel["newer"], "master_password": MASTER}, headers=h).status_code == 403


def test_channel_rules_https_public_no_redirect_no_junk(client, initialized, channel, monkeypatch):
    upd = channel["updates"]
    hdr = unlock(client)
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", False)   # conftest allows private targets
    for url in ("http://api.github.com/x", "https://10.1.2.3/releases", "file:///etc/passwd"):
        monkeypatch.setattr(settings.SETTINGS, "update_channel", url)
        st = client.post("/api/update/check", headers=hdr).json()
        assert "https" in st["channel"]["error"] and st["available"] == [], url
    monkeypatch.setattr(settings.SETTINGS, "update_channel", "https://api.github.com/repos/kzhebenev/aps-vault/releases")
    n = len(channel["calls"])
    channel["state"]["error"] = urllib.error.HTTPError("https://api.github.com/x", 302, "redirect refused", {}, None)
    st = client.post("/api/update/check", headers=hdr).json()
    assert "did not answer" in st["channel"]["error"] and len(channel["calls"]) == n + 1
    channel["state"]["error"] = None
    channel["state"]["body"] = b"<html>not json</html>"
    assert "not release JSON" in client.post("/api/update/check", headers=hdr).json()["channel"]["error"]
    channel["state"]["body"] = b"[" + b" " * (upd.MAX_CHANNEL_BYTES + 10) + b"]"
    assert "too large" in client.post("/api/update/check", headers=hdr).json()["channel"]["error"]
    # off: nothing leaves the vault, the page still shows the shipped history
    monkeypatch.setattr(settings.SETTINGS, "update_channel", "")
    n = len(channel["calls"])
    st = client.get("/api/update/status", headers=hdr).json()
    assert st["channel"]["enabled"] is False and len(channel["calls"]) == n and len(st["history"]) > 40
    assert client.post("/api/update/check", headers=hdr).status_code == 409
    assert settings._update_channel("off") == "" and settings._update_channel("").startswith("https://api.github.com/")


def test_the_owner_requests_an_update_and_one_agent_carries_it_out(client, initialized, channel):
    import main
    hdr = unlock(client)
    newer = channel["newer"]
    # no agent yet
    r = client.post("/api/update/apply", json={"version": newer, "master_password": MASTER}, headers=hdr)
    assert r.status_code == 409 and "agent" in r.text
    assert _agent(client).json() == {"job": None}
    # the vault's own checks
    netutil.clear_fails("testclient")
    r = client.post("/api/update/apply", json={"version": newer, "master_password": "wrong wrong wrong"}, headers=hdr)
    assert r.status_code == 401
    netutil.clear_fails("testclient")
    for v, why in ((main.VERSION, "not newer"), ("0.1.0", "not newer"), ("77.0.0", "not a published release"), ("latest", "X.Y.Z")):
        r = client.post("/api/update/apply", json={"version": v, "master_password": MASTER}, headers=hdr)
        assert r.status_code == 422 and why in r.text, (v, r.text)
    assert client.post("/api/update/apply", json={"version": newer, "master_password": MASTER},
                       headers={"X-CSRF-Token": "forged"}).status_code == 403, "CSRF"
    # the request
    r = client.post("/api/update/apply", json={"version": f"v{newer}", "master_password": MASTER}, headers=hdr)
    assert r.status_code == 200, r.text
    job = r.json()
    assert job["state"] == "requested" and job["target_version"] == newer and job["from_version"] == main.VERSION
    assert client.post("/api/update/apply", json={"version": newer, "master_password": MASTER}, headers=hdr).status_code == 409
    # the agent side: wrong / missing token
    assert _agent(client, token="nope").status_code == 401
    netutil.clear_fails("testclient")
    assert client.get("/api/agent/update", params={"agent_id": "x"}).status_code == 401
    netutil.clear_fails("testclient")
    # exactly one agent gets it
    got = _agent(client, "host-1").json()["job"]
    assert got and got["id"] == job["id"] and got["state"] == "running" and got["agent_id"] == "host-1"
    assert _agent(client, "host-2").json() == {"job": None}
    assert client.post(f"/api/update/jobs/{job['id']}/cancel", headers=hdr).status_code == 409, "a running job is not cancelled"
    rep = lambda aid, body: client.post(f"/api/agent/update/{job['id']}", params={"agent_id": aid}, json=body, headers={"Authorization": f"Bearer {AGENT}"})
    assert rep("host-2", {"state": "done", "step": "x"}).status_code == 409, "another agent cannot finish it"
    assert rep("host-1", {"state": "running", "step": "verify signatures", "log": "cosign: ok"}).status_code == 200
    r = rep("host-1", {"state": "done", "step": "healthy on the new version", "log": "health: ok"})
    assert r.status_code == 200 and r.json()["state"] == "done" and "cosign: ok" in r.json()["log"]
    assert rep("host-1", {"state": "failed"}).status_code == 409, "a finished job stays finished"
    st = client.get("/api/update/status", headers=hdr).json()
    assert st["job"]["state"] == "done" and st["agent"]["connected"] is True and st["agent"]["agent_id"] in ("host-1", "host-2")
    acts = [a["action"] for a in client.get("/api/audit", params={"limit": 60}, headers=hdr).json()]
    for a in ("update:requested", "update:picked", "update:done", "update:apply_fail", "update:agent_denied"):
        assert a in acts, a


def test_a_requested_job_can_be_cancelled_and_the_agent_api_is_off_without_a_token(client, initialized, channel, monkeypatch):
    hdr = unlock(client)
    _agent(client)
    job = client.post("/api/update/apply", json={"version": channel["newer"], "master_password": MASTER}, headers=hdr).json()
    r = client.post(f"/api/update/jobs/{job['id']}/cancel", headers=hdr)
    assert r.status_code == 200 and r.json()["state"] == "cancelled"
    assert _agent(client).json() == {"job": None}, "a cancelled job is never handed out"
    monkeypatch.setattr(settings.SETTINGS, "update_agent_token", "")
    netutil.clear_fails("testclient")
    r = _agent(client, token=AGENT)
    assert r.status_code == 401 and "not enabled" in r.text
    netutil.clear_fails("testclient")


def _job_for(client, hdr, channel, agent="host-1"):
    _agent(client, agent)
    job = client.post("/api/update/apply", json={"version": channel["newer"], "master_password": MASTER}, headers=hdr).json()
    got = _agent(client, agent).json()["job"]
    assert got and got["id"] == job["id"] and got["state"] == "running"
    return job


def test_a_job_its_agent_dropped_is_settled_by_the_next_poll(client, initialized, channel):
    """0.41.2 (found live on 06.10): the agent polls only between jobs, so a poll while its own job is still running
    means the job was lost (agent restarted, stand restored from a mid-update copy). Before, the job stayed `running`
    forever and blocked the update button."""
    import main
    hdr = unlock(client)
    job = _job_for(client, hdr, channel)
    # another agent's poll does not touch it
    assert _agent(client, "host-2").json() == {"job": None}
    assert client.get("/api/update/status", headers=hdr).json()["job"]["state"] == "running"
    # the same agent comes back still on the old version → failed, and a new request is possible again
    assert _agent(client, "host-1", current=main.VERSION).json() == {"job": None}
    st = client.get("/api/update/status", headers=hdr).json()["job"]
    assert st["id"] == job["id"] and st["state"] == "failed" and "abandoned" in st["step"], st
    assert f"reports {main.VERSION}" in st["log"]
    acts = [a for a in client.get("/api/audit", params={"limit": 20}, headers=hdr).json() if a["action"] == "update:failed"]
    assert acts and acts[0]["actor"] == "agent:host-1"
    # the agent came back already on the target (it updated but its report was lost) → done
    job2 = _job_for(client, hdr, channel)
    assert job2["id"] != job["id"]
    _agent(client, "host-1", current=channel["newer"])
    st = client.get("/api/update/status", headers=hdr).json()["job"]
    assert st["id"] == job2["id"] and st["state"] == "done" and "confirmed" in st["step"], st


def test_a_running_job_can_be_cancelled_only_after_an_hour_of_silence(client, initialized, channel):
    """0.41.2: an agent that died for good never polls again — the owner may cancel its running job, but only once the
    agent has been silent (no poll, no report) for SILENT_AFTER; before that the agent is presumed busy."""
    from datetime import timedelta
    import db
    import updates
    hdr = unlock(client)
    job = _job_for(client, hdr, channel)
    r = client.post(f"/api/update/jobs/{job['id']}/cancel", headers=hdr)
    assert r.status_code == 409 and "last sign of life" in r.text, r.text
    assert client.get("/api/update/status", headers=hdr).json()["job"]["cancellable"] is False

    def age(minutes):
        with db.get_session() as s:
            j = s.get(db.UpdateJob, job["id"]); a = s.get(db.UpdateAgent, "host-1")
            j.picked_at = updates.now() - timedelta(minutes=minutes); a.last_seen = updates.now() - timedelta(minutes=minutes)
            s.commit()

    age(59)
    assert client.post(f"/api/update/jobs/{job['id']}/cancel", headers=hdr).status_code == 409, "59 min: still presumed busy"
    age(61)
    # a report is a sign of life: the agent is mid-job (it does not poll then), so the clock starts again
    rep = client.post(f"/api/agent/update/{job['id']}", params={"agent_id": "host-1"}, json={"state": "running", "step": "pulling"},
                      headers={"Authorization": f"Bearer {AGENT}"})
    assert rep.status_code == 200
    with db.get_session() as s:
        s.get(db.UpdateJob, job["id"]).picked_at = updates.now() - timedelta(minutes=61); s.commit()
    assert client.get("/api/update/status", headers=hdr).json()["job"]["cancellable"] is False, "the report reset the silence"
    age(61)
    assert client.get("/api/update/status", headers=hdr).json()["job"]["cancellable"] is True
    r = client.post(f"/api/update/jobs/{job['id']}/cancel", headers=hdr)
    assert r.status_code == 200 and r.json()["state"] == "cancelled" and "silent" in r.json()["step"], r.text
    assert "check what the installation actually runs" in r.json()["log"]
    late = client.post(f"/api/agent/update/{job['id']}", params={"agent_id": "host-1"}, json={"state": "done"},
                       headers={"Authorization": f"Bearer {AGENT}"})
    assert late.status_code == 409, "a cancelled job stays cancelled"
    assert any(a["action"] == "update:cancelled" for a in client.get("/api/audit", params={"limit": 20}, headers=hdr).json())
