"""Token watch (0.26): a token used from a new network, from two places at once, too often, or to
enumerate secrets raises an alert (audit + webhook); `freeze` makes the token answer 403 until a
manager unfreezes it; a canary token trips on any use and answers the attacker with the generic
401; leak-check matches hashes of live tokens; normal use raises nothing."""
import hashlib
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

import db
import settings
from conftest import unlock


class _Peer:
    """ASGI wrapper that sets the TCP peer the vault sees — the only thing a test cannot do through HTTP.
    With a peer inside VAULT_TRUSTED_PROXIES (10.0.0.0/8 in conftest) X-Forwarded-For is honoured."""

    def __init__(self, app, ip: str):
        self.app, self.ip = app, ip

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope); scope["client"] = (self.ip, 40000)
        await self.app(scope, receive, send)


def _machine(ip: str):
    """A machine-API client whose calls appear to come from `ip` (via the trusted proxy 10.0.0.1)."""
    import main
    c = TestClient(_Peer(main.app, "10.0.0.1"), base_url="https://vault.test")
    c.headers["X-Forwarded-For"] = ip
    return c


def _get(c, tok, name="db-password"):
    return c.get(f"/api/v1/m/secret/{name}", headers={"Authorization": f"Bearer {tok}"})


class _Sink(BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(n)
        _Sink.got.append(json.loads(body)); self.send_response(200); self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "watch-apps"}, headers=hdr).json()["id"]
    for i in range(30):
        client.post("/api/secrets", json={"folder_id": fid, "name": f"s{i:02d}", "value": f"v{i}"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "db-password", "value": "pw", "login": "app"}, headers=hdr)
    srv = HTTPServer(("127.0.0.1", 0), _Sink); threading.Thread(target=srv.serve_forever, daemon=True).start()
    client.post("/api/webhooks", json={"name": "watch-sink", "url": f"http://127.0.0.1:{srv.server_port}/w", "event_filter": "token:*"}, headers=hdr)
    return {"hdr": hdr, "fid": fid}


def _token(client, hdr, fid, name, **kw):
    r = client.post("/api/tokens", json={"name": name, "folder_id": fid, **kw}, headers=hdr)
    assert r.status_code == 200, r.text
    return r.json()["raw_token"], r.json()["id"]


def _alerts(client, hdr, tid=None):
    rows = client.get("/api/tokens/alerts", headers=hdr).json()
    return [a for a in rows if tid is None or a["token_id"] == tid]


def _learn(tok, ip="198.51.100.10", n=None):
    c = _machine(ip)
    for _ in range(n or settings.SETTINGS.watch_learn_uses):
        assert _get(c, tok).status_code == 200


def test_normal_use_from_the_usual_network_raises_nothing(client, world):
    hdr, fid = world["hdr"], world["fid"]
    tok, tid = _token(client, hdr, fid, "quiet")
    _learn(tok)
    c = _machine("198.51.100.77")                           # same /24
    for _ in range(5):
        assert _get(c, tok).status_code == 200
    assert _alerts(client, hdr, tid) == []
    prof = client.get(f"/api/tokens/{tid}/profile", headers=hdr).json()
    assert prof["uses"] == settings.SETTINGS.watch_learn_uses + 5 and list(prof["networks"]) == ["198.51.100.0/24"] and prof["secrets"]["db-password"] >= 25


def test_new_network_alerts_but_lets_the_call_through_then_trust_silences_it(client, world):
    hdr, fid = world["hdr"], world["fid"]
    _Sink.got.clear()
    tok, tid = _token(client, hdr, fid, "roaming")
    # during learning a second network is not an anomaly (an installer, a CI runner, a laptop)
    assert _get(_machine("203.0.113.5"), tok).status_code == 200
    assert _alerts(client, hdr, tid) == []
    _learn(tok)
    r = _get(_machine("192.0.2.9"), tok)
    assert r.status_code == 200, "alert policy: the call still succeeds"
    al = _alerts(client, hdr, tid)
    assert len(al) == 1 and al[0]["kind"] == "new_network" and al[0]["network"] == "192.0.2.0/24" and al[0]["action"] == "alert" and al[0]["token_frozen"] is False
    assert al[0]["detail"]["known_networks"] == ["198.51.100.0/24", "203.0.113.0/24"]
    # the webhook saw it, the audit log too
    assert any(e["event"] == "token:anomaly" and e["data"]["kind"] == "new_network" and e["data"]["name"] == "roaming" for e in _Sink.got)
    acts = client.get("/api/audit", params={"limit": 20}, headers=hdr).json()
    assert any(a["action"] == "token:anomaly" and a["actor"] == f"token:{tid}" for a in acts)
    # repeats within the hour fold into the same alert
    for _ in range(3):
        _get(_machine("192.0.2.10"), tok)
    al = _alerts(client, hdr, tid)
    assert len(al) == 1 and al[0]["count"] == 4
    # the token list shows the open count; the manager trusts the network → alert acknowledged, no new ones
    assert next(t for t in client.get("/api/tokens", headers=hdr).json() if t["id"] == tid)["alerts_open"] == 1
    r = client.post(f"/api/tokens/{tid}/trust-network", json={"network": "192.0.2.0/24"}, headers=hdr)
    assert r.status_code == 200
    assert _alerts(client, hdr, tid) == []
    assert _get(_machine("192.0.2.11"), tok).status_code == 200 and _alerts(client, hdr, tid) == []
    assert client.get(f"/api/tokens/{tid}/profile", headers=hdr).json()["networks"]["192.0.2.0/24"]["trusted"] is True


def test_freeze_policy_blocks_until_unfrozen(client, world):
    hdr, fid = world["hdr"], world["fid"]
    tok, tid = _token(client, hdr, fid, "strict", on_anomaly="freeze")
    _learn(tok)
    r = _get(_machine("192.0.2.50"), tok)
    assert r.status_code == 403 and "frozen" in r.json()["detail"], r.text
    assert _get(_machine("198.51.100.10"), tok).status_code == 403, "frozen for everyone, including the usual network"
    t = next(t for t in client.get("/api/tokens", headers=hdr).json() if t["id"] == tid)
    assert t["frozen"] is True and t["frozen_reason"] == "new_network" and t["on_anomaly"] == "freeze"
    al = _alerts(client, hdr, tid)
    assert al[0]["action"] == "freeze" and al[0]["token_frozen"] is True
    assert client.post(f"/api/tokens/{tid}/unfreeze", headers=hdr).status_code == 200
    assert _get(_machine("198.51.100.10"), tok).status_code == 200
    # a manager may freeze by hand too
    assert client.post(f"/api/tokens/{tid}/freeze", headers=hdr).status_code == 200
    assert _get(_machine("198.51.100.10"), tok).status_code == 403
    client.post(f"/api/tokens/{tid}/unfreeze", headers=hdr)
    # the policy can be changed afterwards
    assert client.patch(f"/api/tokens/{tid}", json={"on_anomaly": "alert"}, headers=hdr).status_code == 200
    assert client.patch(f"/api/tokens/{tid}", json={"on_anomaly": "explode"}, headers=hdr).status_code == 422


def test_parallel_networks(client, world):
    hdr, fid = world["hdr"], world["fid"]
    tok, tid = _token(client, hdr, fid, "two-places")
    _learn(tok)                                      # 198.51.100.0/24
    # the token also lives at 203.0.113.0/24 — make it known, slowly (outside the parallel window)
    with db.get_session() as s:
        p = s.get(db.TokenProfile, tid); p.last_seen = p.last_seen - timedelta(minutes=10); s.commit()
    assert _get(_machine("203.0.113.8"), tok).status_code == 200
    al = _alerts(client, hdr, tid)
    assert [a["kind"] for a in al] == ["new_network"]
    # while the new network is pending, the usual network is NOT "a second place" — the new_network alert covers it
    assert _get(_machine("198.51.100.10"), tok).status_code == 200
    assert [a["kind"] for a in _alerts(client, hdr, tid)] == ["new_network"]
    # the manager says it is our second site → now both are known, and seconds apart means two places at once
    assert client.post(f"/api/tokens/{tid}/trust-network", json={"network": "203.0.113.8"}, headers=hdr).json()["network"] == "203.0.113.0/24"
    assert _alerts(client, hdr, tid) == []
    assert _get(_machine("203.0.113.8"), tok).status_code == 200
    assert _get(_machine("198.51.100.10"), tok).status_code == 200
    al = _alerts(client, hdr, tid)
    assert [a["kind"] for a in al] == ["parallel_networks"] and al[0]["detail"]["other_network"] == "203.0.113.0/24", al


def test_rate_spike_and_enumeration(client, world, monkeypatch):
    hdr, fid = world["hdr"], world["fid"]
    monkeypatch.setattr(settings.SETTINGS, "watch_rate_min", 40)
    tok, tid = _token(client, hdr, fid, "busy")
    _learn(tok)
    with db.get_session() as s:                      # a day of quiet history: ~0.14 calls per 10 min
        p = s.get(db.TokenProfile, tid); p.first_seen = p.first_seen - timedelta(days=1); p.window_start = None; s.commit()
    c = _machine("198.51.100.10")
    for _ in range(45):
        assert _get(c, tok).status_code == 200
    al = _alerts(client, hdr, tid)
    assert [a["kind"] for a in al] == ["rate_spike"] and al[0]["detail"]["calls_10min"] >= 40
    # enumeration: a token that always read one secret suddenly reads many it never touched
    tok2, tid2 = _token(client, hdr, fid, "curious")
    _learn(tok2)
    c = _machine("198.51.100.10")
    for i in range(settings.SETTINGS.watch_enum_min + 1):
        assert _get(c, tok2, f"s{i:02d}").status_code == 200
    al = _alerts(client, hdr, tid2)
    assert "enumeration" in [a["kind"] for a in al] and next(a for a in al if a["kind"] == "enumeration")["detail"]["new_secrets_10min"] >= settings.SETTINGS.watch_enum_min


def test_canary_trips_on_first_use_freezes_and_tells_the_attacker_nothing(client, world):
    hdr, fid = world["hdr"], world["fid"]
    _Sink.got.clear()
    tok, tid = _token(client, hdr, fid, "canary-ci-logs", canary=True)
    t = next(t for t in client.get("/api/tokens", headers=hdr).json() if t["id"] == tid)
    assert t["canary"] is True and t["frozen"] is False
    r = _get(_machine("203.0.113.66"), tok)
    assert r.status_code == 401 and r.json()["detail"] == "invalid service token", "the generic answer — no hint that the canary tripped"
    al = _alerts(client, hdr, tid)
    assert len(al) == 1 and al[0]["kind"] == "canary" and al[0]["action"] == "freeze" and al[0]["token_frozen"] is True and al[0]["ip"] == "203.0.113.66"
    assert any(e["event"] == "token:anomaly" and e["data"]["kind"] == "canary" for e in _Sink.got), _Sink.got
    assert _get(_machine("203.0.113.66"), tok).status_code == 401
    # unfreezing a canary does not make it a working token: the next use trips it again
    client.post(f"/api/tokens/{tid}/unfreeze", headers=hdr)
    assert _get(_machine("203.0.113.67"), tok).status_code == 401
    # 0.37: a canary is checked FIRST, so every use is counted — also the one while it was frozen (3 uses, 3 counts)
    assert _alerts(client, hdr, tid)[0]["count"] == 3, "every use of a canary reaches the watch"
    # revoking the token closes the incident: its alerts leave the open list
    assert client.delete(f"/api/tokens/{tid}", headers=hdr).status_code == 200
    assert _alerts(client, hdr, tid) == []
    assert any(a["token_id"] == tid and a["acknowledged"] for a in client.get("/api/tokens/alerts", params={"include_acknowledged": 1}, headers=hdr).json())



def test_leak_check_matches_live_tokens_by_hash_only(client, world):
    hdr, fid = world["hdr"], world["fid"]
    tok, tid = _token(client, hdr, fid, "in-a-repo")
    import state
    h_live = state.hash_token(tok)
    h_random = hashlib.sha256(b"vlt_nope").hexdigest()
    r = client.post("/api/tokens/leak-check", json={"hashes": [h_live, h_random]}, headers=hdr)
    assert r.status_code == 200
    found = r.json()["found"]
    assert len(found) == 1 and found[0]["token_id"] == tid and found[0]["name"] == "in-a-repo" and found[0]["revoked"] is False
    assert r.json()["checked"] == 2
    # revoke straight from the report
    assert client.post("/api/tokens/leak-check", json={"hashes": [h_live], "revoke": True}, headers=hdr).json()["revoked"] == 1
    assert _get(_machine("198.51.100.10"), tok).status_code == 401
    acts = client.get("/api/audit", params={"limit": 10}, headers=hdr).json()
    assert any(a["action"] == "token:leak_check" for a in acts) and any(a["action"] == "token:revoke" and (a["meta"] or {}).get("reason") == "leak-check" for a in acts)
    # garbage in → 422
    assert client.post("/api/tokens/leak-check", json={"hashes": ["zz"]}, headers=hdr).status_code == 422


def test_manager_scope_and_metrics(client, world):
    hdr, fid = world["hdr"], world["fid"]
    other = client.post("/api/folders", json={"name": "watch-other"}, headers=hdr).json()["id"]
    tok_o, tid_o = _token(client, hdr, other, "other-token", canary=True)
    _get(_machine("203.0.113.1"), tok_o)                 # an alert in the other folder
    import main
    u = client.post("/api/users", json={"email": "watch-mgr@example.com", "grants": [{"folder_id": fid, "role": "manager"}]}, headers=hdr).json()
    with TestClient(main.app, base_url="https://vault.test") as anon:
        assert anon.post(f"/api/invite/{u['invite_url'].rsplit('/', 1)[-1]}", json={"password": "watch manager pass!"}).status_code == 200
    import netutil
    mc = TestClient(main.app, base_url="https://vault.test"); netutil.clear_fails("testclient")
    lr = mc.post("/api/auth/login", json={"email": "watch-mgr@example.com", "password": "watch manager pass!"}); mh = {"X-CSRF-Token": lr.json()["csrf_token"]}
    mine = mc.get("/api/tokens/alerts").json()
    assert mine and all(a["folder_id"] == fid for a in mine), "a manager sees alerts of their folders only"
    assert mc.post(f"/api/tokens/{tid_o}/unfreeze", headers=mh).status_code == 403
    assert mc.post("/api/tokens/leak-check", json={"hashes": ["0" * 64]}, headers=mh).status_code == 403, "leak-check is the owner's"
    # metrics expose the open alerts
    m = client.get("/metrics", headers={"Authorization": "Bearer test-metrics"})
    if m.status_code == 200:
        assert "aps_vault_token_alerts_open" in m.text
