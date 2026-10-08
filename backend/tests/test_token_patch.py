"""0.41.10: narrowing an existing token. PATCH /api/tokens/{id} changed only on_anomaly and silently dropped every other
field with 200 — an operator (an AI session, found 08.10.2026) "narrowed" a production token to the tenant's network,
got 200, and the token still worked from anywhere; only a negative check from outside showed it. Now the networks and
hours of a token can be changed, and an unknown field is a 422, never a quiet success."""
from conftest import unlock


def _mk(client, hdr, name):
    fid = client.post("/api/folders", json={"name": f"patch-{name}"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": f"s-{name}", "value": "v"}, headers=hdr)
    t = client.post("/api/tokens", json={"name": name, "folder_id": fid}, headers=hdr).json()
    return t["id"], t["raw_token"], f"s-{name}"


def test_networks_and_hours_of_a_token_can_be_narrowed_and_widened(client, initialized):
    hdr = unlock(client)
    tid, raw, sec = _mk(client, hdr, "narrow-me")
    m = lambda: client.get(f"/api/v1/m/secret/{sec}", headers={"Authorization": f"Bearer {raw}"}).status_code
    assert m() == 200
    r = client.patch(f"/api/tokens/{tid}", json={"allowed_cidrs": "10.99.0.0/16"}, headers=hdr)
    assert r.status_code == 200 and r.json()["allowed_cidrs"] == "10.99.0.0/16", r.text
    assert m() == 403                                                  # the test client is not in 10.99/16
    listed = [t for t in client.get("/api/tokens", headers=hdr).json() if t["id"] == tid][0]
    assert listed["allowed_cidrs"] == "10.99.0.0/16"
    r = client.patch(f"/api/tokens/{tid}", json={"allowed_cidrs": ""}, headers=hdr)      # widen back
    assert r.status_code == 200 and m() == 200
    assert client.patch(f"/api/tokens/{tid}", json={"allowed_hours": "Mon-Fri 08:00-20:00"}, headers=hdr).status_code == 200
    audit = client.get("/api/audit?limit=50", headers=hdr).json()
    assert any(a["action"] == "token:update" and (a.get("meta") or {}).get("allowed_cidrs") == "10.99.0.0/16" for a in audit)


def test_a_bad_value_or_an_unknown_field_is_refused_not_ignored(client, initialized):
    hdr = unlock(client)
    tid, raw, sec = _mk(client, hdr, "strict-patch")
    assert client.patch(f"/api/tokens/{tid}", json={"allowed_cidrs": "not-a-network"}, headers=hdr).status_code == 422
    assert client.patch(f"/api/tokens/{tid}", json={"allowed_hours": "whenever"}, headers=hdr).status_code == 422
    assert client.patch(f"/api/tokens/{tid}", json={"can_write": True}, headers=hdr).status_code == 422     # not changeable here
    assert client.patch(f"/api/tokens/{tid}", json={"alowed_cidrs": "10.0.0.0/8"}, headers=hdr).status_code == 422  # a typo
    assert client.get(f"/api/v1/m/secret/{sec}", headers={"Authorization": f"Bearer {raw}"}).status_code == 200


def test_machine_api_takes_tags_as_a_list_too(client, initialized):
    """0.41.10: tags were a comma-separated string only; a list gave 422 (battlecard tripped on it). A list is joined."""
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "patch-tags"}, headers=hdr).json()["id"]
    raw = client.post("/api/tokens", json={"name": "tags-writer", "folder_id": fid, "can_write": True}, headers=hdr).json()["raw_token"]
    H = {"Authorization": f"Bearer {raw}"}
    assert client.post("/api/v1/m/secret/tagged", json={"value": "v", "tags": ["delivery", " valodrive "]}, headers=H).status_code == 200
    assert client.post("/api/v1/m/secret/tagged2", json={"value": "v", "tags": "a,b"}, headers=H).status_code == 200
    got = {s["name"]: s["tags"] for s in client.get("/api/v1/m/secrets", headers=H).json()}
    assert got["tagged"] == "delivery,valodrive" and got["tagged2"] == "a,b"
    assert client.post("/api/v1/m/secret/tagged3", json={"value": "v", "tags": {"x": 1}}, headers=H).status_code == 422
