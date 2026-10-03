"""Sealed delivery (0.17): a token bound to an X25519 public key never yields plaintext — the
machine API answers with an envelope only the private key opens. Negative cases: wrong key,
another secret's name as AAD, a tampered blob, the KV facade, a malformed public key."""
import base64
import json

import pytest

import sealed
from conftest import unlock


@pytest.fixture(scope="module")
def setup(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "sealed-scope"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "core-db", "value": "pg-pass-2026", "login": "core",
                                      "notes": "primary cluster", "totp_seed": "JBSWY3DPEHPK3PXP"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "other", "value": "unrelated"}, headers=hdr)
    sk, pk = sealed.generate_keypair()
    r = client.post("/api/tokens", json={"name": "core-node-sealed", "folder_id": fid, "can_read_notes": True, "can_read_totp": True,
                                         "can_write": True, "client_public_key": pk}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["sealed"] is True
    plain = client.post("/api/tokens", json={"name": "core-node-plain", "folder_id": fid}, headers=hdr).json()["raw_token"]
    return {"hdr": hdr, "fid": fid, "sk": base64.b64decode(sk), "pk": pk, "token": r.json()["raw_token"], "plain": plain}


def test_malformed_public_key_is_422(client, setup):
    for bad in ("AAAA", base64.b64encode(b"x" * 31).decode(), base64.b64encode(b"\x00" * 32).decode(), "not base64!!"):
        r = client.post("/api/tokens", json={"name": f"bad-{bad[:4]}", "folder_id": setup["fid"], "client_public_key": bad}, headers=setup["hdr"])
        assert r.status_code == 422, (bad, r.text)
    lst = client.get("/api/tokens", headers=setup["hdr"]).json()
    me = next(t for t in lst if t["name"] == "core-node-sealed")
    assert me["sealed"] is True and me["client_public_key"] == setup["pk"]
    assert next(t for t in lst if t["name"] == "core-node-plain")["sealed"] is False


def test_sealed_token_never_returns_plaintext(client, setup):
    h = {"Authorization": f"Bearer {setup['token']}"}
    assert client.get("/api/v1/m/health", headers=h).json()["sealed"] is True
    r = client.get("/api/v1/m/secret/core-db", headers=h)
    assert r.status_code == 200, r.text
    body = r.text
    for secret_bit in ("pg-pass-2026", "primary cluster", '"login"', '"value"', '"totp"'):
        assert secret_bit not in body, f"plaintext leaked: {secret_bit}"
    j = r.json()
    assert set(j) == {"name", "version", "current_version", "updated_at", "sealed"}
    env = j["sealed"]
    assert env["alg"] == sealed.ALG and env["v"] == 1 and len(base64.b64decode(env["epk"])) == 32 and len(base64.b64decode(env["nonce"])) == 12
    # the right private key opens it — value, login, notes and a live TOTP code as granted
    pt = sealed.unseal(env, setup["sk"], "core-db")
    assert pt["value"] == "pg-pass-2026" and pt["login"] == "core" and pt["notes"] == "primary cluster" and len(pt["totp"]) == 6
    # another key does not
    other_sk, _ = sealed.generate_keypair()
    with pytest.raises(Exception):
        sealed.unseal(env, base64.b64decode(other_sk), "core-db")
    # the envelope is bound to the secret's name (AAD)
    with pytest.raises(Exception):
        sealed.unseal(env, setup["sk"], "other")
    # a flipped ciphertext byte is detected
    ct = bytearray(base64.b64decode(env["ct"])); ct[0] ^= 1
    with pytest.raises(Exception):
        sealed.unseal({**env, "ct": base64.b64encode(bytes(ct)).decode()}, setup["sk"], "core-db")
    # every response uses a fresh ephemeral key and nonce
    env2 = client.get("/api/v1/m/secret/core-db", headers=h).json()["sealed"]
    assert env2["epk"] != env["epk"] and env2["nonce"] != env["nonce"] and env2["ct"] != env["ct"]
    assert sealed.unseal(env2, setup["sk"], "core-db")["value"] == "pg-pass-2026"
    # older versions are sealed the same way
    assert client.post("/api/v1/m/secret/core-db", json={"value": "pg-pass-2027"}, headers=h).status_code == 200
    v1 = client.get("/api/v1/m/secret/core-db?version=1", headers=h).json()
    assert "value" not in v1 and sealed.unseal(v1["sealed"], setup["sk"], "core-db")["value"] == "pg-pass-2026"
    assert sealed.unseal(client.get("/api/v1/m/secret/core-db", headers=h).json()["sealed"], setup["sk"], "core-db")["value"] == "pg-pass-2027"
    # the HashiCorp KV facade has no place for an envelope → 403, not plaintext
    kv = client.get("/v1/sealed-scope/data/core-db", headers=h)
    assert kv.status_code == 403 and "sealed" in kv.text and "pg-pass" not in kv.text
    # a plain token in the same folder still reads plaintext — sealing is per token
    p = client.get("/api/v1/m/secret/core-db", headers={"Authorization": f"Bearer {setup['plain']}"}).json()
    assert p["value"] == "pg-pass-2027" and "sealed" not in p
    # audit marks sealed reads
    acts = client.get("/api/audit", params={"limit": 50}, headers=setup["hdr"]).json()
    assert any(a["action"] == "m:secret:read" and (a.get("meta") or {}).get("sealed") for a in acts)
