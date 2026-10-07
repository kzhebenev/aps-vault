"""WebAuthn (0.13) against a software authenticator: ES256 key pair, attestation 'none',
assertions signed over authenticatorData || sha256(clientDataJSON) — exactly what a YubiKey or
Touch ID sends, minus the hardware. The PRF output is what the browser would hand us."""
import hashlib
import json
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import netutil
from conftest import MASTER, unlock

RP_ID, ORIGIN = "vault.test", "https://vault.test"


def b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class SoftKey:
    def __init__(self, prf: bool = True):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0
        self.prf_output = os.urandom(32) if prf else None

    def _cose(self) -> bytes:
        n = self.sk.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options: dict) -> dict:
        cdj = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": ORIGIN, "crossOrigin": False}).encode()
        auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big") + b"\x00" * 16 + len(self.cred_id).to_bytes(2, "big") + self.cred_id + self._cose()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att), "transports": ["usb"]},
                "clientExtensionResults": {"prf": {"enabled": bool(self.prf_output)}}}

    def assertion(self, options: dict) -> dict:
        cdj = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": ORIGIN, "crossOrigin": False}).encode()
        self.counter += 1
        auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + self.counter.to_bytes(4, "big")
        sig = self.sk.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(auth), "signature": b64u(sig), "userHandle": None},
                "clientExtensionResults": {}}


def test_webauthn_prf_unlock_and_second_factor(client, initialized):
    from fastapi.testclient import TestClient
    import main
    hdr = unlock(client)
    assert client.get("/api/auth/webauthn/status").json() == {"rp_id": RP_ID, "credentials": 0, "prf_unlock": False, "second_factor": False}
    # ── register a PRF-capable key (needs the master password, not just the session) ──
    key = SoftKey(prf=True)
    opts = client.post("/api/auth/webauthn/register/options", json={"name": "YubiKey 5"}, headers=hdr).json()
    assert opts["rp"]["id"] == RP_ID and opts["extensions"]["prf"]["eval"]["first"] and opts["challenge"]
    reg = key.register(opts)
    r = client.post("/api/auth/webauthn/register/finish", json={"name": "YubiKey 5", "credential": reg, "prf_output": b64u(key.prf_output), "transports": ["usb"], "master_password": "wrong wrong wrong"}, headers=hdr)
    assert r.status_code == 401
    netutil.clear_fails("testclient")
    # the challenge was consumed by the failed attempt? No — only on verification; a fresh options call is cheap anyway
    opts = client.post("/api/auth/webauthn/register/options", json={"name": "YubiKey 5"}, headers=hdr).json()
    reg = key.register(opts)
    r = client.post("/api/auth/webauthn/register/finish", json={"name": "YubiKey 5", "credential": reg, "prf_output": b64u(key.prf_output), "transports": ["usb"], "master_password": MASTER}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["prf"] is True
    assert client.get("/api/auth/webauthn/status").json()["prf_unlock"] is True
    lst = client.get("/api/auth/webauthn/credentials").json()
    assert lst["credentials"][0]["name"] == "YubiKey 5" and lst["credentials"][0]["prf"] is True
    # ── touch-to-unlock from a client with no session at all ──
    with TestClient(main.app, base_url=ORIGIN) as anon:
        o = anon.post("/api/auth/webauthn/options?purpose=unlock").json()
        assert any(c["id"] == b64u(key.cred_id) for c in o["allowCredentials"]) and o["extensions"]["prf"]["eval"]["first"]
        # wrong PRF output: the signature is fine, the cell does not open → 401, counted
        bad = anon.post("/api/auth/webauthn/unlock", json={"credential": key.assertion(o), "prf_output": b64u(os.urandom(32))})
        assert bad.status_code == 401
        netutil.clear_fails("testclient")
        o = anon.post("/api/auth/webauthn/options?purpose=unlock").json()
        a = key.assertion(o)
        ok = anon.post("/api/auth/webauthn/unlock", json={"credential": a, "prf_output": b64u(key.prf_output)})
        assert ok.status_code == 200, ok.text
        assert anon.cookies.get("vault_session") and anon.get("/api/folders").status_code == 200, "a real session, no password typed"
        # replay of the same assertion: the challenge is single-use
        assert anon.post("/api/auth/webauthn/unlock", json={"credential": a, "prf_output": b64u(key.prf_output)}).status_code == 401
        # a tampered signature is refused
        o = anon.post("/api/auth/webauthn/options?purpose=unlock").json(); a = key.assertion(o)
        a["response"]["signature"] = b64u(os.urandom(70))
        assert anon.post("/api/auth/webauthn/unlock", json={"credential": a, "prf_output": b64u(key.prf_output)}).status_code == 401
        netutil.clear_fails("testclient")
    # ── a key without PRF as a second factor on top of the password ──
    plain = SoftKey(prf=False)
    opts = client.post("/api/auth/webauthn/register/options", json={"name": "old token"}, headers=hdr).json()
    r = client.post("/api/auth/webauthn/register/finish", json={"name": "old token", "credential": plain.register(opts), "master_password": MASTER}, headers=hdr).json()
    assert r["prf"] is False
    assert client.post("/api/auth/webauthn/second-factor", json={"enabled": True}, headers=hdr).json()["second_factor"] is True
    with TestClient(main.app, base_url=ORIGIN) as anon:
        netutil.clear_fails("testclient")
        r = anon.post("/api/auth/unlock", json={"master_password": MASTER})
        assert r.status_code == 401 and r.headers.get("x-webauthn-required") == "1", "password alone is no longer enough"
        o = anon.post("/api/auth/webauthn/options?purpose=second_factor").json()
        assert len(o["allowCredentials"]) == 2 and "extensions" not in o
        r = anon.post("/api/auth/unlock", json={"master_password": MASTER, "webauthn": plain.assertion(o)})
        assert r.status_code == 200, r.text
        assert anon.get("/api/folders").status_code == 200
    # the administrator's existing session is untouched by the switch; audit has the whole story
    netutil.clear_fails("testclient")
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 80}).json()]
    assert {"auth:webauthn_registered", "auth:webauthn_fail", "auth:webauthn_second_factor"} <= set(actions)
    # cleanup for the rest of the suite: second factor off, keys removed
    # 0.37: turning the factor off needs the password — a session alone is refused
    assert client.post("/api/auth/webauthn/second-factor", json={"enabled": False}, headers=hdr).status_code == 401
    netutil.clear_fails("testclient")
    assert client.post("/api/auth/webauthn/second-factor", json={"enabled": False, "password": MASTER}, headers=hdr).status_code == 200
    for c in client.get("/api/auth/webauthn/credentials").json()["credentials"]:
        assert client.delete(f"/api/auth/webauthn/credentials/{c['id']}", headers=hdr).status_code == 200
    assert client.get("/api/auth/webauthn/status").json()["credentials"] == 0
