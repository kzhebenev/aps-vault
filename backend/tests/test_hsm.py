"""PKCS#11 master-key cell (0.15) against SoftHSM2 — the software token that behaves like a
hardware one through the same interface. Skipped with "НЕ НАСТРОЕНО" when no module is
configured (run_tests.sh installs SoftHSM2 and initialises a token)."""
import os

import pytest

import crypto
import netutil
import settings
from conftest import MASTER, unlock

PIN = os.environ.get("TEST_PKCS11_PIN", "1234")
pytestmark = pytest.mark.skipif(not os.environ.get("VAULT_PKCS11_MODULE") or not os.path.exists(os.environ.get("VAULT_PKCS11_MODULE", "")),
                                reason="НЕ НАСТРОЕНО: VAULT_PKCS11_MODULE не задан — SoftHSM2 не установлен в контуре тестов")


def test_hsm_cell_enable_unlock_rewrap(client, initialized, monkeypatch):
    from fastapi.testclient import TestClient
    import main
    import hsm
    hdr = unlock(client)
    st = client.get("/api/auth/hsm/status").json()
    assert st["configured"] and st["enabled"] is False and st["token"]["label"] == settings.SETTINGS.pkcs11_token_label, st
    # enabling needs the master password and the token PIN
    assert client.post("/api/auth/hsm/enable", json={"master_password": "nope nope nope nope", "pin": PIN}, headers=hdr).status_code == 401
    netutil.clear_fails("testclient")
    r = client.post("/api/auth/hsm/enable", json={"master_password": MASTER, "pin": "0000"}, headers=hdr)
    assert r.status_code == 400 and "PIN" in r.text, "a wrong PIN is refused by the token itself"
    netutil.clear_fails("testclient")
    r = client.post("/api/auth/hsm/enable", json={"master_password": MASTER, "pin": PIN}, headers=hdr)
    assert r.status_code == 200, r.text
    cfg = crypto.load_config()
    mk = crypto.verify_master_password(MASTER, cfg)
    assert cfg.hsm_master_enc and cfg.hsm_master_enc != mk and len(cfg.hsm_master_enc) == 48 and len(cfg.hsm_master_iv) == 16 and cfg.hsm_key_label == settings.SETTINGS.pkcs11_key_label   # CBC-PAD of 32 bytes = 48
    assert client.get("/api/auth/hsm/status").json()["enabled"] is True
    # the cell opens only through the token with the PIN; the module decrypts, we never see the AES key
    assert hsm.unwrap(cfg.hsm_master_enc, cfg.hsm_master_iv, PIN) == mk
    with pytest.raises(hsm.HsmError):
        hsm.unwrap(cfg.hsm_master_enc, cfg.hsm_master_iv, "9999")
    # PIN unlock from a client without a session
    with TestClient(main.app, base_url="https://vault.test") as anon:
        bad = anon.post("/api/auth/hsm/unlock", json={"pin": "9999"})
        assert bad.status_code == 401 and "PIN" in bad.text
        netutil.clear_fails("testclient")
        assert anon.post("/api/auth/hsm/unlock", json={}).status_code == 400, "no PIN and no auto mode"
        ok = anon.post("/api/auth/hsm/unlock", json={"pin": PIN})
        assert ok.status_code == 200, ok.text
        assert anon.cookies.get("vault_session") and anon.get("/api/folders").status_code == 200, "a real session without the master password"
    # auto mode: the server may use the token itself → SSO source becomes "hsm", unlock needs no PIN
    monkeypatch.setenv("VAULT_PKCS11_PIN", PIN); settings.reload()
    try:
        assert client.get("/api/auth/hsm/status").json()["auto"] is True
        main.STATE.lock()
        assert main.sso_unlock_source() == "hsm"
        with TestClient(main.app, base_url="https://vault.test") as anon:
            # 0.41.15: the server's PIN serves SSO and re-wrap — an empty request no longer opens an owner session
            assert anon.post("/api/auth/hsm/unlock", json={}).status_code == 403
            netutil.clear_fails("testclient")
            assert anon.post("/api/auth/hsm/unlock", json={"pin": PIN}).status_code == 200
        # password change re-wraps the cell through the token (auto mode has the PIN)
        new_pw = "hsm cell follows the password change"
        r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": new_pw}, headers=hdr)
        assert r.status_code == 200
        cfg2 = crypto.load_config()
        assert cfg2.hsm_master_enc and hsm.unwrap(cfg2.hsm_master_enc, cfg2.hsm_master_iv, PIN) == crypto.verify_master_password(new_pw, cfg2)
        # restore the suite's password via recovery — still re-wrapped
        r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER})
        assert r2.status_code == 200
        cfg3 = crypto.load_config()
        assert hsm.unwrap(cfg3.hsm_master_enc, cfg3.hsm_master_iv, PIN) == crypto.verify_master_password(MASTER, cfg3)
    finally:
        monkeypatch.delenv("VAULT_PKCS11_PIN"); settings.reload()
    hdr = unlock(client)
    # without the PIN on the server a password change cannot re-wrap: the cell is dropped and audited
    r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": "temporary password for drop test"}, headers=hdr)
    assert r.status_code == 200
    assert not crypto.load_config().hsm_master_enc
    r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER}); assert r2.status_code == 200
    hdr = unlock(client)
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 80}).json()]
    assert {"auth:hsm_enabled", "auth:hsm_fail", "auth:hsm_cell_dropped"} <= set(actions)
    assert client.post("/api/auth/hsm/disable", headers=hdr).json()["enabled"] is False
