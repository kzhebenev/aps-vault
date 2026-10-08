"""Cloud KMS master-key cell (0.16) against LocalStack's AWS KMS — the same wire protocol
(SigV4, TrentService.Encrypt/Decrypt, EncryptionContext) as the real service. Skipped with
"НЕ НАСТРОЕНО" when run_tests.sh could not start the emulator (VAULT_KMS_KEY_ID unset)."""
import os

import pytest

import crypto
import kms
import netutil
import settings
from conftest import MASTER, unlock

PIN = "4321"
pytestmark = pytest.mark.skipif(settings.SETTINGS.kms_provider != "aws" or not settings.SETTINGS.kms_key_id or not settings.SETTINGS.kms_endpoint,
                                reason="НЕ НАСТРОЕНО: VAULT_KMS_PROVIDER/KEY_ID/ENDPOINT не заданы — эмулятор KMS не поднят в контуре тестов")


def test_kms_provider_roundtrip_and_context_binding():
    """The provider itself. 0.37: the PIN is applied locally (Argon2id) and the cloud sees a constant context — the
    PIN never reaches the KMS request (AWS logs the encryption context in clear in CloudTrail). Someone with the cloud
    credentials who replays the constant context gets only the Argon2-sealed blob, not the master key."""
    mk = os.urandom(32)
    ct = kms.encrypt(mk, PIN)
    assert ct != mk and kms.decrypt(ct, PIN) == mk
    for wrong in (PIN + "0",):
        with pytest.raises(kms.KmsError, match="InvalidCiphertext"):
            kms.decrypt(ct, wrong)
    with pytest.raises(kms.KmsError):
        kms.decrypt(ct, None)                         # the no-PIN context does not open a PIN cell
    with pytest.raises(kms.KmsError, match="InvalidCiphertext"):
        kms.decrypt(ct[:-4] + b"\x00\x00\x00\x00", PIN)
    # an attacker with kms:Decrypt and CloudTrail: the logged context is constant and yields a PIN-sealed blob only
    blob = kms._decrypt_ctx(ct, kms._PIN_V2_CONTEXT)
    assert blob.startswith(kms._PIN_V2_MAGIC) and mk not in blob, "the KMS alone does not release the master key"
    assert PIN not in kms._PIN_V2_CONTEXT and kms._PIN_V2_CONTEXT == "aps-vault:pin:v2"
    # a pre-0.37 cell (PIN-derived context) still opens and is reported as legacy for re-wrapping
    legacy = kms._encrypt_ctx(mk, kms.aad_for_pin(PIN))
    assert kms.decrypt_with_info(legacy, PIN) == (mk, True)
    assert kms.decrypt_with_info(ct, PIN) == (mk, False)
    assert kms.aad_for_pin(None) == "aps-vault:no-pin" and kms.info()["credentials"] is True
    # auto mode (no PIN) is unchanged
    ct0 = kms.encrypt(mk, None)
    assert kms.decrypt(ct0, None) == mk


def test_kms_cell_pin_bound_unlock(client, initialized):
    from fastapi.testclient import TestClient
    import main
    hdr = unlock(client)
    st = client.get("/api/auth/kms/status").json()
    assert st["configured"] and st["enabled"] is False and st["provider"] == "aws" and st["kms"]["key_id"] == settings.SETTINGS.kms_key_id, st
    # enabling needs the master password
    assert client.post("/api/auth/kms/enable", json={"master_password": "nope nope nope nope", "pin": PIN}, headers=hdr).status_code == 401
    netutil.clear_fails("testclient")
    assert client.post("/api/auth/kms/enable", json={"master_password": MASTER, "pin": "12"}, headers=hdr).status_code == 400, "short PIN refused"
    r = client.post("/api/auth/kms/enable", json={"master_password": MASTER, "pin": PIN}, headers=hdr)
    assert r.status_code == 200 and r.json()["pin_bound"] is True, r.text
    cfg = crypto.load_config()
    mk = crypto.verify_master_password(MASTER, cfg)
    assert cfg.kms_master_enc and mk not in cfg.kms_master_enc and cfg.kms_pin_bound and cfg.kms_provider == "aws" and cfg.kms_key_id == settings.SETTINGS.kms_key_id
    assert kms.decrypt(cfg.kms_master_enc, PIN) == mk
    st = client.get("/api/auth/kms/status").json()
    assert st["enabled"] is True and st["pin_bound"] is True
    # a PIN-bound cell is not an SSO source: the server cannot open it alone
    main.STATE.lock()
    assert main.sso_unlock_source() != "kms"
    with TestClient(main.app, base_url="https://vault.test") as anon:
        bad = anon.post("/api/auth/kms/unlock", json={"pin": PIN + "0"})
        assert bad.status_code == 401, bad.text
        assert anon.post("/api/auth/kms/unlock", json={}).status_code == 400, "PIN required"
        netutil.clear_fails("testclient")
        ok = anon.post("/api/auth/kms/unlock", json={"pin": PIN})
        assert ok.status_code == 200, ok.text
        assert anon.cookies.get("vault_session") and anon.get("/api/folders").status_code == 200, "a real session without the master password"
    hdr = unlock(client)
    # password change: the server has no PIN → the cell cannot follow and is dropped (audited)
    r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": "temporary password for kms drop"}, headers=hdr)
    assert r.status_code == 200
    assert not crypto.load_config().kms_master_enc and client.get("/api/auth/kms/status").json()["enabled"] is False
    r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER}); assert r2.status_code == 200
    hdr = unlock(client)      # recovery revoked every session
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 80}).json()]
    assert {"auth:kms_enabled", "auth:kms_fail", "auth:kms_cell_dropped"} <= set(actions)


def test_kms_cell_auto_mode_sso_source_and_rewrap(client, initialized, monkeypatch):
    from fastapi.testclient import TestClient
    import main
    hdr = unlock(client)
    r = client.post("/api/auth/kms/enable", json={"master_password": MASTER}, headers=hdr)
    assert r.status_code == 200 and r.json()["pin_bound"] is False, r.text
    cfg = crypto.load_config()
    assert kms.decrypt(cfg.kms_master_enc, None) == crypto.verify_master_password(MASTER, cfg)
    # without a PIN the cloud identity alone opens the cell → it is an SSO source, but never a direct login
    main.STATE.lock()
    assert main.sso_unlock_source() == "kms"
    assert client.get("/api/auth/oidc/status").json()["sso_unlock"] == "kms"
    with TestClient(main.app, base_url="https://vault.test") as anon:
        assert anon.post("/api/auth/kms/unlock", json={"pin": "whatever"}).status_code == 403
    # password change re-wraps through the KMS (no PIN needed)
    new_pw = "kms cell follows the password change"
    r = client.post("/api/auth/change-password", json={"current_password": MASTER, "new_password": new_pw}, headers=hdr)
    assert r.status_code == 200
    cfg2 = crypto.load_config()
    assert cfg2.kms_master_enc and cfg2.kms_master_enc != cfg.kms_master_enc
    assert kms.decrypt(cfg2.kms_master_enc, None) == crypto.verify_master_password(new_pw, cfg2)
    r2 = client.post("/api/auth/recover", json={"recovery_code": r.json()["new_recovery_code"], "new_master_password": MASTER}); assert r2.status_code == 200
    cfg3 = crypto.load_config()
    assert kms.decrypt(cfg3.kms_master_enc, None) == crypto.verify_master_password(MASTER, cfg3)
    hdr = unlock(client)
    # the KMS unreachable: enable answers 502 (not 500, not a silent success), status stays honest
    monkeypatch.setattr(settings.SETTINGS, "kms_endpoint", "http://127.0.0.1:9/")
    r = client.post("/api/auth/kms/enable", json={"master_password": MASTER}, headers=hdr)
    assert r.status_code == 502 and "unreachable" in r.text, r.text
    monkeypatch.undo()
    assert client.post("/api/auth/kms/disable", headers=hdr).json()["enabled"] is False
    assert not crypto.load_config().kms_master_enc
