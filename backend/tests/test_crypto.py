"""Primitives: what the whole product rests on."""
import os
import secrets

import pytest
from cryptography.exceptions import InvalidTag

import crypto


def test_encrypt_decrypt_roundtrip_and_unique_nonces():
    key = secrets.token_bytes(32)
    ct1, n1 = crypto.encrypt(key, b"hello")
    ct2, n2 = crypto.encrypt(key, b"hello")
    assert n1 != n2 and ct1 != ct2, "same plaintext must never produce the same ciphertext"
    assert len(n1) == 12 and len(ct1) == len(b"hello") + 16
    assert crypto.decrypt(key, ct1, n1) == b"hello"


def test_tampered_ciphertext_is_rejected():
    key = secrets.token_bytes(32)
    ct, n = crypto.encrypt(key, b"payload")
    bad = bytearray(ct); bad[0] ^= 1
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, bytes(bad), n)
    with pytest.raises(InvalidTag):
        crypto.decrypt(secrets.token_bytes(32), ct, n)


def test_key_length_enforced():
    with pytest.raises(ValueError):
        crypto.encrypt(b"short", b"x")


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """A private database so the vault_config row of the shared test vault is untouched."""
    import db
    monkeypatch.setenv("VAULT_DATABASE_URL", f"sqlite:///{tmp_path}/own.db")
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    db.reset_engine()
    yield tmp_path
    monkeypatch.delenv("VAULT_DATABASE_URL")
    db.reset_engine()


def test_master_password_verifier(isolated_db):
    import db
    tmp_path = isolated_db
    assert crypto.config_exists() is False
    cfg, recovery = crypto.init_vault("a very long master password")
    # since 0.6 the verifier lives in the database (shared by replicas), not in data/config.json
    with db.get_session() as s:
        assert s.get(db.VaultConfigRow, 1) is not None
    assert not (tmp_path / "config.json").exists()
    assert len(recovery) == 24 and recovery == recovery.upper()
    assert crypto.verify_master_password("a very long master password", cfg) is not None
    assert crypto.verify_master_password("a very long master passworD", cfg) is None
    # recovery code unwraps the same master key
    assert crypto.verify_recovery_code(recovery, cfg) == crypto.verify_master_password("a very long master password", cfg)
    assert crypto.verify_recovery_code("0" * 24, cfg) is None
    assert crypto.load_config().salt == cfg.salt


def test_legacy_config_json_is_imported_once(isolated_db):
    """An install upgraded from 0.5 has data/config.json and no vault_config row: the file is
    imported on first read, then the database is authoritative (file edits are ignored)."""
    import json
    import db
    tmp_path = isolated_db
    salt = secrets.token_bytes(32); key = crypto.derive_key("legacy master password!", salt)
    ve, vn = crypto.encrypt(key, crypto.VERIFIER_PLAINTEXT)
    (tmp_path / "config.json").write_text(json.dumps({
        "salt": salt.hex(), "verifier_enc": ve.hex(), "verifier_nonce": vn.hex(),
        "init_at_utc": "2026-01-01T00:00:00Z", "recovery_code_hash": "x"}))
    assert crypto.config_exists() is True
    cfg = crypto.load_config()
    assert crypto.verify_master_password("legacy master password!", cfg) is not None
    with db.get_session() as s:
        assert s.get(db.VaultConfigRow, 1).salt == salt
    # the file is no longer consulted
    (tmp_path / "config.json").write_text("{}")
    assert crypto.load_config().salt == salt


def test_service_token_format_and_entropy():
    t1, t2 = crypto.gen_service_token(), crypto.gen_service_token()
    assert t1.startswith("vlt_") and t1 != t2
    assert len(t1.split("_")[2]) == 64
