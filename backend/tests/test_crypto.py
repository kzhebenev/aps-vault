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


def test_master_password_verifier(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    cfg, recovery = crypto.init_vault("a very long master password")
    assert len(recovery) == 24 and recovery == recovery.upper()
    assert crypto.verify_master_password("a very long master password", cfg) is not None
    assert crypto.verify_master_password("a very long master passworD", cfg) is None
    # recovery code unwraps the same master key
    assert crypto.verify_recovery_code(recovery, cfg) == crypto.verify_master_password("a very long master password", cfg)
    assert crypto.verify_recovery_code("0" * 24, cfg) is None
    assert oct(os.stat(tmp_path / "config.json").st_mode)[-3:] == "600"


def test_service_token_format_and_entropy():
    t1, t2 = crypto.gen_service_token(), crypto.gen_service_token()
    assert t1.startswith("vlt_") and t1 != t2
    assert len(t1.split("_")[2]) == 64
