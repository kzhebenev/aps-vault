"""0.36: VAULT_<NAME>_FILE — a setting read from a file (Swarm secrets, mounted Kubernetes Secrets, Nomad templates).
The explicit variable wins; an unreadable file is a loud startup error; path-valued *_FILE settings are left alone."""
import pytest

import settings


def test_file_variant_is_read_and_explicit_value_wins(monkeypatch, tmp_path):
    f = tmp_path / "init_token"; f.write_text("tok-from-file\n")
    monkeypatch.delenv("VAULT_INIT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_INIT_TOKEN_FILE", str(f))
    assert settings.reload().init_token == "tok-from-file"
    monkeypatch.setenv("VAULT_INIT_TOKEN", "explicit")
    assert settings.reload().init_token == "explicit", "an explicit variable beats the file"
    import base64
    k = tmp_path / "sso.key"; k.write_bytes(base64.b64encode(bytes(range(32))) + b"\n")     # 32 bytes of base64 (hex-looking strings decode as hex!)
    monkeypatch.delenv("VAULT_SSO_UNLOCK_KEY", raising=False)
    monkeypatch.setenv("VAULT_SSO_UNLOCK_KEY_FILE", str(k))
    assert settings.reload().sso_unlock_key, "a server key from a file is accepted like the variable"
    monkeypatch.delenv("VAULT_INIT_TOKEN_FILE"); monkeypatch.delenv("VAULT_SSO_UNLOCK_KEY_FILE"); monkeypatch.delenv("VAULT_INIT_TOKEN")
    settings.reload()


def test_missing_file_is_a_startup_error_and_path_settings_are_untouched(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_INIT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_INIT_TOKEN_FILE", str(tmp_path / "nope"))
    with pytest.raises(RuntimeError, match="VAULT_INIT_TOKEN_FILE"):
        settings.reload()
    monkeypatch.delenv("VAULT_INIT_TOKEN_FILE")
    monkeypatch.setenv("VAULT_KMS_YANDEX_KEY_FILE", str(tmp_path / "also-nope.json"))
    assert settings.reload().kms_yandex_key_file.endswith("also-nope.json"), "a *_FILE that IS a path setting is not opened"
    monkeypatch.delenv("VAULT_KMS_YANDEX_KEY_FILE")
    settings.reload()
