"""Test harness: a real FastAPI app on a temporary data directory.

Environment is set *before* `main` is imported because settings and the DB engine are read
at import time. The TestClient's peer address is the literal string "testclient", which is
not an IP and therefore never a trusted proxy — so a spoofed X-Forwarded-For must be ignored.
"""
import os
import sys
import tempfile

import pytest

TMP = tempfile.mkdtemp(prefix="aps-vault-test-")
os.environ.update({
    "VAULT_DATA_DIR": TMP,
    "VAULT_DB_PATH": os.path.join(TMP, "vault.db"),
    "VAULT_INIT_TOKEN": "test-init-token",
    "VAULT_ALLOWED_ORIGINS": "https://vault.test",
    "VAULT_PUBLIC_URL": "https://vault.test",
    "VAULT_TRUSTED_PROXIES": "10.0.0.0/8",
    "VAULT_WEBHOOK_ALLOW_PRIVATE": "1",
    "VAULT_FAIL_LIMIT_PER_IP": "5",
    "VAULT_FAIL_LIMIT_GLOBAL": "50",
})
os.environ.pop("VAULT_DEV", None)
os.environ.pop("OIDC_ISSUER", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import netutil  # noqa: E402

MASTER = "correct horse battery staple 2026"


@pytest.fixture(scope="session")
def client():
    with TestClient(main.app, base_url="https://vault.test") as c:
        yield c


@pytest.fixture(scope="session")
def initialized(client):
    """Vault initialised once per test session; returns the recovery code."""
    r = client.post("/api/init", json={"master_password": MASTER, "init_token": "test-init-token"})
    assert r.status_code == 200, r.text
    return r.json()["recovery_code"]


def unlock(client, password=MASTER, totp=None):
    netutil.clear_fails("testclient")
    body = {"master_password": password}
    if totp:
        body["totp_code"] = totp
    r = client.post("/api/auth/unlock", json=body)
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


@pytest.fixture
def session(client, initialized):
    """Unlocked session; yields the CSRF header dict for write calls."""
    return unlock(client)
