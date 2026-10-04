"""Backward compatibility: a database written by 0.17.1 (tests/fixtures/v0171.db, aes suite)
must open with the current code — master password, recovery code, token, sealed token, share
and note links, SSO cell, approver password — regardless of what VAULT_CIPHER asks for (the
stored suite wins). Runs in its own process because the suite and the engine are process state:

    python tests/compat_fixture_check.py        (run_tests.sh does this after pytest)
"""
import base64
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, "fixtures", "v0171.json")))
TMP = tempfile.mkdtemp(prefix="aps-vault-compat-")
shutil.copy(os.path.join(HERE, "fixtures", "v0171.db"), os.path.join(TMP, "vault.db"))
os.environ.update({
    "VAULT_DATA_DIR": TMP, "VAULT_DB_PATH": os.path.join(TMP, "vault.db"), "VAULT_INIT_TOKEN": "x",
    "VAULT_ALLOWED_ORIGINS": "https://vault.test", "VAULT_PUBLIC_URL": "https://vault.test",
    "VAULT_SSO_UNLOCK_KEY": FX["sso_key"], "VAULT_WEBHOOK_ALLOW_PRIVATE": "1",
})
os.environ.pop("VAULT_DATABASE_URL", None); os.environ.pop("TEST_DATABASE_URL", None)
sys.path.insert(0, os.path.dirname(HERE))

from fastapi.testclient import TestClient  # noqa: E402

import db  # noqa: E402

# freeze the clock at the fixture's creation time: its share/note links have a 7-day TTL and the
# fixture must keep opening for years
import datetime as _dt  # noqa: E402
_FROZEN = _dt.datetime.strptime(FX["created_at"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=_dt.timezone.utc) + _dt.timedelta(minutes=1)
db.utcnow = lambda: _FROZEN

import crypto  # noqa: E402
import main  # noqa: E402
import sealed  # noqa: E402
import suite  # noqa: E402
from argon2 import PasswordHasher  # noqa: E402

failures = []


def check(cond, what):
    print(("  ✓ " if cond else "  ✗ ") + what)
    if not cond:
        failures.append(what)


with TestClient(main.app, base_url="https://vault.test") as c:
    h = c.get("/api/health").json()
    check(h["initialized"] is True and h["cipher"] == "aes", f"fixture is an aes vault (env asked for {os.environ.get('VAULT_CIPHER', 'aes')}); health reports {h['cipher']}")
    r = c.post("/api/auth/unlock", json={"master_password": FX["master"]})
    check(r.status_code == 200, "master password of 0.17.1 unlocks")
    hdr = {"X-CSRF-Token": r.json().get("csrf_token", "")}
    secs = c.get("/api/secrets").json()
    s = next((x for x in secs if x["name"] == "db-password"), None)
    full = c.get(f"/api/secrets/{s['id']}").json() if s else {}
    check(full.get("value") == "value-v2" and full.get("login") == "app" and full.get("notes") == "some notes" and len(full.get("totp") or "") == 6,
          "secret fields decrypt (value v2, login, notes, live TOTP)")
    hist = c.get(f"/api/secrets/{s['id']}/history").json() if s else {}
    check(any(x.get("value") == "value-v1" for x in hist.get("history", [])), "history version 1 decrypts")
    mo = next((x for x in secs if x["name"] == "machine-only"), None)
    check(mo is not None and c.get(f"/api/secrets/{mo['id']}").json().get("value_hidden") is True, "machine-only secret stays hidden")
    tok = c.get("/api/v1/m/secret/db-password", headers={"Authorization": f"Bearer {FX['token']}"}).json()
    check(tok.get("value") == "value-v2" and tok.get("login") == "app" and tok.get("notes") == "some notes", "service token of 0.17.1 reads plaintext")
    old = c.get("/api/v1/m/secret/db-password?version=1", headers={"Authorization": f"Bearer {FX['token']}"}).json()
    check(old.get("value") == "value-v1", "token reads version 1")
    st = c.get("/api/v1/m/secret/db-password", headers={"Authorization": f"Bearer {FX['sealed_token']}"}).json()
    check("value" not in st and sealed.unseal(st.get("sealed", {}), base64.b64decode(FX["sealed_sk"]), "db-password").get("value") == "value-v2",
          "sealed token of 0.17.1 still seals to the stored client key")
    share_tok = (FX["share_url"] or "").rsplit("/", 1)[-1]
    sh = c.get(f"/api/share/{share_tok}")
    check(sh.status_code == 200 and sh.json().get("value") == "value-v2", "share link of 0.17.1 opens")
    note_tok = (FX["note_url"] or "").rsplit("/", 1)[-1]
    nt = c.get(f"/api/share/{note_tok}")
    check(nt.status_code == 200 and nt.json().get("kind") == "note" and nt.json().get("value") == "note text", "note link of 0.17.1 opens")
    main.STATE.lock()
    check(main.sso_unlock_source() == "cell", "SSO cell of 0.17.1 opens with the server key")
    cfg = crypto.load_config()
    ok_appr = False
    try:
        PasswordHasher().verify(cfg.approver_hash, FX["approver_password"]); ok_appr = True
    except Exception:
        pass
    check(ok_appr, "approver password hash verifies")
    check(crypto.verify_recovery_code(FX["recovery"], cfg) == crypto.verify_master_password(FX["master"], cfg), "recovery code of 0.17.1 unwraps the same master key")
    check(suite.active() == "aes", "suite stays aes for this database")

shutil.rmtree(TMP, ignore_errors=True)
if failures:
    print(f"COMPAT FAIL: {len(failures)}"); sys.exit(1)
print("COMPAT OK: a 0.17.1 database opens unchanged")
