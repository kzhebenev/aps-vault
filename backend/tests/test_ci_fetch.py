"""CI step (0.34): clients/ci/aps-vault-ci.py against a live server — GitHub mode writes $GITHUB_ENV and masks,
dotenv mode writes a file, export mode is eval-able; a missing secret, a refused token or a bad variable name
writes nothing; a sealed token opens with VAULT_CLIENT_KEY; the token is never printed."""
import os
import pathlib
import subprocess
import sys

import pytest

from conftest import unlock
from test_python_client import live_url  # noqa: F401  (fixture: uvicorn on a free port)

SCRIPT = str(pathlib.Path(__file__).resolve().parents[2] / "clients" / "ci" / "aps-vault-ci.py")


@pytest.fixture(scope="module")
def ci_token(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "ci-folder"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "db-password", "value": "pg-ci-1", "login": "app"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "tls.key", "value": "-----BEGIN KEY-----\nline2\n-----END KEY-----"}, headers=hdr)
    plain = client.post("/api/tokens", json={"name": "ci-reader", "folder_id": fid, "can_read_totp": True}, headers=hdr).json()["raw_token"]
    import sealed
    sk, pk = sealed.generate_keypair()
    sealed_tok = client.post("/api/tokens", json={"name": "ci-sealed", "folder_id": fid, "client_public_key": pk}, headers=hdr).json()["raw_token"]
    return {"plain": plain, "sealed": sealed_tok, "sk": sk}


def run(args, env, live_url):
    e = {"PATH": os.environ.get("PATH", ""), "VAULT_URL": live_url, "PYTHONDONTWRITEBYTECODE": "1"}
    e.update(env)
    return subprocess.run([sys.executable, SCRIPT, *args], env=e, capture_output=True, text=True, timeout=30)


def test_github_mode_exports_masks_and_never_prints_the_token(live_url, ci_token, tmp_path):
    gh = tmp_path / "github_env"; gh.write_text("")
    r = run(["--github", "db-password:DB_PASSWORD db-password.login:DB_USER", "tls.key"], {"VAULT_TOKEN": ci_token["plain"], "GITHUB_ENV": str(gh)}, live_url)
    assert r.returncode == 0, r.stderr
    assert "::add-mask::pg-ci-1" in r.stdout and "::add-mask::app" in r.stdout and "::add-mask::line2" in r.stdout
    assert ci_token["plain"] not in r.stdout + r.stderr
    content = gh.read_text()
    assert "DB_PASSWORD<<APSVAULT_EOF_" in content and "\npg-ci-1\n" in content and "DB_USER<<" in content and "\napp\n" in content
    assert "TLS_KEY<<" in content and "-----BEGIN KEY-----\nline2\n-----END KEY-----\n" in content, "multi-line value through a heredoc"
    assert "exported 3 variable(s): DB_PASSWORD, DB_USER, TLS_KEY" in r.stdout
    # the value appears in stdout only as a mask directive
    assert r.stdout.count("pg-ci-1") == 1


def test_dotenv_and_export_modes(live_url, ci_token, tmp_path):
    f = tmp_path / "s.env"
    r = run(["--dotenv", str(f), "db-password", "db-password.login:DB_USER"], {"VAULT_TOKEN": ci_token["plain"]}, live_url)
    assert r.returncode == 0, r.stderr
    assert f.read_text() == "DB_PASSWORD=pg-ci-1\nDB_USER=app\n" and oct(f.stat().st_mode & 0o777) == "0o600"
    assert "pg-ci-1" not in r.stdout
    r = run(["--dotenv", str(f), "tls.key"], {"VAULT_TOKEN": ci_token["plain"]}, live_url)
    assert r.returncode == 1 and "multi-line" in r.stderr
    r = run(["--export", "db-password:DB_PASSWORD", "tls.key:TLS"], {"VAULT_TOKEN": ci_token["plain"]}, live_url)
    assert r.returncode == 0, r.stderr
    shell = subprocess.run(["bash", "-c", f'eval "$1"; printf "%s|%s" "$DB_PASSWORD" "$TLS"', "_", r.stdout], capture_output=True, text=True)
    assert shell.stdout == "pg-ci-1|-----BEGIN KEY-----\nline2\n-----END KEY-----", shell.stdout


def test_failures_are_closed_and_named(live_url, ci_token, tmp_path):
    gh = tmp_path / "github_env"; gh.write_text("")
    env = {"VAULT_TOKEN": ci_token["plain"], "GITHUB_ENV": str(gh)}
    r = run(["--github", "db-password", "ghost"], env, live_url)
    assert r.returncode == 1 and "'ghost' is not in the folder" in r.stderr and gh.read_text() == "", "a missing secret writes nothing, not even the ones before it"
    r = run(["--github", "db-password:9BAD"], env, live_url)
    assert r.returncode == 2 and "bad variable name" in r.stderr
    r = run(["--github", "db-password:X", "tls.key:X"], env, live_url)
    assert r.returncode == 2 and "assigned twice" in r.stderr
    r = run(["--github", "db-password"], {"VAULT_TOKEN": "vlt_wrong_token_000", "GITHUB_ENV": str(gh)}, live_url)
    assert r.returncode == 1 and "refused the token" in r.stderr and gh.read_text() == ""
    r = run(["--github", "db-password"], {"VAULT_TOKEN": "correct horse battery staple", "GITHUB_ENV": str(gh)}, live_url)
    assert r.returncode == 2 and "master password" in r.stderr
    r = run(["--github", "db-password.totp"], env, live_url)
    assert r.returncode == 1 and "has no totp" in r.stderr
    r = run(["--github", "db-password"], {"VAULT_TOKEN": ci_token["plain"], "VAULT_URL": "http://127.0.0.1:9", "GITHUB_ENV": str(gh)}, live_url)
    assert r.returncode == 1 and "unreachable" in r.stderr
    r = run(["db-password"], env, live_url)
    assert r.returncode == 2 and "choose --github" in r.stderr


def test_sealed_token_opens_with_the_client_key(live_url, ci_token, tmp_path):
    gh = tmp_path / "github_env"; gh.write_text("")
    r = run(["--github", "db-password"], {"VAULT_TOKEN": ci_token["sealed"], "GITHUB_ENV": str(gh)}, live_url)
    assert r.returncode == 1 and "VAULT_CLIENT_KEY" in r.stderr and gh.read_text() == ""
    r = run(["--github", "db-password"], {"VAULT_TOKEN": ci_token["sealed"], "GITHUB_ENV": str(gh), "VAULT_CLIENT_KEY": ci_token["sk"]}, live_url)
    assert r.returncode == 0, r.stderr
    assert "\npg-ci-1\n" in gh.read_text() and "::add-mask::pg-ci-1" in r.stdout
    import sealed
    other, _ = sealed.generate_keypair()
    gh.write_text("")
    r = run(["--github", "db-password"], {"VAULT_TOKEN": ci_token["sealed"], "GITHUB_ENV": str(gh), "VAULT_CLIENT_KEY": other}, live_url)
    assert r.returncode == 1 and "does not open" in r.stderr and gh.read_text() == ""
