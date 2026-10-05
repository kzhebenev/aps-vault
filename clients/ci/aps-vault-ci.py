#!/usr/bin/env python3
"""APS Vault → CI environment (0.34). Standard library only; the sealed envelope needs the Python client
(`aps_vault`, importable from ../python or installed) plus its `cryptography` extra.

    aps-vault-ci.py --github  db-password:DB_PASSWORD api-key               # GitHub Actions: $GITHUB_ENV + ::add-mask::
    aps-vault-ci.py --dotenv secrets.env  db-password:DB_PASSWORD           # GitLab: dotenv artifact for later jobs
    eval "$(aps-vault-ci.py --export db-password:DB_PASSWORD)"              # any shell: export KEY='value'

Each item is  name[.field][:ENV]  — field = value (default) | login | notes | totp; ENV defaults to the name in
UPPER_SNAKE_CASE (db-password → DB_PASSWORD, db-password.login → DB_PASSWORD_LOGIN).
Settings from the environment: VAULT_URL, VAULT_TOKEN (or VAULT_TOKEN_FILE), VAULT_CLIENT_KEY (sealed tokens).
Fails closed: an unreachable vault, a refused token or a missing secret is exit 1 and nothing is written; a bad
variable name is exit 2. Values are never printed except as a masking directive (GitHub) or into the file/export
the caller asked for — the token is never printed at all.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request

FIELDS = ("value", "login", "notes", "totp")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def env_name(name: str, field: str) -> str:
    base = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "SECRET"
    if base[0].isdigit():
        base = "_" + base
    return base if field == "value" else f"{base}_{field.upper()}"


def parse_item(item: str) -> tuple[str, str, str]:
    """'db-password.login:DB_USER' → ('db-password', 'login', 'DB_USER')."""
    spec, _, var = item.partition(":")
    name, dot, field = spec.rpartition(".")
    if not dot or field not in FIELDS:
        name, field = spec, "value"
    if not name:
        raise SystemExit(f"aps-vault-ci: empty secret name in {item!r}")
    var = var or env_name(name, field)
    if not ENV_RE.match(var):
        print(f"aps-vault-ci: bad variable name {var!r} for {name!r}", file=sys.stderr)
        raise SystemExit(2)
    return name, field, var


class Reader:
    def __init__(self, url: str, token: str, client_key: str, timeout: float = 10.0):
        self.url, self.token, self.client_key, self.timeout = url.rstrip("/"), token, client_key, timeout
        self._cache: dict[str, dict] = {}

    def full(self, name: str) -> dict:
        if name in self._cache:
            return self._cache[name]
        req = urllib.request.Request(f"{self.url}/api/v1/m/secret/{urllib.parse.quote(name, safe='')}",
                                     headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                                              "User-Agent": "aps-vault-ci/0.36.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read().decode("utf-8")).get("detail", "")
            except Exception:
                pass
            if e.code == 404:
                raise SystemExit(f"aps-vault-ci: secret {name!r} is not in the folder this token is scoped to")
            if e.code in (401, 403):
                raise SystemExit(f"aps-vault-ci: the vault refused the token (HTTP {e.code}): {detail}")
            raise SystemExit(f"aps-vault-ci: HTTP {e.code} reading {name!r}: {detail}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise SystemExit(f"aps-vault-ci: vault unreachable at {self.url}: {e}")
        if isinstance(data, dict) and "sealed" in data:
            if not self.client_key:
                raise SystemExit("aps-vault-ci: this token delivers sealed values — set VAULT_CLIENT_KEY (the token's private key)")
            try:
                sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
                from aps_vault import unseal
            except ImportError:
                raise SystemExit("aps-vault-ci: sealed values need the aps_vault client with its `sealed` extra (pip install 'aps-vault[sealed]')")
            try:
                payload = unseal(data.pop("sealed"), self.client_key, data.get("name") or name)
            except Exception as e:
                raise SystemExit(f"aps-vault-ci: sealed value of {name!r} does not open with VAULT_CLIENT_KEY: {e}")
            data.update(payload)
        self._cache[name] = data
        return data


def collect(reader: Reader, items: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        name, field, var = parse_item(item)
        if var in seen:
            print(f"aps-vault-ci: variable {var!r} assigned twice", file=sys.stderr)
            raise SystemExit(2)
        seen.add(var)
        data = reader.full(name)
        value = data.get(field)
        if value is None or value == "" and field != "value":
            raise SystemExit(f"aps-vault-ci: secret {name!r} has no {field} (or the token may not read it)")
        out.append((var, str(value)))
    return out


def main(argv: list[str]) -> int:
    mode, dotenv_path, items = "", "", []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--github":
            mode = "github"
        elif a == "--export":
            mode = "export"
        elif a == "--dotenv":
            mode = "dotenv"; i += 1
            dotenv_path = argv[i] if i < len(argv) else ""
            if not dotenv_path:
                print("aps-vault-ci: --dotenv needs a file path", file=sys.stderr); return 2
        elif a in ("-h", "--help"):
            print(__doc__); return 0
        elif a.startswith("-"):
            print(f"aps-vault-ci: unknown option {a}", file=sys.stderr); return 2
        else:
            items.extend(a.split())
        i += 1
    if not mode:
        print("aps-vault-ci: choose --github, --dotenv FILE or --export", file=sys.stderr); return 2
    if not items:
        print("aps-vault-ci: no secrets given (name[.field][:ENV] …)", file=sys.stderr); return 2
    url = os.environ.get("VAULT_URL", "").strip()
    token = os.environ.get("VAULT_TOKEN", "").strip()
    if not token and os.environ.get("VAULT_TOKEN_FILE"):
        with open(os.environ["VAULT_TOKEN_FILE"], encoding="utf-8") as f:
            token = f.read().strip()
    if not url or not token:
        print("aps-vault-ci: set VAULT_URL and VAULT_TOKEN (or VAULT_TOKEN_FILE)", file=sys.stderr); return 2
    if not token.startswith("vlt_"):
        print("aps-vault-ci: VAULT_TOKEN must be a service token (vlt_…), not a master password", file=sys.stderr); return 2
    pairs = collect(Reader(url, token, os.environ.get("VAULT_CLIENT_KEY", "").strip()), items)   # all or nothing

    if mode == "github":
        env_file = os.environ.get("GITHUB_ENV")
        if not env_file:
            print("aps-vault-ci: --github needs $GITHUB_ENV (run inside GitHub Actions)", file=sys.stderr); return 2
        for var, value in pairs:
            for line in value.splitlines():            # a mask covers one line
                if line.strip():
                    print(f"::add-mask::{line}")
        sys.stdout.flush()
        with open(env_file, "a", encoding="utf-8") as f:
            for var, value in pairs:
                delim = f"APSVAULT_EOF_{os.urandom(8).hex()}"
                f.write(f"{var}<<{delim}\n{value}\n{delim}\n")
        print(f"aps-vault-ci: exported {len(pairs)} variable(s): {', '.join(v for v, _ in pairs)}")
    elif mode == "dotenv":
        for var, value in pairs:
            if "\n" in value:
                raise SystemExit(f"aps-vault-ci: {var} is multi-line; a dotenv artifact cannot carry it — use --export in the job instead")
        with open(dotenv_path, "w", encoding="utf-8") as f:
            for var, value in pairs:
                f.write(f"{var}={value}\n")
        os.chmod(dotenv_path, 0o600)
        print(f"aps-vault-ci: wrote {len(pairs)} variable(s) to {dotenv_path}: {', '.join(v for v, _ in pairs)}")
    else:
        for var, value in pairs:
            print(f"export {var}={shlex.quote(value)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
