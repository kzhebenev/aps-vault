#!/usr/bin/env python3
"""Minimal service start-up with APS Vault: secrets are fetched once, the service refuses to
start without them, nothing secret is printed."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clients", "python"))
from aps_vault import Vault, VaultError  # noqa: E402


def main() -> int:
    try:
        vault = Vault.from_env()                  # VAULT_URL + VAULT_TOKEN / VAULT_TOKEN_FILE
    except ValueError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    try:
        db = vault.get_full("db-password")        # {"value", "login", ...}
        smtp_password = vault.get("smtp-password")
    except VaultError as e:
        # 404 → the secret is not in this token's folder; 401 → token revoked/expired
        print(f"vault refused: HTTP {e.status} — {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"vault unreachable: {e}", file=sys.stderr)
        return 1

    dsn = f"postgresql://{db.get('login', 'app')}:***@db.internal/app"   # never print the password
    print(f"connecting as {db.get('login', 'app')} → {dsn}")
    print(f"smtp password length: {len(smtp_password)}")

    # optional: a TOTP second factor for an upstream API (token needs can_read_totp)
    try:
        code = vault.totp("upstream-api")
        if code:
            print(f"upstream 2FA code ready ({len(code)} digits)")
    except VaultError as e:
        if e.status != 404:
            raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
