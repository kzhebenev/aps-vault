# aps-vault (Python)

Standard-library client for the APS Vault machine API. Python 3.9+, no dependencies.

```bash
pip install ./clients/python          # or: pip install aps-vault (once published)
```

```python
import os
from aps_vault import Vault, VaultError

v = Vault("https://vault.example.com", os.environ["VAULT_TOKEN"])   # or Vault.from_env()
try:
    dsn_password = v.get("db-password")
    smtp = v.get_full("smtp")            # {"name","value","login","updated_at",...}
except VaultError as e:
    if e.status == 404: ...
```

- `get(name)` / `get_full(name)` — cached for `cache_ttl` seconds (default 300). While the
  vault is unreachable a stale cached value is returned (`fail_open_cache=True`), so a vault
  restart never takes your service down; the first fetch still fails loudly.
- `put(name, value, login=..., tags=..., url=...)` — token needs `can_write`.
- `totp(name)` — current 6-digit code, never cached; token needs `can_read_totp`.
- `list()`, `health()`.
- Retries 429/5xx/network with 1 s, 2 s, 4 s back-off.

Tokens: pass via environment (`VAULT_TOKEN`) or a `0600` file (`VAULT_TOKEN_FILE`). Never
commit one, never log one. `Vault` refuses anything that does not look like a service token.

## Sealed delivery (0.17)

If the token is bound to this application's X25519 public key, values arrive encrypted and the
client decrypts them in-process (needs the optional extra: `pip install 'aps-vault[sealed]'`):

```bash
python -m aps_vault keygen          # prints VAULT_CLIENT_KEY (private, keep with the token) and client_public_key (for the token)
```
```python
v = Vault(url, token, client_private_key=os.environ["VAULT_CLIENT_KEY"])   # or just set VAULT_CLIENT_KEY
v.get("db-password")
```

Without the key the client raises `VaultError("… sealed values …")` rather than returning the
envelope; with the wrong key it says so. See `docs/SEALED.md`.
