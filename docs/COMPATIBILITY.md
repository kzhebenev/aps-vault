# HashiCorp Vault / Deckhouse Stronghold compatibility

APS Vault exposes a **KV v2 compatible facade** so that code, tooling and habits built for
HashiCorp Vault — and for its Russian fork Deckhouse Stronghold, which keeps the same API —
work unchanged. The intended use: start a project on APS Vault, move to Stronghold or
HashiCorp later (or the other way round) by changing the address and the token only.

## What works

Tested with the official Python client `hvac` (see `backend/tests/test_hashicorp_compat.py`):

| HashiCorp call | hvac | APS Vault |
|---|---|---|
| `GET /v1/sys/health`, `GET /v1/sys/seal-status` | `sys.read_health_status`, `sys.is_sealed` | ✓ (never sealed — tokens work regardless of the UI lock) |
| `GET /v1/auth/token/lookup-self` | `is_authenticated`, `lookup_token` | ✓ policies = `default`, `folder-<name>` |
| `GET /v1/sys/internal/ui/mounts/<path>` | (vault CLI uses it to detect KV v2) | ✓ |
| `GET /v1/<mount>/data/<path>` | `kv.v2.read_secret_version` | ✓ `data.data = {value, login?, notes?, totp?}`; `metadata.version` |
| `LIST /v1/<mount>/metadata/<path>` (or `?list=true`) | `kv.v2.list_secrets` | ✓ folders by `/` in secret names |
| `GET /v1/<mount>/metadata/<path>` | `kv.v2.read_secret_metadata` | ✓ |
| `POST/PUT /v1/<mount>/data/<path>` | `kv.v2.create_or_update_secret` | ✓ when the token has `can_write`; `data` must contain `value` (+ optional `login`) |
| `X-Vault-Token` header | all | ✓ (also `Authorization: Bearer`) |
| Errors | all | ✓ `{"errors": [...]}`, 403 for any auth problem, 404 for unknown paths |

```bash
export VAULT_ADDR=https://vault.example.com VAULT_TOKEN=vlt_…
vault kv get -mount=core-prod file-encryption-key
vault kv list core-prod/
vault kv put -mount=core-prod db-password value=…      # token with can_write
```

```python
import hvac
c = hvac.Client(url="https://vault.example.com", token=os.environ["VAULT_TOKEN"])
key = c.secrets.kv.v2.read_secret_version(path="file-encryption-key", mount_point="core-prod")["data"]["data"]["value"]
```

Mapping: **mount = APS Vault folder**, **path = secret name** (use `/` in names for a tree),
**data.value = the secret**, other data keys = `login` (and `notes`/`totp` on read, by grant).
The token's folder must equal the mount; anything else is `403 permission denied` — the same
error HashiCorp gives for a path outside your policy.

## What does not work (by design)

| Not implemented | Why / what to do instead |
|---|---|
| Arbitrary key/value maps in `data` | a secret has one value (+login); store JSON in `value` if you need a map |
| `DELETE`/`undelete`/`destroy`, `cas`, `max_versions` | history exists but is not addressable through the facade yet (roadmap: `?version=N`) |
| Auth methods (AppRole, Kubernetes, LDAP, userpass), token create/renew/revoke | APS Vault tokens are issued by the administrator; `lookup-self` works, `renew` is not needed (no TTL) |
| Transit, PKI, Database, SSH engines, namespaces, policies in HCL | APS Vault is a secret store, not a secrets *platform*; when you need these you have outgrown it — and migration is exactly what the facade is for |
| `sys/mounts` management | folders are created in the UI / human API |

## Migrating

**APS Vault → Stronghold / HashiCorp:** create a KV v2 mount per folder (same name), import
with `GET /api/export` → `vault kv put` per secret (`value`, `login`), issue tokens with a
policy limited to that mount, switch `VAULT_ADDR` and the token in the service. No code change
if the service used the facade or a HashiCorp client.

**Stronghold / HashiCorp → APS Vault:** one folder per mount, `vault kv get -format=json` →
`POST /api/import`; service tokens per folder; switch address and token.
