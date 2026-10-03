# Architecture

## Components

```
 browser ──HTTPS──▶ reverse proxy (TLS) ──▶ frontend (nginx, static) ──/api/──▶ backend (FastAPI)
 service ──HTTPS──▶ reverse proxy ─────────────────────────────────────/api/v1/m/──▶ backend
                                                                                      │
                                                                               data/vault.db (SQLite)
                                                                               data/config.json
```

| Part | Tech | Role |
|---|---|---|
| `backend/` | Python 3.11, FastAPI, SQLAlchemy, `cryptography`, `argon2-cffi`, `pyotp` | all logic; one uvicorn worker |
| `frontend/` | `index.html` + `app.js` (no framework, no build step), nginx | UI; nginx also proxies `/api/` to the backend |
| `data/` | `vault.db`, `config.json` | the only state; back this up |
| `mcp/` | Python, FastMCP | MCP server for AI agents (stdio) |
| `ops/` | bash | CLI, backup, restore |

The backend keeps three things in process memory only: the unwrapped master key, the session
table and the failed-attempt counters. A restart therefore means the vault comes up **locked**
and someone has to enter the master password again. The machine API does not depend on that
state (see below).

## Key hierarchy (envelope encryption)

```
master password ──Argon2id(m=64 MiB, t=3, p=4, salt)──▶ master key (32 B, RAM only)
                                                              │ AES-256-GCM
                                                              ▼
                                           folder key (random 32 B per folder, stored wrapped)
                                                              │ AES-256-GCM, fresh 96-bit nonce per field
                                                              ▼
                                       secret value · login · notes · TOTP seed · history entries
```

- `config.json` holds the Argon2 salt and a *verifier*: the constant `APS-VAULT-OK-v1`
  encrypted under the master key. Unlock = derive candidate key → decrypt verifier → compare.
  No password hash is stored.
- Folder keys exist so that (a) a token can be scoped to one folder and (b) a password change
  or recovery re-wraps a handful of folder keys instead of re-encrypting every value.
- Field-level nonces are random (`secrets.token_bytes(12)`); GCM tag is 128 bits. Plaintext
  metadata that stays searchable: secret name, tags, URL, timestamps, counters.

### Service tokens

A token is `vlt_<base32-12>_<hex-64>` (≈ 320 bits of entropy). On creation the backend stores
`SHA-256(token)` for lookup and the folder key encrypted under `Argon2id(token, salt)`
(lighter parameters: m=8 MiB, t=2 — the token itself is random, so the KDF only needs to be a
one-way mapping). On each request: hash → row → derive → unwrap folder key → decrypt value.
The master key is not involved, which is why the machine API works while the UI is locked,
and why revoking a token (flag in DB) is the only way to stop it — there is no master-side
kill switch beyond revocation.

Permissions per token: `can_read_value` (always), `can_read_notes`, `can_read_totp`,
`can_write` (upsert within the folder; old value goes to history). All default to off except
value.

### Share links

`/api/share` wraps the folder key under `Argon2id(link token, sha256(token)[:16])` and stores
only the token hash, TTL and `max_uses`. `/api/share/<token>` is public and needs neither a
session nor an unlocked vault; it increments `used_count` and is audited as `unauth`.

### Recovery

At init a 96-bit recovery code is shown once. Its Argon2 hash is stored for verification, and
the master key is stored encrypted under `Argon2id(recovery code, recovery salt)`.
`/api/auth/recover` decrypts that cell, derives a new master key from the new password,
re-wraps every folder key and the TOTP seed, writes a new verifier and a new recovery code,
and clears all sessions. Service tokens are untouched — their chain does not pass through the
master key.

## Authentication paths

| Path | Who | Mechanism |
|---|---|---|
| `POST /api/auth/unlock` | human | master password (+ TOTP if enabled) → `vault_session` cookie (HttpOnly, Secure, Lax, 8 h) + CSRF cookie/header pair |
| `GET /api/auth/oidc/*` | human | OIDC Authorization Code + PKCE; needs the vault already unlocked, or `VAULT_MASTER_PASSWORD` in env (dev only) |
| `Authorization: Bearer vlt_…` | service | folder-scoped token, `/api/v1/m/*` only |
| `GET /api/share/<token>` | anyone with the link | one-time/TTL link |

State-changing calls under a session require `X-CSRF-Token` equal to the `vault_csrf` cookie
(double submit, timing-safe compare). Machine API calls are exempt (no cookie involved).

## Request flow: read a secret in the UI

1. `GET /api/secrets?folder_id=…` — list without values.
2. `GET /api/secrets/{id}` — backend unwraps the folder key with the master key, decrypts
   value/login/notes, computes the current TOTP code if a seed exists, bumps `last_accessed`,
   writes `secret:read` to the audit log.
3. The frontend renders through `el()` with `textContent` — no `innerHTML` with data.

## Data model (SQLite)

`folders`, `secrets`, `secret_history`, `service_tokens`, `share_links`, `webhooks`,
`audit_log`, `lockdown` (reserved). Schema is created by SQLAlchemy `create_all`; column
additions are idempotent `ALTER TABLE`s in `db._idempotent_migrations`.

## Operational boundaries

- **Single worker.** Sessions and rate limits live in memory; run `uvicorn --workers 1`.
- **Backup = `data/`.** `ops/backup.sh` snapshots SQLite via the online backup API and tars it
  with `config.json`; without `config.json` the database cannot be opened by anyone.
- **Locked after restart** by design. For unattended restarts use OIDC with
  `VAULT_MASTER_PASSWORD` from a secret store — and understand that this moves the master
  password into the orchestrator's secret storage.
