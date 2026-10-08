# Architecture

Current as of 0.17. Earlier revisions of this document described a single-node, SQLite-only
design with sessions in process memory; since 0.6 everything that must be shared lives in the
database, and a vault is one or more identical replicas on top of it.

## Components

```
 browser ──HTTPS──▶ reverse proxy (TLS, optional mTLS) ──▶ frontend (nginx, static) ──/api/ /v1/ /metrics──▶ backend (FastAPI)
 service ──HTTPS──▶ reverse proxy ───────────────────────────────────────────────────/api/v1/m/──────────▶ backend
                                                                                                             │
                                                              ┌──────────────────────────────────────────────┴──────────────┐
                                                              │ database: SQLite file (single node) or PostgreSQL (cluster) │
                                                              └──────────────────────────────────────────────┬──────────────┘
                                                                  optional master-key providers: PKCS#11 token · cloud KMS
```

| Part | Tech | Role |
|---|---|---|
| `backend/` | Python 3.11, FastAPI, SQLAlchemy 2, `cryptography`, `argon2-cffi`, `pyotp`, `py_webauthn`, `python-pkcs11`, psycopg 3 | all logic; one uvicorn worker per replica |
| `frontend/` | `index.html`, `app.js`, `pages.js`, `boot.js`, `app.css`, `i18n*.js` — no framework, no build step; nginx | UI (hash routes, three panes); nginx also proxies `/api/`, `/v1/`, `/metrics` to the backend |
| `data/` | `vault.db` (SQLite mode), `softhsm/` (software PKCS#11 tokens, if used), legacy `config.json` (≤0.5, imported once) | the only state of a single node; back it up |
| `deploy/cluster/` | compose: 2 replicas + nginx balancer + PostgreSQL | reference cluster — `docs/CLUSTER.md` |
| `clients/` | Python (stdlib), Node, Go, Java | machine-API clients: cache, retries, fail-open, sealed delivery |
| `mcp/` | Python, FastMCP | MCP server for AI agents (stdio): `health / list_secrets / get / put`, and `use` — a request with a secret the agent never sees ([MCP.md](MCP.md)) |
| `ops/` | bash, node | CLI, backup/restore, fail2ban glue, browser checks |

### Backend modules (0.41.7)

Until 0.41.6 the human API was one 4 200-line `main.py`. It is now split by responsibility; the code moved verbatim
and `backend/tests/test_route_table.py` holds the routes, their dependency trees (the permission checks among them),
the middleware chain and the order of overlapping paths to what they were before the split.

| Module | What is in it |
|---|---|
| `main.py` | assembly only: includes the routers, the machine API, the startup checks |
| `app_core.py` | the app object, CORS, security headers, CSRF, the audit log, request helpers, crypto helpers, models |
| `authz.py` | **every permission check of the human API**: unlocked session, roles per folder, owner-only, attempt limits, TOTP replay |
| `api_auth.py` | health, init, unlock/lock, HSM and KMS master key, WebAuthn, 2FA, recovery |
| `api_users.py` | named users and their roles, their TOTP, folder-key rotation |
| `api_secrets.py` | folders, secrets, favourites, history, stats, export/import, import from other managers |
| `api_rotation.py` | rotation in target systems and its scheduler |
| `api_tokens.py` | service tokens, token watch, node enrolment |
| `api_sharing.py` | read approvals, one-time share links |
| `api_ops.py` | audit log, backups to S3, updates, metrics |
| `webhooks.py` | outgoing webhooks and the event emitter the other modules call |
| `sdk_api.py` | the machine API (`/api/v1/m/…`) and the HashiCorp-compatible facade (`/v1/…`) |
| `crypto.py`, `suite.py`, `gost.py`, `sealed.py`, `hsm.py`, `kms.py`, … | the cryptography and the providers (unchanged) |

### What lives where

| State | Where | Why |
|---|---|---|
| secrets, folders, history, tokens, links, webhooks, audit | database | shared by every replica |
| master-password salt, verifier, recovery cell, 2FA seed, SSO/HSM/KMS cells, approver hash | database, table `vault_config` (one row) | one vault = one row, whichever replica answers; ≤0.5 kept this in `config.json`, which is imported on first start |
| UI sessions | database, table `ui_sessions` | a session opened on replica A is valid on replica B |
| failed-attempt counters (lock-outs) | database, table `lockdown` | survive restarts, shared |
| WebAuthn challenges | database | single-use, 3 min, any replica may finish what another started |
| the **unwrapped master key** | nowhere at rest — see below | the thing everything else protects |

A replica keeps **no secret state in memory between requests**. The master key exists in the
process only for the duration of a request that needs it (a `contextvar`), and comes from one
of the cells described next.

## Key hierarchy

```
                     ┌─ master password ─Argon2id(m=64 MiB,t=3,p=4)─┐
                     ├─ recovery code ───Argon2id───────────────────┤
                     ├─ UI session cookie ─HKDF─ wraps the key in the session row (0.6)
                     ├─ WebAuthn PRF output ─HKDF─ per-credential cell (0.13)
   opens ──────────▶ ├─ SSO server key (VAULT_SSO_UNLOCK_KEY) ─HKDF─ cell (0.10)   ───▶  master key (32 B, per request)
                     ├─ PKCS#11 token: wrap key inside the HSM, CKM_AES_CBC_PAD (0.15)              │ AES-256-GCM
                     └─ cloud KMS key, optional PIN as encryption context (0.16)                     ▼
                                                                        folder key (random 32 B per folder, stored wrapped)
                                                                                     │ AES-256-GCM, fresh 96-bit nonce per field
                                                                                     ▼
                                                     secret value · login · notes · TOTP seed · every history version
```

- **Cipher suite (0.18)**: every primitive in this diagram goes through `suite.py` — AES-256-GCM /
  HKDF-SHA256 / SHA-256 by default, Kuznyechik-MGM / KDF_TREE / Streebog-256 with
  `VAULT_CIPHER=gost`; chosen at init, stored in `vault_config`, fixed afterwards (`docs/GOST.md`).
- **Verifier**: the constant `APS-VAULT-OK-v1` encrypted under the master key. Any path that
  yields a candidate key (password, recovery, PRF, token, KMS) is checked against it before a
  session is opened, so a wrong PIN or a foreign cell fails closed instead of producing garbage.
- **Folder keys** exist so that (a) a token, a share link or a sealed envelope can be scoped to
  one folder, and (b) a password change or recovery re-wraps a handful of folder keys instead
  of re-encrypting every value. The nonce of a folder key is kept on re-wrap because tokens
  derive their salt from it.
- **Cells** (`vault_config`): every alternative way to open the vault is the same master key
  encrypted under a different key. Password change and recovery re-wrap the cells the server
  can open by itself (SSO, HSM in auto mode, KMS without PIN) and drop the ones it cannot (PRF,
  HSM without a server-side PIN, PIN-bound KMS) with an audit row; the UI asks to re-enable them.
- **Sessions (0.6)**: `ui_sessions` holds the master key encrypted under
  `HKDF(session id)`; the id is only in the browser's cookie (or the Bearer header of a native
  client). A database dump therefore contains no usable master key even while administrators
  are logged in.

### Named users (0.20)

A user has a key pair (X25519 / GOST by suite); the private key is wrapped under Argon2id of
the user's password, the public key is stored in clear. A grant (`folder_grants`) carries the
folder key sealed to the user's public key with a role; a user's session row wraps the
private key instead of the master key, and the request identity (`state.Identity`) decides
how `_get_or_create_folder_key` obtains a folder key. Owner-only paths refuse users with 403
before any handler runs. `docs/USERS.md`.

### Service tokens

A token is `vlt_<base32-12>_<hex-64>` (≈320 bits of entropy). The database holds
`SHA-256(token)` for lookup and the folder key encrypted under `Argon2id(token, salt)` (light
parameters, m = 8 MiB, t = 2: the token is random, the KDF is a one-way mapping, not a
password stretcher). Every request: hash → row → derive → unwrap folder key → decrypt. The
master key is not involved, which is why the machine API works while the UI is locked and on
a replica that has never seen an administrator.

Per-token attributes: `can_read_notes`, `can_read_totp`, `can_write` (upsert, old value to
history), `allowed_cidrs` / `allowed_hours` (where-and-when policy, `policy.py`),
`allowed_cert_fingerprints` (mTLS binding: the proxy verifies the client certificate and
forwards its fingerprint; honoured only from trusted proxies), `expires_at`, and
`client_public_key` (sealed delivery, below).

### Sealed delivery (0.17)

A token with an X25519 public key never receives plaintext: the payload
`{value, login?, notes?, totp?}` is encrypted to that key — ephemeral X25519 → HKDF-SHA256
(`info = "aps-vault/sealed/v1" || epk || client_pk`) → AES-256-GCM with the secret name as
AAD — and only the process holding the private key opens it. This protects the path (proxy,
balancer, captured responses) and binds the token to a key the application holds; it does not
hide the value from the application itself. A 64-byte GOST R 34.10-2012 key on the token selects
the GOST envelope instead (VKO → KDF_TREE → Kuznyechik-MGM, 0.19). `docs/SEALED.md`.

### Machine-only secrets, versions, approvals

- `machine_only`: the value is never shown to a person — not in the card, history, export or a
  share link; the server can generate (`generate: base64:32|hex:32|alnum:40`) and rotate it.
- Every value change is a numbered **version**; `secret_history` keeps the old ones under the
  same folder key; the machine API and the KV facade read `?version=N`.
- `require_approval`: a person reads the value only after an **approver** (a second password,
  not an account) confirms from a link; tokens read as usual. `docs/APPROVALS.md`.

### Share links and notes

`/api/share` wraps the folder key under `Argon2id(link token)` and stores the token hash, TTL
and `max_uses`; `used_count` is decremented with a conditional UPDATE (no double spend).
`/share/<token>` renders a page for a person, `/api/share/<token>` returns JSON for a machine.
A **note** share (0.14) encrypts free text under a key derived from the link token — the text
exists nowhere else.

### Recovery

A 96-bit recovery code is shown once at init; its Argon2 hash and the master key wrapped under
`Argon2id(code)` are stored. Recovery derives a new master key from a new password, re-wraps
folder keys, the TOTP seed and the server-openable cells, writes a new verifier and a new
recovery code, revokes every session on every replica. Tokens are untouched.

## Authentication paths

| Path | Who | Mechanism |
|---|---|---|
| `POST /api/auth/unlock` | human | master password (+ TOTP code, + WebAuthn assertion when the second factor is on) → `vault_session` cookie (HttpOnly, Secure, Lax, 8 h) + CSRF pair |
| `POST /api/auth/webauthn/unlock` | human | security key / Touch ID / Android with the PRF extension → one touch, no password |
| `POST /api/auth/hsm/unlock` | human | PIN of the PKCS#11 token (or `{}` in auto mode) |
| `POST /api/auth/kms/unlock` | human | PIN of a PIN-bound KMS cell |
| `GET /api/auth/oidc/*` | human | OIDC Authorization Code + PKCE; the master key comes from the SSO cell, the HSM (auto mode) or the KMS (no-PIN cell) — `GET /api/auth/oidc/status` → `sso_unlock: node \| cell \| hsm \| kms \| env \| none` |
| `Authorization: Bearer vlt_…` / `X-Vault-Token` | service | folder-scoped token, `/api/v1/m/*` and the `/v1/` KV facade |
| `GET /api/share/<token>`, `/api/approve/<token>` | anyone with the link | one-time / TTL link; approver password for approvals |

State-changing calls under a cookie session need `X-CSRF-Token` equal to the `vault_csrf`
cookie. Exempt: the machine API, `/api/init`, the unlock entry points, `/api/approve/*`, and
any request carrying `Authorization: Bearer` without a session cookie (native clients).

## Request flow: a service reads a secret

1. `GET /api/v1/m/secret/db-password` with the token.
2. Token hash → row; expiry, revocation, where-and-when policy, mTLS binding checked (each
   refusal audited as `m:auth:policy_denied`, forwarded to the security log / SIEM).
3. Folder key derived from the token, value (and granted fields) decrypted.
4. Plain token → JSON with the fields. Sealed token → the fields encrypted to the client's
   key, `sealed: {alg, v, epk, nonce, ct}` in place of them.
5. `access_count`, `last_accessed` bumped; `m:secret:read` audited (with `sealed: true` /
   `version: N` in `meta`).

## Data model

`vault_config`, `folders`, `secrets`, `secret_history`, `service_tokens`, `share_links`,
`note_shares`, `webhooks`, `audit_log`, `lockdown`, `ui_sessions`, `approvals`,
`webauthn_credentials`, `webauthn_challenges`, `users`, `folder_grants`. Schema by SQLAlchemy `create_all`; column
additions are idempotent `ALTER TABLE`s in `db._idempotent_migrations` for both dialects, so an
old database upgrades on first start. SQLite and PostgreSQL run the same test suite
(`./run_tests.sh`, `./run_tests.sh pg`).

## Cluster

`VAULT_DATABASE_URL=postgresql+psycopg://…` turns a replica into a member of a cluster:
everything above is in the shared database, nothing is pinned to a node, `GET /api/ready`
reports whether this replica reaches the database (for the balancer). `docs/CLUSTER.md`.

## Operational boundaries

- **One uvicorn worker per replica** (the image's CMD); scale by replicas, not workers.
- **Backup**: single node — `ops/backup.sh` (online SQLite snapshot; `config.json` only on
  installations upgraded from 0.5); cluster — `pg_dump` of the vault database. Either is
  ciphertext without the master password or a token.
- **Locked after restart** by design, unless an auto-mode cell (SSO key, HSM with server-side
  PIN, KMS without PIN) lets OIDC logins mint sessions. Tokens never depend on that.
- **Observability**: audit to syslog/SIEM (JSON or CEF), Prometheus `/metrics`, a
  fail2ban-friendly security log. `docs/OBSERVABILITY.md`.
