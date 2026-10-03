# Deployment

## Requirements

- Docker + Compose. Single node: one host, ~200 MB RAM for the backend (Argon2 uses 64 MiB
  per unlock). Cluster: PostgreSQL 14+ and a load balancer — `docs/CLUSTER.md`.
- A reverse proxy terminating TLS (Caddy, nginx, Nginx Proxy Manager, Traefik). Session
  cookies are `Secure`; the UI will not log in over plain HTTP from a non-localhost origin.
  WebAuthn needs a host name (RP ID), not an IP address.

## Configuration

Everything comes from `.env` (see `.env.example` — every variable is explained there).

### Core

| Variable | Required | Meaning |
|---|---|---|
| `VAULT_PUBLIC_URL` | yes | e.g. `https://vault.example.com` — TOTP label, OIDC redirect base, WebAuthn RP ID |
| `VAULT_ALLOWED_ORIGINS` | yes | browser origins allowed for CORS with credentials; your UI origin and, if used, your extension ID (`chrome-extension://…`, `safari-web-extension://…`). Several → space-separated, quote the value |
| `VAULT_INIT_TOKEN` | yes (first start) | one-time token the first-run screen asks for; remove after initialisation |
| `VAULT_PROXY_HOPS` | yes if behind your own proxy | proxies that append to `X-Forwarded-For` before the backend: `1` = only the bundled nginx (default), `2` = your reverse proxy + bundled nginx. Wrong value → the rate limiter keys on the wrong address (too coarse, never attacker-controlled) |
| `VAULT_TRUSTED_PROXIES` | no | networks those proxies connect from; default loopback + RFC1918. Also gates the mTLS fingerprint header |
| `VAULT_BIND`, `VAULT_PORT` | no | where the UI is published on the host; default `127.0.0.1:8087` |
| `VAULT_DATABASE_URL` | cluster | `postgresql+psycopg://user:pass@host:5432/vault`; unset = SQLite in `data/` |
| `VAULT_DATA_DIR`, `VAULT_DB_PATH` | no | SQLite location (defaults `/app/data`, `/app/data/vault.db`) |
| `VAULT_FAIL_LIMIT_PER_IP/GLOBAL`, `VAULT_FAIL_WINDOW_SEC` | no | brute-force budget for every unlock path (5 per IP, 50 global, 15 min); persisted in the database |
| `VAULT_HIBP` | no | `0` disables the breach check (the server forwards a 5-char SHA-1 prefix to Have I Been Pwned) |
| `VAULT_CIPHER` | at init | `aes` (default) or `gost` — Kuznyechik-MGM / Streebog / KDF_TREE for everything the vault encrypts and hashes; stored in the database and fixed for the vault's life — `docs/GOST.md` |
| `VAULT_GOST_PBKDF2` | no | gost suite only: PBKDF2-HMAC-Streebog-512 iterations for the master password instead of Argon2id (slow in pure Python; opt-in) |
| `VAULT_WEBHOOK_ALLOW_PRIVATE` | no | let webhooks and the approval notifier target private/loopback addresses |

### Sign-in and master-key providers

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_ALLOWED_EMAILS` | OIDC login; `OIDC_REDIRECT_URI` = `<VAULT_PUBLIC_URL>/api/auth/oidc/callback`; endpoints must be https |
| `VAULT_SSO_UNLOCK_KEY` | ≥32 random bytes (hex/base64), the same on every replica: lets an OIDC login open the vault on any replica once the administrator enables the SSO cell in Settings — `docs/CLUSTER.md` |
| `VAULT_PKCS11_MODULE`, `VAULT_PKCS11_TOKEN_LABEL`, `VAULT_PKCS11_KEY_LABEL`, `VAULT_PKCS11_PIN` | PKCS#11 master-key cell (HSM / SoftHSM2): unlock with the token's PIN; the PIN in the environment = auto mode (SSO source, re-wrap) — `docs/HSM.md` |
| `VAULT_PKCS11_MECHANISM`, `VAULT_PKCS11_KEY_TYPE`, `VAULT_PKCS11_CREATE_KEY` | `AES_CBC_PAD`/`AES` (default) or `GOST28147`/`GOST28147` for GOST tokens; `0` = the wrap key is pre-created by the vendor's tools |
| `VAULT_KMS_PROVIDER` (`aws`/`yandex`), `VAULT_KMS_KEY_ID`, `VAULT_KMS_REGION`, `VAULT_KMS_ENDPOINT`, `VAULT_KMS_AWS_ACCESS_KEY/SECRET_KEY/SESSION_TOKEN`, `VAULT_KMS_YANDEX_KEY_FILE` or `VAULT_KMS_YANDEX_IAM_TOKEN` | cloud KMS master-key cell; with a PIN → PIN login, without → SSO auto mode — `docs/KMS.md` |
| `VAULT_CLIENT_CERT_HEADER` | header in which the TLS proxy forwards the client-certificate fingerprint for mTLS-bound tokens (default `x-client-cert-fingerprint`) — `docs/ACCESS-POLICIES.md` |
| `VAULT_APPROVAL_NOTIFY_URL`, `…_HEADERS`, `…_BODY`, `…_METHOD` | where the approver's link goes (Telegram Bot API, Slack, ntfy, a company gateway); templated body — `docs/APPROVALS.md` |

### Policies and observability

| Variable | Meaning |
|---|---|
| `VAULT_UI_ALLOWED_CIDRS`, `VAULT_UI_ALLOWED_HOURS`, `VAULT_TIMEZONE` | where-and-when policy for the human UI — `docs/ACCESS-POLICIES.md` |
| `VAULT_SYSLOG_URL`, `VAULT_SYSLOG_FORMAT` | forward audit events to syslog/SIEM (`udp://host:514`, `json` or `cef`) |
| `VAULT_METRICS_TOKEN` | enables `GET /metrics` and `/api/security/*` for this Bearer token |
| `VAULT_SECURITY_LOG` | fail2ban-friendly log of failed attempts, e.g. `/app/data/security.log` (`ops/fail2ban/`) |

### Never in production

| Variable | Meaning |
|---|---|
| `VAULT_DEV` | relaxed CORS (localhost), http OIDC, init without token |
| `VAULT_MASTER_PASSWORD` | OIDC callback auto-unlocks a locked vault from the environment; use the SSO cell, the HSM or the KMS instead |

## Start (single node)

```bash
cp .env.example .env && $EDITOR .env
mkdir -p data && chown 10001:10001 data      # the backend runs as uid 10001, not root
docker compose up -d --build
./smoke_test.sh
```

The frontend container serves the UI and proxies `/api/`, `/metrics` and `/v1/` (HashiCorp KV
v2 facade) to the backend; the backend is not published at all. Point your reverse proxy at
`VAULT_BIND:VAULT_PORT` and pass `X-Forwarded-For` / `X-Forwarded-Proto` (set
`VAULT_PROXY_HOPS=2`).

Cluster: `deploy/cluster/` (two replicas, nginx balancer, PostgreSQL) — `docs/CLUSTER.md`.

## First run

1. Open the UI → enter the init token from `.env`, set a master password (≥12 chars, use a
   passphrase).
2. **Write down the recovery code.** Shown exactly once. Without it a forgotten master
   password means the data is gone — there is no back door.
3. Remove `VAULT_INIT_TOKEN` from `.env` (`docker compose up -d` to apply).
4. Settings: enable what you need — TOTP 2FA, security keys / Touch ID (WebAuthn), the PKCS#11
   or KMS cell, an approver for read approvals, OIDC.
5. Create folders per consumer (one per service or installation), add secrets, issue tokens
   (with a client public key for sealed delivery where the consumer supports it).
6. Invite colleagues (Users): each gets a role per folder and a one-time link to set a
   password — `docs/USERS.md`.

## Operations

| Task | How |
|---|---|
| Backup (single node) | `ops/backup.sh` — online SQLite snapshot (+ legacy `config.json` if present) → `vault_<ts>.tar.zst`. Ciphertext without the master password or a token |
| Backup (cluster) | `pg_dump` of the vault database; the balancer and replicas are stateless |
| Restore | `ops/restore.sh <archive>` → stop backend, replace `data/`, start |
| Restart / upgrade | the vault comes up **locked** (unless an auto-mode cell is configured); someone enters the master password or signs in with a key / PIN. Machine API keeps working regardless. Schema migrations run on start |
| Rotate master password | Settings → change password (re-wraps folder keys and server-openable cells; PRF cells and PIN-bound cells are dropped and re-enabled by the administrator), or `POST /api/auth/recover` with the recovery code |
| Rotate a secret | card → rotate (server-generated) or edit; services read the previous value with `?version=N` while they re-encrypt |
| Revoke a token | UI → Tokens → revoke; effective immediately on every replica |
| Monitor | `GET /api/health`, `GET /api/ready` (per replica), audit in UI or `GET /api/audit`, `/metrics`, syslog/SIEM |
| Lock-outs | failed attempts live in the `lockdown` table; `delete from lockdown` clears them (`ops/fail2ban/` can also ban at the firewall) |

## Hardening checklist

- [ ] TLS at the proxy (HSTS is already sent by the backend); mTLS for machine clients where
      the proxy supports it, fingerprints bound to tokens.
- [ ] `VAULT_ALLOWED_ORIGINS` contains only your UI origin (and your extension ID).
- [ ] `VAULT_INIT_TOKEN` set before first exposure, removed after init.
- [ ] `VAULT_PROXY_HOPS` matches your proxy chain; `VAULT_TRUSTED_PROXIES` lists your proxies.
- [ ] Ports bound to `127.0.0.1`; firewall closed otherwise.
- [ ] `VAULT_DEV` and `VAULT_MASTER_PASSWORD` **not** set; unattended SSO through a cell
      (`VAULT_SSO_UNLOCK_KEY`), the HSM or the KMS instead.
- [ ] Second factor on the master password: TOTP or a security key (`Require a key when signing
      in with the password`).
- [ ] Tokens: read-only unless needed, where-and-when policy, expiry, sealed delivery for
      consumers that support it (all bundled clients do).
- [ ] `data/` owned by uid 10001; backups encrypted where they land; the database on
      PostgreSQL with its own backup regime in a cluster.
- [ ] Audit forwarded to a SIEM or syslog; `/metrics` scraped; fail2ban on the security log.
- [ ] One uvicorn worker per replica (the image's default CMD).
