# Deployment

## Requirements

- Docker + Compose, one host. ~200 MB RAM for the backend (Argon2 uses 64 MiB per unlock).
- A reverse proxy terminating TLS (Caddy, nginx, Nginx Proxy Manager, Traefik). Session
  cookies are `Secure`; the UI will not log in over plain HTTP from a non-localhost origin.

## Configuration

Everything comes from `.env` (see `.env.example` — every variable is explained there).

| Variable | Required | Meaning |
|---|---|---|
| `VAULT_PUBLIC_URL` | yes | e.g. `https://vault.example.com` — TOTP label, OIDC redirect base |
| `VAULT_ALLOWED_ORIGINS` | yes | browser origins allowed for CORS with credentials; your UI origin and, if used, your extension ID |
| `VAULT_INIT_TOKEN` | yes (first start) | one-time token the first-run screen asks for; remove after initialisation |
| `VAULT_PROXY_HOPS` | yes if behind your own proxy | number of proxies that append to `X-Forwarded-For` before the backend: `1` = only the bundled nginx (default), `2` = your reverse proxy + bundled nginx. Wrong value → the rate limiter keys on the wrong address (too coarse, never attacker-controlled) |
| `VAULT_TRUSTED_PROXIES` | no | networks those proxies connect from; default loopback + RFC1918 |
| `VAULT_BIND`, `VAULT_PORT` | no | where the UI is published on the host; default `127.0.0.1:8087` |
| `OIDC_*` | no | enable OIDC login; `OIDC_REDIRECT_URI` must be `<VAULT_PUBLIC_URL>/api/auth/oidc/callback`; endpoints must be https |
| `VAULT_FAIL_LIMIT_PER_IP/GLOBAL`, `VAULT_FAIL_WINDOW_SEC` | no | brute-force budget (5 per IP, 50 global, 15 min) |
| `VAULT_WEBHOOK_ALLOW_PRIVATE` | no | let webhooks target private/loopback addresses |
| `VAULT_SYSLOG_URL`, `VAULT_SYSLOG_FORMAT` | no | forward audit events to syslog/SIEM (`udp://host:514`, `json` or `cef`) |
| `VAULT_METRICS_TOKEN` | no | enables `GET /metrics` and `/api/security/*` for this Bearer token |
| `VAULT_SECURITY_LOG` | no | fail2ban-friendly log of failed attempts, e.g. `/app/data/security.log` |
| `VAULT_UI_ALLOWED_CIDRS`, `VAULT_UI_ALLOWED_HOURS`, `VAULT_TIMEZONE` | no | access policy for the human UI — docs/ACCESS-POLICIES.md |
| `VAULT_DEV` | **never in prod** | relaxed CORS (localhost), http OIDC, init without token |
| `VAULT_MASTER_PASSWORD` | **never in prod** | OIDC callback auto-unlocks a locked vault; puts the master password into the orchestrator's secret store |

## Start

```bash
cp .env.example .env && $EDITOR .env
mkdir -p data && chown 10001:10001 data      # the backend runs as uid 10001, not root
docker compose up -d --build
./smoke_test.sh
```

The frontend container serves the UI and proxies `/api/`, `/metrics` and `/v1/` (HashiCorp
KV v2 facade) to the backend; the backend is not published at all. Point your reverse proxy at `VAULT_BIND:VAULT_PORT` and pass
`X-Forwarded-For` / `X-Forwarded-Proto` (set `VAULT_PROXY_HOPS=2`).

## First run

1. Open the UI → enter the init token from `.env`, set a master password (≥12 chars, use a
   passphrase).
2. **Write down the recovery code.** Shown exactly once. Without it a forgotten master
   password means the data is gone — there is no back door.
3. Remove `VAULT_INIT_TOKEN` from `.env` (`docker compose up -d` to apply).
4. Optionally enable TOTP (Settings → 2FA) and OIDC.
5. Create folders per consumer (one per service or installation), add secrets, issue tokens.

## Operations

| Task | How |
|---|---|
| Backup | `ops/backup.sh` — online SQLite snapshot + `config.json` → `vault_<ts>.tar.zst`. Both files are needed; `config.json` holds the salt and the wrapped master-key cell |
| Restore | `ops/restore.sh <archive>` → stop backend, replace `data/`, start |
| Restart | the vault comes up **locked**; someone enters the master password. Machine API keeps working regardless |
| Rotate master password | `POST /api/auth/recover` with the recovery code (re-wraps folder keys, data untouched) |
| Revoke a token | UI → Tokens → revoke; effective immediately |
| Monitor | `GET /api/health`; audit in UI or `GET /api/audit`; stale-secret counters in `GET /api/stats` |
| Lock-outs | failed unlock attempts live in the `lockdown` table; `sqlite3 data/vault.db 'delete from lockdown'` clears them |

## Hardening checklist

- [ ] TLS at the proxy (HSTS is already sent by the backend).
- [ ] `VAULT_ALLOWED_ORIGINS` contains only your UI origin (and your extension ID).
- [ ] `VAULT_INIT_TOKEN` set before first exposure, removed after init.
- [ ] `VAULT_PROXY_HOPS` matches your proxy chain.
- [ ] Ports bound to `127.0.0.1`; firewall closed otherwise.
- [ ] `VAULT_DEV` and `VAULT_MASTER_PASSWORD` **not** set.
- [ ] `data/` owned by uid 10001, backups encrypted where they land.
- [ ] One uvicorn worker (the image's default CMD).
