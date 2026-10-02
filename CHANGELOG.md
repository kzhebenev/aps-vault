# Changelog

All notable changes. Dates are release dates.

## 0.6.0 — 2026-10-03

**Cluster mode.** Several replicas behind a load balancer share one PostgreSQL and behave as
one vault — `docs/CLUSTER.md`, reference deployment `deploy/cluster/`.

- `VAULT_DATABASE_URL`: PostgreSQL (psycopg 3) as the store; SQLite stays the single-node default.
- UI sessions live in the database; the master key is wrapped into the session row under a key
  derived from the cookie value (HKDF-SHA256) and unwrapped per request — any replica serves any
  session, a database dump holds no usable key. `POST /api/auth/lock?all=1` drops every session.
- The master-password verifier and recovery material moved from `data/config.json` into the
  database (`vault_config`); a legacy file is imported on first start.
- `GET /api/ready` (503 when the database is unreachable) for load balancers; `/api/health` adds
  `node` and `db`. Metrics: `aps_vault_sessions_active`, `node` label on `aps_vault_info`.
- Schema creation tolerates replicas starting simultaneously; migrations are dialect-aware.
- `backend/tests/test_cluster.py`: two real nodes on one database — init, session hand-over,
  lock, shared brute-force budget, tokens/KV facade, recovery, node loss. `./run_tests.sh pg`
  runs the whole suite against PostgreSQL 16.
- **Fixed:** service tokens stopped working after a password recovery (the token key is salted
  with the folder nonce, which recovery used to regenerate). Found by the cluster test.
- OIDC: an SSO login needs a master unlock on the same replica (or `VAULT_MASTER_PASSWORD`);
  documented in `docs/CLUSTER.md`.

## 0.5.1 — 2026-10-03

- HashiCorp Vault / Deckhouse Stronghold compatibility extended: `lookup-self`,
  `sys/seal-status`, `sys/internal/ui/mounts`, `LIST`/metadata, KV v2 write; errors in
  HashiCorp's shape; verified with the official `hvac` client. `docs/COMPATIBILITY.md`.
- Backend runs uvicorn with the h11 parser (the `LIST` method).

## 0.5.0 — 2026-10-02

Observability and access control:
- Syslog/SIEM forwarding of every audit event (RFC 5424 over UDP/TCP; JSON or CEF payload).
- Prometheus `/metrics` behind `VAULT_METRICS_TOKEN`; `GET /api/security/lockdowns`.
- PAM-style policies: `allowed_cidrs` / `allowed_hours` per service token, `VAULT_UI_ALLOWED_*`
  for the human UI; denials audited, forwarded and written to the fail2ban log.
- fail2ban: security log, filter, jail generator, `sync-bans.sh`.
- Persistent lock-out now emits `auth:lockdown`.
- HashiCorp KV v2 compatible read facade: `GET /v1/<folder>/data/<name>` with `X-Vault-Token`.

UI and ecosystem:
- English UI with a language switch (RU/EN), browser-language default.
- Token form: allowed networks and hours.
- Browser extension published separately (configurable vault URL, en/ru):
  https://github.com/kzhebenev/aps-vault-extension

## 0.4.0 — 2026-10-02 (first public release)

Security (see `docs/SECURITY-REVIEW-2026-10-02.md`):
- Client IP for the brute-force limiter is taken only from a trusted proxy and only the hop we
  control (`VAULT_PROXY_HOPS`); a client-supplied `X-Forwarded-For` / `X-Real-IP` no longer
  resets the budget. Failed attempts persist in the database (per-IP and global limits).
- CORS origins come from `VAULT_ALLOWED_ORIGINS`; no implicit localhost or any-extension origin.
- `POST /api/init` requires `VAULT_INIT_TOKEN`.
- Secret and webhook URLs must be `http(s)://`; webhooks refuse private/loopback targets
  unless `VAULT_WEBHOOK_ALLOW_PRIVATE=1`.
- Webhooks are now actually delivered (`secret:*`, `token:*`) with HMAC-SHA256 signatures.
- OIDC discovery and JWKS are fetched over https only.
- Removed unused `python-jose` (known CVEs) and `slowapi`.
- Container runs as uid 10001; backend port is no longer published.
- Tailwind is bundled (no CDN at runtime), CSP `script-src 'self'`.
- Share-link use counter is consumed atomically.
- API error messages in English.

Project:
- Configuration via environment (`.env.example`), no hard-coded hostnames.
- Clients: Python (stdlib), Node, Go, Java — all dependency-free, with cache, retries and
  fail-open-on-stale-cache; examples.
- Tests: crypto, auth, brute-force budget, CSRF, CORS, token scope, share links, webhooks,
  recovery, Python client end-to-end (33 backend tests), Go/Java/Node client tests; CI.
- Documentation: README (en/ru), ARCHITECTURE, API, DEPLOYMENT, SECURITY, CONTRIBUTING.

## 0.3.3 — 2026-06-19
- OIDC login (Authorization Code + PKCE) via Keycloak or any OpenID Connect provider.

## 0.3.2 — 2026-06-18
- `login` as a separate encrypted field of a secret (UI, machine API, CLI).

## 0.3.1 — 2026-06-10
- Machine API write: `POST /api/v1/m/secret/{name}` gated by per-token `can_write`.
- `vault put` in the CLI; fixed a command-injection in `vault get-all` (`shlex.quote`).
- MCP server (`mcp/`) for AI agents: `health / list / get / put`.

## 0.3.0 — 2026-06-08
- Cmd+K search, secret history, one-time share links, stats, favorites, auto-lock after 15 min,
  JSON export/import, CLI, drag-and-drop credential parsing, folder tree.
- Browser extension 0.1.0 (Chrome/Firefox MV3), Python and Node clients, backup script.

## 0.2.0 — 2026-06-08
- Hardening: CSRF double-submit, security headers, TOTP second factor on the master password,
  recovery code with master-key re-wrap.
- Per-client session check in `/api/health`.

## 0.1.0 — 2026-06-08
- First version: Argon2id + AES-256-GCM, envelope encryption per folder, folder-scoped
  service tokens, machine API, audit log.
