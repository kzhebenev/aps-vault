# API

Base URL: `https://<host>/api`. JSON in, JSON out. Error bodies are `{"detail": "…"}`. Interactive OpenAPI UI: `/docs`.

## Authentication

| Style | Header / cookie | Used by |
|---|---|---|
| Session | cookie `vault_session` (set by unlock/OIDC) or `Authorization: Bearer <session id>`; writes also need `X-CSRF-Token: <vault_csrf cookie>` | UI, admin scripts |
| Service token | `Authorization: Bearer vlt_…` or `X-Vault-Token: vlt_…` | services, CLI, MCP, SDKs — `/api/v1/m/*` only |
| None | — | `/health`, `/init`, `/auth/*` entry points, `/share/{token}` |

## Health & lifecycle

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | `{status, version, initialized, unlocked}` — `unlocked` is true only if the server holds the master key **and** the caller has a valid session |
| POST | `/init` | `{master_password, init_token}` (≥12 chars; `init_token` = `VAULT_INIT_TOKEN`). Once. Returns `recovery_code` — shown once |
| POST | `/auth/unlock` | `{master_password, totp_code?}` → sets cookies, returns `csrf_token`. 5 failures / 15 min per IP or 50 globally → 429 (persisted; client IP taken from the trusted proxy only) |
| POST | `/auth/lock` | revokes the session; drops the master key if no sessions remain |
| POST | `/auth/recover` | `{recovery_code, new_master_password}` → re-wraps keys, returns `new_recovery_code`, clears all sessions |
| GET/POST | `/auth/2fa/status`, `/auth/2fa/setup`, `/auth/2fa/verify`, `/auth/2fa/disable` | TOTP on the master password; `setup` returns `otpauth_url` and a QR data URL, nothing is saved until `verify` |
| GET | `/auth/oidc/status`, `/auth/oidc/login`, `/auth/oidc/callback` | OIDC login (see Deployment) |

## Folders (session)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/folders` | `[{id, name, description, created_at}]` |
| POST | `/folders` | `{name, description?}` — generates a new folder key |
| DELETE | `/folders/{id}` | only if empty; revokes tokens scoped to it |

## Secrets (session)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/secrets?folder_id=&q=` | list without values; `q` matches name/tags/url |
| POST | `/secrets` | `{folder_id, name, value, login?, notes?, totp_seed?, tags?, url?}` — `url` must be `http(s)://` |
| GET | `/secrets/{id}` | full record incl. `value`, `login`, `notes`, current `totp`; bumps access stats; audited |
| PATCH | `/secrets/{id}` | any subset of the create fields; a changed `value` is kept in history |
| DELETE | `/secrets/{id}` | |
| POST | `/secrets/{id}/favorite` | toggle |
| GET | `/secrets/{id}/history` | last 50 previous values, decrypted |

## Service tokens (session)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/tokens` | list (no raw tokens) |
| POST | `/tokens` | `{name, folder_id, expires_days?, can_read_notes?, can_read_totp?, can_write?, allowed_cidrs?, allowed_hours?}` → `raw_token` once. Policy specs validated (422) — see docs/ACCESS-POLICIES.md |
| DELETE | `/tokens/{id}` | revoke |

## Share links

| Method | Path | Body / notes |
|---|---|---|
| POST | `/share` (session) | `{secret_id, ttl_minutes=60 (≤10080), max_uses=1 (≤100), note?}` → `url: /share/<token>` once |
| GET | `/share/{token}` (public) | `{name, value, uses_left, expires_at, note}`; 404 unknown/revoked, 410 expired/exhausted |
| GET | `/shares` (session) | list |
| DELETE | `/shares/{id}` (session) | revoke |

## Audit, stats, export

| Method | Path | Notes |
|---|---|---|
| GET | `/audit?limit=100` | newest first, ≤1000 |
| GET | `/stats` | totals, stale secrets (>90 days unread), token usage for 30 days |
| GET | `/export` | **plaintext** JSON of everything; audited |
| POST | `/import` | `{folders:[{name, description?, secrets:[…]}], create_missing_folders=true, skip_existing=true}` |

## Webhooks (session)

`GET/POST/DELETE /webhooks` manage records with an HMAC signing secret. Delivered on
`secret:create|update|delete` and `token:create|revoke` as `POST {event, ts, data}` with
`X-Vault-Event` and `X-Vault-Signature: sha256=<hmac>`; `data` carries names and ids, never
values. Targets must be `http(s)://` and public unless `VAULT_WEBHOOK_ALLOW_PRIVATE=1`.

## Machine API — `/api/v1/m` (service token)

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | token name, scope folder, permissions |
| GET | `/secrets` | names in scope, no values |
| GET | `/secret/{name}` | `{name, value, login?, updated_at}` + `notes` if `can_read_notes`, + `totp` (current code) if `can_read_totp` |
| POST | `/secret/{name}` | `{value, login?, tags?, url?}` — upsert, requires `can_write`; previous value goes to history |

Examples:

```bash
# read
curl -sf -H "Authorization: Bearer $VAULT_TOKEN" "$VAULT_URL/api/v1/m/secret/smtp-password"

# write (token must have can_write)
curl -sf -X POST -H "Authorization: Bearer $VAULT_TOKEN" -H 'Content-Type: application/json' \
     -d '{"value":"new-secret","login":"smtp-user"}' "$VAULT_URL/api/v1/m/secret/smtp-password"
```

Every machine call is audited as `m:secret:read` / `m:secret:put` with actor `token:<id>`;
a bad token is audited as `m:auth:fail`.

## Observability (Bearer `VAULT_METRICS_TOKEN`; 404 when unset)

| Method | Path | Notes |
|---|---|---|
| GET | `/metrics` | Prometheus text format — see docs/OBSERVABILITY.md |
| GET | `/api/security/lockdowns` | `{locked:[{ip, fail_count, last_fail}], window_sec, limit_per_ip}` — input for `ops/fail2ban/sync-bans.sh` |

## HashiCorp KV v2 compatible facade (service token)

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/sys/health` | `{initialized, sealed:false, version:"aps-vault x.y.z"}` |
| GET | `/v1/{folder}/data/{name}` | header `X-Vault-Token: vlt_…`; `{data:{data:{value, login?, notes?, totp?}, metadata:{version,…}}}`; 403 if the token's folder differs from `{folder}`, 404 unknown name |

Policy denials on the machine API return **403** `access policy: …` and are audited as
`m:auth:policy_denied`.
