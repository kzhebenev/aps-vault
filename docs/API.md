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
| GET | `/health` | `{status, version, node, db, initialized, unlocked, cipher, cipher_label, server_time_utc}` — `cipher` is `aes` or `gost` (0.18, docs/GOST.md) — always 200; `unlocked` is a property of the caller's session (0.6: the master key travels inside the session row, so any replica answers alike); `db: error` → `status: degraded` |
| GET | `/ready` | `{ready, node, db}` — 200 when this replica reaches the shared database, 503 otherwise; for load balancers |
| POST | `/init` | `{master_password, init_token}` (≥12 chars; `init_token` = `VAULT_INIT_TOKEN`). Once. Returns `recovery_code` — shown once |
| POST | `/auth/unlock` | `{master_password, totp_code?}` → sets cookies, returns `csrf_token`. 5 failures / 15 min per IP or 50 globally → 429 (persisted; client IP taken from the trusted proxy only) |
| — | tokens: `allowed_cert_fingerprints` (0.11) — hex SHA-1/SHA-256 prints; the machine API refuses a bound token unless a trusted proxy forwards a matching `X-Client-Cert-Fingerprint` |
| — | enrolment (0.21): `POST /enrollments {folder_id, name_prefix, ttl_minutes, max_uses, …}` → `{code, command}` (owner / manager); `GET /enrollments`; `DELETE /enrollments/{id}`; public `POST /enroll {code, public_key, name}` → `{raw_token, token_name, …}` — `docs/ENROLLMENT.md` |
| — | tokens: `client_public_key` (0.17) — raw X25519 public key (32 B), a GOST R 34.10-2012 point (64 B, X‖Y little-endian → GOST envelope `VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM` with an extra `ukm` field) or, since 0.22, an uncompressed P-256 point (65 B → `P256-HKDF-SHA256-AES256GCM`, for keys held in a TPM / PKCS#11 token), base64; `GET /api/v1/m/secret/{name}` then returns `{name, version, current_version, updated_at, sealed:{alg,v,epk,nonce,ct}}` and no plaintext; the KV facade answers 403; see `docs/SEALED.md` |
| POST | `/auth/login` | `{email, password}` — a named user (0.20) signs in; same cookies / `csrf_token` as unlock, body adds `kind: "user"`, `email`, `name`; 401 / 429 as for the master password |
| GET | `/me` | `{kind: "owner"}` or `{kind: "user", id, email, name, grants: {folder_id: role}}` — what the UI may show |
| — | `/users`, `/users/{id}/invite`, `/users/{id}/grants`, `/invite/{token}`, `/me/password` | users, invitations, grants (0.20) — `docs/USERS.md` |
| GET/POST | `/auth/hsm/status`, `…/enable {master_password, pin}`, `…/disable`, `…/unlock {pin?}` | PKCS#11 master-key cell (0.15): master key wrapped by an AES key inside a token; unlock with the token PIN; see `docs/HSM.md` |
| GET/POST | `/auth/kms/status`, `…/enable {master_password, pin?}`, `…/disable`, `…/unlock {pin}` | Cloud KMS cell (0.16, AWS / Yandex): with a PIN → PIN login (the PIN is the KMS encryption context), without → SSO auto mode (`unlock` answers 403); see `docs/KMS.md` |
| GET | `/auth/webauthn/status` | public: `{rp_id, credentials, prf_unlock, second_factor}` |
| POST | `/auth/webauthn/options?purpose=unlock\|second_factor[&email=…]` | public (`email` = a named user's keys, 0.23): WebAuthn `PublicKeyCredentialRequestOptions` JSON (base64url fields); `unlock` adds `extensions.prf.eval.first` |
| POST | `/auth/webauthn/unlock` | `{credential, prf_output}` → session (cookies + `csrf_token`), no password |
| POST | `/auth/webauthn/register/options`, `…/register/finish` | session; finish takes `{name, credential, prf_output?, transports, master_password}` → `{id, name, prf}` |
| GET / DELETE | `/auth/webauthn/credentials[/{id}]` | list / remove; `POST /auth/webauthn/second-factor {enabled}` |
| POST | `/auth/unlock` + `webauthn` | with the second factor on, the password alone gets 401 + `X-WebAuthn-Required: 1`; resend with `webauthn: <assertion>` |
| GET/POST | `/auth/sso-unlock/status`, `…/enable {master_password}`, `…/disable` | SSO unlock cell (0.10): master key wrapped under HKDF(`VAULT_SSO_UNLOCK_KEY`) so an OIDC login on any replica can open a session; `GET /auth/oidc/status` → `sso_unlock: node|cell|env|none` |
| POST | `/auth/change-password` | `{current_password, new_password, totp_code?}` → `{new_recovery_code}`; folder keys re-wrapped (tokens keep working), all sessions dropped |
| POST | `/auth/lock` | revokes the caller's session on every replica; `?all=1` revokes all sessions (cluster-wide "lock the vault") |
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
| GET | `/secrets/{id}/totp` | `{code, period, remaining}` for the live countdown; does not bump `access_count` or write `secret:read` |

Fields added in 0.7: `expires_at` (ISO date, rotation deadline; `clear_expires: true` in PATCH removes it) and
`folder_id` in PATCH to **move** a secret — every encrypted field is re-wrapped under the target folder's key,
history rows stay readable, audit `secret:move`.
| POST | `/secrets/{id}/rotate` | `{generate: "base64:32"|"hex:32"|"alnum:40"}` → `{version, previous_version}`; new server-made value, old one readable by machines via `?version=N` |

Machine-only (0.9): `machine_only: true` on create or PATCH hides the value from every human path (card returns
`value: ""` + `value_hidden: true` and does not count as a read; history values empty; export `value: null`,
import skips; share → 403). `generate` on create makes the value on the server so nobody sees it.

## Approvals (0.12)

| Method | Path | Notes |
|---|---|---|
| GET | `/approvals/settings` | `{approver_set, notify_configured, request_ttl_min, ticket_min}` |
| POST / DELETE | `/approvals/approver` | set `{master_password, approver_password}` / clear |
| POST | `/secrets/{id}/approvals` | `{reason}` → request `{id, status, approve_url, notified, expires_at}`; notifier called |
| GET | `/approvals/{id}`, `/approvals` | status of own request / recent requests |
| GET / POST | `/approve/{token}` (public) | metadata for the approver / `{approver_password, decision: approve\|deny}` |

A flagged secret's `GET /secrets/{id}` returns 403 with header `X-Approval-Required: 1` until called with
`?approval=<id>` of an approved request of the same session (10-minute ticket). History, export and share hide it.

## Tools (session)

| Method | Path | Notes |
|---|---|---|
| GET | `/tools/hibp/{prefix}` | Have I Been Pwned range API proxied for the UI's breach check: `prefix` = first 5 hex chars of SHA-1; returns the suffix list as text. 404 when `VAULT_HIBP=0`, 503 when upstream is unreachable |

## Service tokens (session)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/tokens` | list (no raw tokens) |
| POST | `/tokens` | `{name, folder_id, expires_days?, can_read_notes?, can_read_totp?, can_write?, allowed_cidrs?, allowed_hours?}` → `raw_token` once. Policy specs validated (422) — see docs/ACCESS-POLICIES.md |
| DELETE | `/tokens/{id}` | revoke |

## Token watch (session, 0.26)

| Method | Path | Notes |
|---|---|---|
| GET | `/tokens/alerts?include_acknowledged=0` | open alerts of the caller's folders (owner: all) — `{id, token_id, token_name, folder_name, kind, detail, ip, network, count, action, token_frozen, token_canary, last_at}` |
| POST | `/tokens/alerts/{id}/ack` | dismiss |
| GET | `/tokens/{id}/profile` | `{uses, networks: {cidr: {n, first, last, trusted, pending}}, secrets: {name: n}, first_seen, last_seen}` |
| PATCH | `/tokens/{id}` | `{on_anomaly: "alert"|"freeze"}` |
| POST | `/tokens/{id}/freeze`, `/tokens/{id}/unfreeze` | manager |
| POST | `/tokens/{id}/trust-network` | `{network: "203.0.113.0/24" or an address}` — known from now on, its open alerts dismissed |
| POST | `/tokens/leak-check` | owner; `{hashes: [64-hex…], revoke?: false}` → `{checked, found: [{hash, token_id, name, folder_name, revoked, last_used}], revoked}`; hashes = the vault's token hash (SHA-256 / Streebog-256) |

`POST /tokens` accepts `canary: bool` and `on_anomaly`; `GET /tokens` returns `canary`, `on_anomaly`, `frozen`, `frozen_reason`, `alerts_open`, `uses`.

## Users: TOTP, managers granting, folder-key rotation (0.30)

| Method | Path | Notes |
|---|---|---|
| GET | `/me/totp` | user; `{enabled}` (`/me` also carries `totp_enabled`) |
| POST | `/me/totp/setup` | user; `{secret_base32, otpauth_url, qr_data_url}` — nothing stored yet |
| POST | `/me/totp/verify` | user; `{secret_base32, code, password}` → enabled; the password is re-checked |
| POST | `/me/totp/disable` | user; `{code}` |
| POST | `/auth/login` | with TOTP on: `401` + `X-TOTP-Required: 1` until `totp_code` is sent |
| PUT / DELETE | `/users/{id}/grants…` | also for a folder **manager** on the folders they manage (not their own grant) |
| GET | `/users` | for a manager: a reduced directory (active people, roles on managed folders) |
| POST | `/folders/{id}/rotate-key` | owner; → `{secrets, history, grants, tokens_revoked: [names], enrollments_revoked}` |

## Share links

| Method | Path | Body / notes |
|---|---|---|
| POST | `/share` (session) | `{secret_id, ttl_minutes=60 (≤10080), max_uses=1 (≤100), note?}` → `url: /share/<token>` once |
| GET | `/share/{token}` (public) | `{name, value, uses_left, expires_at, note}`; 404 unknown/revoked, 410 expired/exhausted |
| GET | `/shares` (session) | list |
| DELETE | `/shares/{id}` (session) | revoke |

Two URLs for the same token: `GET /api/share/<token>` — JSON `{name, login, value, uses_left, expires_at, note}`
for scripts; `/share/<token>` — a page for a person (served by the UI; it calls the JSON endpoint only after the
recipient clicks "Open", so a messenger's link preview does not consume the link). Both count as one open.
| POST | `/share/note` | `{text (≤20000), title, ttl_minutes, max_uses, note}` → `{id, kind:"note", url:"/share/<token>", …}` — text encrypted under the link token, not stored as a secret (0.14) |
| DELETE | `/shares/note/{id}` | revoke a note link; `GET /shares` lists both kinds with `kind: secret\|note` |

Opening a note link (`GET /api/share/<token>`) returns `{kind:"note", name, value, uses_left, expires_at, note}`.

## Audit, stats, export

| Method | Path | Notes |
|---|---|---|
| GET | `/audit?limit=100` | newest first, ≤1000 |
| GET | `/stats` | totals, stale secrets (>90 days unread), token usage for 30 days |
| GET | `/export` | **plaintext** JSON of everything; audited |
| POST | `/import` | `{folders:[{name, description?, secrets:[…]}], create_missing_folders=true, on_conflict="skip"\|"version"\|"rename"}` → `{created_secrets, created_folders, updated, skipped}` |
| POST | `/import/parse` | owner; multipart `file`, `format=auto\|bitwarden\|keepass\|1password\|1pux\|lastpass\|csv\|dotenv\|apsvault`, `into_folder?`, `prefix?` → `{format, payload, warnings, stats}` — nothing stored (0.29, `docs/IMPORT.md`) |
| POST | `/import/hashicorp` | owner; `{addr, token, mount, path?, into_folder?}` → the same preview from a live KV v2 mount; the token is not stored |
| POST | `/import/passwork` | owner; `{host, token, master_password?, master_key?, vault_id?, into_folder?}` → the same preview from a Passwork 7+ instance (API v1), decrypted here when the instance encrypts on the client; nothing stored |

## Rotation in target systems (0.24)

| Method | Path | Body / notes |
|---|---|---|
| PUT | `/secrets/{id}/rotation` | manager; `{target: "postgres"\|"mysql"\|"ldap"\|"ssh"\|"http", config, interval_days=0, generate?, enabled=true}` — postgres: `{dsn_secret_id, role?, sslmode?, connect_timeout?, verify?, verify_dbname?}`; mysql (0.30): `{dsn_secret_id, role?, user_host?}`; ldap (0.31): `{dsn_secret_id, url, role?, mode?, start_tls?, tls_verify?, attribute?}`; ssh (0.31): `{dsn_secret_id, host, port?, host_key, role?, use_sudo?}`; http: `{url, method?, headers?, timeout?}` → rotation + public config + `scheduler` + `cells_written`; `signing_secret` once on the first http save |
| GET | `/secrets/{id}/rotation` | manager; configuration without the signing secret |
| DELETE | `/secrets/{id}/rotation` | manager |
| POST | `/secrets/{id}/rotation/run` | writer; generate → apply in the target → verify → store → `{version, previous_version, note}`; **502** with the target's reason when refused (vault unchanged) |
| GET | `/rotations` | scoped to granted folders |
| GET | `/rotations/status` | `{configured, tick_sec, total, scheduled, due, failing, cells_missing}` — `configured` = `VAULT_ROTATION_KEY` set |
| POST | `/rotations/cells` | owner; (re)write the automation cells after the server key was set |

Secrets carry `rotation: {target, interval_days, enabled, next_at, last_at, last_status, last_error, runs} | null`.
Audit: `rotation:set|delete|run|fail|cells`; webhooks: `secret:update {rotated: true, target}`, `rotation:fail`. `docs/ROTATION.md`.

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
| GET | `/secret/{name}` | `{name, value, login?, version, current_version, updated_at}` + `notes` if `can_read_notes`, + `totp` (current code) if `can_read_totp`. Token with `client_public_key` (0.17): the same fields arrive inside `sealed: {alg, v, epk, nonce, ct}` and nothing in plaintext — `docs/SEALED.md` |
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

**Token watch (0.26).** A call that does not fit the token's profile raises an alert (audit
`token:anomaly`, webhook `token:anomaly`). With `on_anomaly: freeze` the token is frozen and
every call answers `403 token is frozen by the token watch (<kind>) — a folder manager can unfreeze it in Tokens`
(audit `m:auth:frozen`). A canary token answers the generic `401 invalid service token` on any use.
`docs/TOKEN-WATCH.md`.

Versions (0.8): `GET /secret/{name}?version=N` returns an older value (`version`, `current_version` in every read;
404 when the version does not exist, 409 when it is encrypted under another folder — only possible for history
written before 0.8 and moved); `GET /secret/{name}/versions` → `{current_version, versions:[{version, current,
changed_at, changed_by, readable}]}`, no decrypt, not counted as an access. A write (`POST /secret/{name}`) returns
the new `version`.

## Observability (Bearer `VAULT_METRICS_TOKEN`; 404 when unset)

| Method | Path | Notes |
|---|---|---|
| GET | `/metrics` | Prometheus text format — see docs/OBSERVABILITY.md |
| GET | `/api/security/lockdowns` | `{locked:[{ip, fail_count, last_fail}], window_sec, limit_per_ip}` — input for `ops/fail2ban/sync-bans.sh` |

## HashiCorp Vault / Stronghold compatible facade (service token)

Full list and the mapping — docs/COMPATIBILITY.md. Errors here come in HashiCorp's shape
(`{"errors": [...]}`, 403 for any auth problem).

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/sys/health` | `{initialized, sealed:false, version:"aps-vault x.y.z"}` |
| GET | `/v1/{folder}/data/{name}` | header `X-Vault-Token: vlt_…`; `{data:{data:{value, login?, notes?, totp?}, metadata:{version,…}}}`; 403 if the token's folder differs from `{folder}`, 404 unknown name |
| POST/PUT | `/v1/{folder}/data/{name}` | `{data:{value, login?}}` — token needs `can_write` |
| LIST / GET `?list=true` | `/v1/{folder}/metadata/{prefix}` | `{data:{keys:[…]}}`, `/` in names makes sub-folders |
| GET | `/v1/{folder}/metadata/{name}` | versions metadata |
| GET | `/v1/auth/token/lookup-self`, `/v1/sys/seal-status`, `/v1/sys/internal/ui/mounts/{path}` | what `hvac` / `vault` CLI call around a read |

Policy denials on the machine API return **403** `access policy: …` and are audited as
`m:auth:policy_denied`.
