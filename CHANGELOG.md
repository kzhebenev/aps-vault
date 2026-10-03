# Changelog

All notable changes. Dates are release dates.

## 0.17.1 — 2026-10-03

**Documentation and tooling caught up with 0.6–0.17.** `docs/ARCHITECTURE.md` rewritten
(state in the database, master-key cells, sessions, sealed delivery, data model, cluster);
`docs/DEPLOYMENT.md` lists every environment variable incl. PKCS#11, KMS, SSO cell, approvals,
mTLS; `SECURITY.md` threat model and crypto table updated to 0.17 (what sealed delivery, HSM/KMS
cells and WebAuthn do and do not protect, untested GOST/Yandex paths named); `docs/COMPARISON.md`
gains the 0.8–0.17 rows; README (en/ru) no longer calls the vault "one SQLite file, one
process" next to the cluster section. CLI: `vault get <name> [version]`, refuses to print a
sealed envelope as a value (decrypts with `VAULT_CLIENT_KEY` when the Python client is at hand).
MCP server: `version` argument, clear error for sealed tokens. Examples index mentions
`VAULT_CLIENT_KEY`.

## 0.17.0 — 2026-10-03

**Sealed delivery.** A service token can be bound to the application's X25519 public key; the
machine API then never returns plaintext — the value (with login / notes / TOTP as granted) is
encrypted to that key (X25519 → HKDF-SHA256 → AES-256-GCM, secret name as AAD, fresh ephemeral
key per response) and only the process holding the private key opens it. Nothing on the path
sees the value (proxy, load balancer, captured responses) and a stolen token is useless
without the key; what it does not change: the value is in the application's memory after
decryption. The Python (`aps-vault[sealed]`), Node, Go and Java clients decrypt in-process and
generate key pairs (`python -m aps_vault keygen` and equivalents); their tests open the same
envelope produced by the server. UI: *Sealed delivery* field in the token dialog, *sealed*
badge. The HashiCorp KV facade answers 403 for a sealed token. `docs/SEALED.md`.

## 0.16.0 — 2026-10-03

**Cloud KMS for the master key (AWS KMS, Yandex Cloud KMS).** The master key can be encrypted
by a key that lives in a cloud KMS and never leaves it; the cell opens only through the
vault's cloud identity. **With a PIN** the PIN-derived value becomes the KMS *encryption
context*, so the KMS refuses to decrypt for anyone without it — cloud credentials alone are
not enough — and the login screen gains a PIN field. **Without a PIN** (auto mode) the server
opens the cell itself: an SSO source for a whole cluster (`sso_unlock: "kms"`) and re-wrap on
password change; not a login. No SDKs (SigV4 / PS256 IAM JWT in-house). AWS verified through
LocalStack 3.8.1 (community image; the wire protocol is the real one); Yandex implemented
from the API reference and **not verified** — needs a real service-account key.
`docs/KMS.md`; endpoints `/api/auth/kms/{status,enable,disable,unlock}`; audit
`auth:kms_*`.

**GOST tokens through PKCS#11.** `VAULT_PKCS11_MECHANISM` / `VAULT_PKCS11_KEY_TYPE`
(`GOST28147`, 64-bit IV) and `VAULT_PKCS11_CREATE_KEY=0` for keys made by the vendor's tools —
the configuration CryptoPro HSM and Rutoken HSM need instead of AES. **Not exercised**: no
GOST module was at hand; `docs/HSM.md` says exactly what was and was not tested.

Test runner: LocalStack KMS sidecar in `run_tests.sh` and in the e2e stack
(`ops/checks/e2e-stack.sh`); the browser check covers the KMS Settings and PIN login.

## 0.15.0 — 2026-10-03

**Hardware token for the master key (PKCS#11).** The master key can be wrapped by an AES-256
key inside a PKCS#11 token; the administrator unlocks with the token's PIN, the AES key never
leaves the token, a database dump is useless without it. Tested against SoftHSM2 (bundled in
the backend image, tokens in the data volume); YubiHSM 2, Nitrokey HSM, Rutoken HSM and other
AES-GCM-capable modules are expected to work unchanged but were not exercised. Optional auto
mode (`VAULT_PKCS11_PIN`) lets the token serve SSO logins and re-wrap on password change.
`docs/HSM.md`; endpoints `/api/auth/hsm/{status,enable,disable,unlock}`.

## 0.14.0 — 2026-10-03

**Share a note.** A one-time link for free text that is not a stored secret — access details
for a contractor, a temporary password, a piece of config. Same model as secret sharing
(TTL, max uses, link for a person or JSON for a machine); the text is encrypted under a key
derived from the link token and exists nowhere else. Links page button and the `S` key;
`POST /api/share/note`, `DELETE /api/shares/note/{id}`; the shares list carries `kind`.

## 0.13.0 — 2026-10-03

**Security keys and biometrics (WebAuthn).** YubiKey, Touch ID on macOS, Windows Hello,
Android — registered from Settings (master password required). With the PRF / hmac-secret
extension (YubiKey 5, passkeys in Safari 18+/Chrome) the master key is wrapped under a key
derived from the authenticator's PRF output and **unlock is one touch, no password**; the
database holds ciphertext, the secret lives in the authenticator. Keys without PRF become a
**second factor**: password sign-in then also asks for the key (`X-WebAuthn-Required: 1`).

- `GET /api/auth/webauthn/status` (public), `POST …/options?purpose=unlock|second_factor`,
  `POST …/unlock` (assertion + PRF output → session), `…/register/options|finish`,
  `GET/DELETE …/credentials`, `POST …/second-factor`.
- Challenges are stored in the database (replicas share them), single-use, 3 minutes.
  RP ID = host of `VAULT_PUBLIC_URL` (an IP address cannot be an RP ID; `localhost` works).
- Password change / recovery drop the PRF cells (they wrapped the old key) — re-register keys;
  removing the last key switches the second factor off so the administrator is never locked out.
- Tests: a software ES256 authenticator in `test_webauthn.py`; the browser check registers and
  unlocks with Chrome's virtual CTAP2 authenticator with PRF.

## 0.12.0 — 2026-10-03

**Read approval (two-person rule).** A secret flagged `require_approval` is read by a person
only after an approver — a second person with a password of their own, no account — confirms
from a link. The approver never sees the value; service tokens are not involved. The link is
delivered through a configurable HTTP notifier (`VAULT_APPROVAL_NOTIFY_URL/HEADERS/BODY`:
Telegram, Slack, ntfy, any gateway) or shown to the requester when none is configured.
Requests live 15 minutes, approvals 10, bound to the requesting session; everything is
audited. UI: Settings section with recent requests, editor toggle, request panel in the card,
public approve page. `docs/APPROVALS.md`.

## 0.11.0 — 2026-10-03

**Token binding to client certificates (mTLS).** A service token may list fingerprints
(SHA-1 or SHA-256) of client certificates; the TLS proxy verifies the certificate and forwards
the fingerprint (`X-Client-Cert-Fingerprint`, configurable), the vault refuses a bound token
without a matching one. The header counts only from trusted proxies, so a client cannot
claim a certificate. Token editor field, table display, `docs/ACCESS-POLICIES.md` with the
nginx snippet.

## 0.10.0 — 2026-10-03

**SSO unlock across replicas.** An OIDC login proves identity, not the master password; until
now an SSO sign-in worked only on the replica where a password unlock had happened. With
`VAULT_SSO_UNLOCK_KEY` (≥32 random bytes, the same on every replica, never given to the IdP)
the administrator enables "SSO unlock" in Settings (master password required): the master key
is stored in `vault_config` wrapped under HKDF(server key), and every replica can mint a
session for an allowed OIDC user.

- `GET /api/auth/sso-unlock/status`, `POST …/enable {master_password}`, `POST …/disable`;
  `GET /api/auth/oidc/status` reports `sso_unlock: node|cell|env|none` per replica.
- The cell is re-wrapped on password change and recovery (or dropped when the replica has no
  server key); disabling it also clears the node cache. Audited.
- Trade-off, stated in `docs/CLUSTER.md`: a database dump plus the server key opens the vault —
  keep the key out of database backups. Without the key the cell is ciphertext.

## 0.9.0 — 2026-10-03

**Machine-only secrets.** A secret flagged `machine_only` is never shown to a person: the
card, the history, the export and share links hide its value; only service tokens read it.
For key material the administrator issues but must not see.

- `POST /api/secrets` with `machine_only: true` and `generate: "base64:32" | "hex:32" | "alnum:40"`
  makes the value on the server — nobody ever sees it. Also usable without `machine_only`.
- `POST /api/secrets/{id}/rotate {generate}` replaces the value with a fresh server-made one;
  the old value becomes the previous version (machines keep reading it with `?version=N`).
- Export writes `"value": null` for such secrets, import skips them; sharing returns 403.
- Opening the card does not count as a read (`secret:view`); un-hiding is audited (`secret:unhide`).
- UI: "Только для машин" toggle in the editor with server-side generation chips, a "Ротация"
  button in the card, badges in the list, a separate line in the health report.

## 0.8.0 — 2026-10-03

**Secret versions.** Every value change advances a per-secret version counter; history rows
carry the number they held. For a key rotation a service can keep decrypting old files with
the old key while new files use the new one.

- Machine API: `GET /api/v1/m/secret/{name}?version=N` returns an older value (404 for an
  unknown version); `GET /api/v1/m/secret/{name}/versions` lists versions without values and
  without counting as an access; reads and writes return `version`/`current_version`.
- HashiCorp KV v2 facade: `?version=N` on `data/`, full `versions` map and `oldest_version` in
  `metadata/` — `hvac.read_secret_version(version=…)` works.
- Human API: `version` on secrets, numbered history (`current_version`); the UI shows the
  version in the card and `vN` badges in the history.
- Moving a secret between folders re-wraps its history too, so `?version=N` keeps working for
  the new folder's tokens.
- Clients (Python, Node, Go, Java): `get(name, version)` / `getFull(name, version)` and `versions(name)`.
- Migration numbers existing history rows by time and sets each secret's counter above them.

## 0.7.1 — 2026-10-03

- **Two kinds of share link**, chosen with a toggle in the Share dialog (remembered):
  *for a person* (default) — `/share/<token>` opens a page with the secret's name, login,
  value (blurred, copy button) and the sender's message; the page asks for a click before
  consuming the one-time link, so link previews do not burn it; *for a machine* —
  `/api/share/<token>` returns JSON as before. Both count opens the same way.
- Share response now includes `login`; the dialog's note is explicitly a message to the recipient.

## 0.7.0 — 2026-10-03

**New web UI.** Same vanilla JS and CSP, no framework, no build step — rebuilt around the
daily loop instead of the API (`docs/COMPARISON.md` for the feature gap analysis).

- Three-pane layout: scopes and folders · list · detail card; every screen has a URL
  (`#/folder/3/s/12`, `#/tokens`, …), browser back works; responsive down to a phone.
- Keyboard: ⌘K palette with fuzzy search and ⌘Enter-to-copy, `/` search, `J/K`, `Enter`, `C`
  copy, `N` new, `?` help; list sorting; hover quick actions (copy value/login, open URL, star).
- Theme: dark / light / system, persisted; letter avatars instead of third-party favicons.
- Password generator: random (length, classes, look-alike filter) or passphrase (words,
  separator, capitalisation, number) with an entropy estimate; strength meter on every value.
- Breach check (Have I Been Pwned, k-anonymity: 5 hex chars of the SHA-1 leave the browser,
  proxied by `GET /api/tools/hibp/{prefix}`; `VAULT_HIBP=0` disables). Per secret and for
  the whole vault.
- Health report: weak, reused, overdue, expiring, unchanged 180 d, unopened 90 d, score,
  token usage. Plain text lives only in that tab while it is open.
- Rotation deadline per secret (`expires_at`), "Expiring" scope, badges 30 days ahead.
- Live TOTP with countdown; `GET /api/secrets/{id}/totp` refreshes the code without
  counting as an access.
- Move a secret between folders (`PATCH … {"folder_id"}`) with re-encryption under the target key.
- Pages instead of modals: tokens (with policy fields), share links, webhooks, audit log
  (group filters, text filter, CSV), settings (theme, language, auto-lock, clipboard
  clearing, auto-hide, 2FA with QR, change master password, lock everywhere, export/import,
  version/node).
- `POST /api/auth/change-password`: re-wraps folder keys (tokens survive), issues a new
  recovery code, drops every session.
- Unlock screen: 2FA code field appears when required; recovery from the login screen; SSO
  button when OIDC is configured. Clipboard fallback for plain-http origins.
- Checks: `ops/checks/ui-e2e.mjs` — 56 assertions in a real browser on a fresh vault
  (`ops/checks/e2e-stack.sh`), including a real machine-API read with a token created in the
  UI and a real share-link open; `ui-i18n.mjs` adapted; English dictionary regenerated (378 keys).
- Removed: the Tailwind bundle; styles are one hand-written `app.css` with design tokens.

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
