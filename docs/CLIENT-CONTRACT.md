# Client contract — building an extension or a mobile app against APS Vault

This is the stable surface a human-facing client (browser extension, iOS/Android app, desktop
tool) relies on. Everything here is tested in `backend/tests` and used by the bundled web UI;
anything not listed is subject to change. Base URL below is `https://vault.example.com`.

## 1. Two ways in

| | Session (a person) | Service token (a machine) |
|---|---|---|
| obtained by | `POST /api/auth/unlock` with the master password (+ TOTP code when 2FA is on) | issued by the administrator in the UI, scoped to one folder |
| carried as | cookie `vault_session` **or** header `Authorization: Bearer <sid>` | `Authorization: Bearer vlt_…` or `X-Vault-Token: vlt_…` |
| lifetime | 8 h (`session_ttl_sec`), revoked by `POST /api/auth/lock` | until revoked / `expires_at`; no refresh |
| sees | everything the administrator sees (except machine-only / approval-required values) | one folder, read-only unless `can_write` |
| CSRF | cookie clients must send `X-CSRF-Token` (see §3); Bearer clients without cookies are exempt | none |
| CORS | origin must be in `VAULT_ALLOWED_ORIGINS` (extensions: `chrome-extension://<id>` / `safari-web-extension://<id>`) | same |

A mobile app or an extension's background script should use the **Bearer session**: store
`sid` in the platform's secure storage (Keychain / Keystore / `storage.session`), never a cookie
jar. The web UI uses the cookie form.

## 2. Session lifecycle

```http
GET  /api/health                     → {status, version, node, db, initialized, unlocked}
POST /api/auth/unlock                {master_password, totp_code?}
     200 → {ok, session_ttl_sec, csrf_token} + Set-Cookie vault_session (httpOnly) + vault_csrf
     401 "wrong master password" | 401 "2FA is enabled: totp_code is required" | 429 (lock-out)
POST /api/auth/lock                  → drops this session on every replica (`?all=1` — every session)
```

The session id is the value of the `vault_session` cookie. Native clients: read it from the
`Set-Cookie` header of the unlock response (or use a cookie-less HTTP client and parse it),
then send `Authorization: Bearer <sid>` on every call. `GET /api/health` with the Bearer header
reports `unlocked: true` for a live session — use it to decide between "show the vault" and
"ask for the master password" on start.

Lock-outs: 5 failed unlock attempts per IP in 15 min (`VAULT_FAIL_LIMIT_PER_IP`) → 429 for
15 min; 50 globally. Show the user the retry time rather than retrying.

## 3. CSRF for cookie clients

Writes (`POST/PATCH/DELETE /api/*`) from a client that sends the session **cookie** must also
send `X-CSRF-Token` equal to the `vault_csrf` cookie (returned in the unlock body as
`csrf_token` too). Exempt: `/api/init`, `/api/auth/unlock`, `/api/auth/recover`,
`/api/auth/oidc/*`, `/api/approve/*`, the machine API, and any request that carries
`Authorization: Bearer` and no session cookie.

## 4. Reading

```http
GET /api/folders                     → [{id, name, description, created_at}]
GET /api/secrets                     → list items (no values): {id, folder_id, folder_name, name, tags, url,
                                        has_login, has_totp, has_notes, is_favorite, created_at, updated_at,
                                        last_accessed, access_count, expires_at, version, machine_only, require_approval}
GET /api/secrets/{id}                → list item + {value, login, notes, totp, value_hidden}
GET /api/secrets/{id}/totp           → {code, period, remaining}        (does not count as a read)
GET /api/secrets/{id}/history        → {history:[{id, version, value, changed_at, changed_by, hidden}], current_version, hidden}
```

Special cases a client must handle:

- `machine_only: true` → `value` is `""` and `value_hidden: true`; do not offer copy/reveal,
  show "only machines read this". The record still has login/notes/TOTP.
- `require_approval: true` → `GET /api/secrets/{id}` answers **403** with header
  `X-Approval-Required: 1`. Flow: `POST /api/secrets/{id}/approvals {reason}` →
  `{id, status:"pending", approve_url, notified, expires_at}`; poll `GET /api/approvals/{id}`
  every few seconds until `status` is `approved` (then read with `GET /api/secrets/{id}?approval={id}`,
  valid 10 min) or `denied`/`expired`. If `notified` is false, show `approve_url` for the user
  to pass on. The approver's side is `/approve/<token>` (public page; API: `GET/POST /api/approve/{token}`).
- Reading a secret bumps `access_count` and writes `secret:read` to the audit log — do not
  prefetch values in a list.
- TOTP: `period` is 30 s; refresh via `/totp` at `remaining` → 0. Display `code` grouped 3+3.

Search is client-side (the list is small): filter on `name`, `tags`, `url`, `folder_name`.

## 5. Writing

```http
POST  /api/folders                   {name, description}
POST  /api/secrets                   {folder_id, name, value, login?, notes?, totp_seed?, tags?, url?, expires_at? (YYYY-MM-DD),
                                      machine_only?, generate? ("base64:32"|"hex:32"|"alnum:40"), require_approval?}
PATCH /api/secrets/{id}              any of: name, value, login, notes, totp_seed, tags, url, folder_id (move),
                                      expires_at | clear_expires, machine_only, require_approval
POST  /api/secrets/{id}/favorite     toggle
POST  /api/secrets/{id}/rotate       {generate} → {version, previous_version}
DELETE /api/secrets/{id}
```

`url` must start with `http://` or `https://` (422 otherwise). `tags` is a comma-separated
string. A value change creates a new `version`; history keeps the old one.

## 6. Sharing (one-time links)

```http
POST /api/share                      {secret_id, ttl_minutes (1..10080), max_uses (1..100), note}
     → {url: "/share/<token>", …}    person: https://host/share/<token>   machine: https://host/api/share/<token>
GET  /api/shares  ·  DELETE /api/shares/{id}
```

Machine-only and approval-required secrets return 403 here.

## 7. Browser-extension specifics

- Register the extension origin in `VAULT_ALLOWED_ORIGINS` on the server; credentials mode
  `include` for the cookie form, or use the Bearer form from the background script and keep
  `sid` in `storage.session`.
- The Chrome/Edge extension in `kzhebenev/aps-vault-extension` is the reference: it fills
  login/value into the active tab, matches secrets by `url` host, copies TOTP, auto-locks on
  a timer. A Safari web extension can reuse its `background.js` and `popup.js` almost
  unchanged (manifest v3, `browser.*` namespace).
- Autofill matching: compare `new URL(secret.url).hostname` with the tab's hostname;
  secrets without `url` are offered only via search.

## 8. Mobile-app specifics

- Store `sid` in Keychain/Keystore; the server's 8-hour TTL and `lock` apply. Re-unlock asks for
  the master password (+ TOTP). Biometric unlock on the device = protecting the stored `sid`
  with the OS biometry; the vault itself does not see biometrics. (Server-side WebAuthn
  unlock with passkeys/security keys is on the roadmap and will be announced in this file.)
- Clipboard: copy, then clear after 30 s (the web UI does the same).
- Certificate pinning is optional; the API is plain HTTPS behind the deployment's proxy.
- Offline: cache the **list** (no values) if you like; never cache values.

## 9. Errors

JSON `{"detail": "…"}` with 400/401/403/404/409/410/422/429; the message is English and
meant to be shown. 401 on a session call means "locked — ask for the master password".
The HashiCorp facade (`/v1/…`) uses `{"errors": ["…"]}` instead.

## 10. Audit expectations

Every read/write by a client appears in `GET /api/audit` with the client's IP and
`User-Agent`. Set a descriptive `User-Agent` (`aps-vault-ios/1.0`, `aps-vault-safari/1.0`).
