# Users and roles (0.20)

Until 0.19 the vault knew one person: whoever holds the master password — the **owner**. Teams
need more: a developer who may read one folder, an operator who may change another, a team
lead who issues tokens for a third. 0.20 adds **named users** with a **role per folder**,
without weakening the owner's model and without any folder key existing in plaintext anywhere.

## Roles

| role on a folder | may |
|---|---|
| **reader** | see the folder and its secrets, read values, logins, notes, TOTP codes and history; mark favourites; request an approval |
| **writer** | reader + create, change, delete and rotate secrets; move a secret between folders where they are a writer |
| **manager** | writer + issue and revoke service tokens for the folder; create and revoke share links of its secrets |

A user sees only the folders they were granted; everything else does not exist for them —
not in the list, not by id (403). Everything that is not about a folder stays with the owner:
creating and deleting folders, users and grants, settings, 2FA and security keys of the
vault, SSO/HSM/KMS cells, webhooks, export and import, the audit log, note links, locking
every session. A user who calls an owner endpoint gets **403**, not 401.

The audit log names the person: `actor` is the user's e-mail for everything they do
(`secret:read`, `secret:update`, `token:create`, …), history entries carry `changed_by`.

## How it works

Each user has a **key pair** — X25519 in the `aes` cipher suite, GOST R 34.10-2012 in the
`gost` suite. The private key is stored encrypted under Argon2id(user password); the public
key in clear. A **grant** is a row (user, folder, role) carrying the folder's key encrypted
to the user's public key — an ephemeral key agreement, the suite's KDF and AEAD, the same
construction as sealed delivery. The owner, who holds the master key and therefore every
folder key, creates grants; the user opens them with the private key that only their
password unwraps. A user's **session** carries the private key wrapped under the session
cookie, exactly as the owner's session carries the master key.

Consequences:

- a database dump does not help: user private keys are under user passwords, folder keys
  under those private keys, the master key under the master password — nothing in clear;
- the owner never learns a user's password, and a user never learns the master password;
- a password change by the user re-wraps the private key; grants are untouched;
- the owner's password change or recovery does not affect users at all (grants depend on
  folder keys, which do not change);
- revoking a grant removes the user's only way to the folder key. It does **not** rotate the
  folder key — the key never left the server unwrapped, so there is nothing to recover from.
  Rotating folder keys is a separate operation, not part of 0.20.

## Invitations

```
owner: Users → Invite → e-mail, name, roles per folder   →   one-time link  /invite/<token>  (7 days)
user:  opens the link → sets a password (≥ 12 chars)     →   signs in: "User" tab, e-mail + password
```

The owner creates the user and gets a link to hand over through any trusted channel. Until
the user sets a password the private key is wrapped under the invite token; accepting the
invitation moves it under the password. **Reset password** (owner) regenerates the key pair,
wraps it under a new invite, re-creates every grant to the new public key and closes the
user's sessions. **Deactivate** closes sessions, removes grants and refuses sign-in; the
account can be invited again.

Failed sign-ins count against the same per-IP budget as the master password (5 in 15 min →
429) and appear in the audit log and the security log with the e-mail that was tried.

## API

Owner (session with the master key):

```http
GET    /api/users                                → [{id, email, name, is_active, has_password, invite_pending, grants:[{folder_id, folder_name, role}], created_at, last_login, public_key}]
POST   /api/users            {email, name?, grants?:[{folder_id, role}]}   → {id, email, invite_url: "/invite/<token>", invite_expires_sec}
POST   /api/users/{id}/invite                    → {invite_url, …}   (reset: new key pair, grants re-created, sessions closed)
DELETE /api/users/{id}                           → deactivate
PUT    /api/users/{id}/grants {folder_id, role}  → create or change a grant
DELETE /api/users/{id}/grants/{folder_id}
```

Public (no session):

```http
GET    /api/invite/{token}                       → {email, name}   404 when unknown, used or expired
POST   /api/invite/{token}  {password}           → sets the password (CSRF-exempt: the token authenticates)
POST   /api/auth/login      {email, password}    → session cookies + csrf_token, {kind:"user", email, name}; 401 / 429 like the master unlock
```

Any session:

```http
GET    /api/me                                   → {kind:"owner"} | {kind:"user", id, email, name, grants:{folder_id: role}}
POST   /api/me/password     {current_password, new_password}   (users)
GET    /api/folders                              → for a user: only granted folders, each with its `role`
```

Native clients (`docs/CLIENT-CONTRACT.md`) use `/api/auth/login` for people with accounts and
`/api/auth/unlock` for the owner; the session they receive works the same way, and `/api/me`
tells them which buttons to show.

## Security keys and SSO for users (0.23)

A user registers security keys from **My profile** (YubiKey, Touch ID, Windows Hello, Android),
proving their own password. A key with the PRF extension holds a cell with the user's private
key wrapped under HKDF(PRF output): the sign-in screen's **User** tab gets *Sign in with a
security key* — e-mail (to find the user's keys), one touch, no password. A key without PRF
becomes a **second factor**: the user switches it on in the profile, and `POST /api/auth/login`
then answers `401` + `X-WebAuthn-Required: 1` until the assertion is sent along
(`webauthn` field; options from `POST /api/auth/webauthn/options?purpose=second_factor&email=…`).
Keys are per person: the owner neither sees nor can delete them; a password reset by the owner
(re-invitation) drops them, because the key pair they wrapped is gone; deleting the last key
switches the second factor off so nobody is locked out.

**SSO**: when the vault's OIDC is configured and `VAULT_SSO_UNLOCK_KEY` is set, an OIDC login
whose e-mail belongs to an active user mints a *user* session. The private key reaches the
server through the user's **SSO cell** — the private key wrapped under HKDF(server SSO key,
user id), written when the user sets or changes their password or signs in with it for the
first time after the key was configured. Until then the callback answers 503 with a plain
message (sign in with the password once). An e-mail that is not a user falls through to the
owner path exactly as before. Deactivation clears the cell.

## One-time codes, managers granting, folder-key rotation (0.30)

**TOTP.** A user turns one-time codes on in *My profile*: a QR for the authenticator app, then a
code and the password to confirm. From then on a password sign-in needs the code
(`POST /api/auth/login` answers `401` + `X-TOTP-Required: 1` until `totp_code` is sent; a
wrong code counts against the failed-attempt budget). The seed is stored encrypted under a key
derived from the user's **own private key** — it can only be checked after the password has
unwrapped that key, the server has no way to read it on its own, and a password reset by the
owner (new key pair) clears it. One-touch sign-in with a PRF security key and SSO are strong
factors on their own and do not ask for the code.

**Managers grant.** A folder **manager** gives other users a role on the folders they manage —
from the folder's *Who has access* button (the person icon in the folder header) or
`PUT /api/users/{id}/grants`. The manager holds the folder key through their own grant and wraps
it to the other person's public key; the owner is not involved. A manager cannot change their
own grant, cannot touch folders they do not manage, and sees a reduced directory (`GET /api/users`
for a manager: active people with their roles on the managed folders, no keys). Inviting people
stays with the owner.

**Folder-key rotation.** Removing a grant or revoking a token takes away the *way* to the folder
key; the key itself stays. When the key may have left the building — a laptop with a user's
session, a token in a leaked `.env` — the owner presses *Rotate folder key* (the arrows icon in
the folder header, `POST /api/folders/{id}/rotate-key`): a new key is made, every secret of the
folder (value, login, notes, TOTP seed), its history and its rotation configurations are
re-encrypted, every user's grant is re-wrapped, the automation cell is rewritten. Service tokens
and enrolment codes of the folder carry the old key under a secret the vault does not hold (the
token itself), so they are **revoked** and their names returned — redeploy them with new tokens.
Audit `folder:rotate_key`, webhook `folder:rotate_key` with the revoked token names.

## Not yet

Per-user approval roles (the approver stays a second password); a manager inviting new people.
