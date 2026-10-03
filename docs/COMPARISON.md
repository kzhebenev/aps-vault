# APS Vault next to the usual suspects

What the web UI of APS Vault 0.7 does compared with the tools people already know, and what
it deliberately does not do. Written to decide what to build, kept as the honest answer to
"why not just use X". Checked against the products' documentation as of October 2026;
feature sets move, so treat it as a snapshot.

| | APS Vault 0.7 | Bitwarden / Vaultwarden | 1Password | Passbolt | HashiCorp Vault / Stronghold UI | Infisical |
|---|---|---|---|---|---|---|
| Audience | one team, services and agents | end users, families, companies | end users, companies | teams, shared credentials | platform teams | dev teams, app config |
| Three-pane layout (scopes · list · detail) | ✓ | ✓ | ✓ | ✓ | – (tree + KV form) | – (table) |
| Deep links / browser back | ✓ hash routes | ✓ | ✓ | ✓ | ✓ | ✓ |
| Dark / light / system theme | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Keyboard-first (palette, J/K, copy) | ✓ ⌘K, /, N, J/K, C, ? | partial | ✓ | partial | – | – |
| Password generator (random + passphrase, strength) | ✓ | ✓ | ✓ | ✓ | – | – |
| Breach check (HIBP k-anonymity) | ✓ per secret and whole vault | ✓ (premium) | ✓ Watchtower | ✓ | – | – |
| Health report (weak, reused, old, expiring, stale) | ✓ | ✓ reports (premium) | ✓ Watchtower | partial | – | – |
| TOTP with live countdown | ✓ | ✓ (premium) | ✓ | ✓ | – | – |
| Rotation deadline per secret, "expiring" view | ✓ | – | ✓ (expiry fields) | ✓ expiry | ✓ lease TTL (different idea) | ✓ secret rotation |
| Value history | ✓ | ✓ | ✓ | ✓ | ✓ versions | ✓ versions |
| One-time share links (no account) | ✓ | ✓ Send | ✓ | ✓ | – | ✓ |
| Move between folders with re-encryption | ✓ | ✓ | ✓ | ✓ | copy/delete | ✓ |
| Drag-and-drop text → parsed secret | ✓ | – | – | – | – | – |
| Clipboard auto-clear, auto-hide of revealed value | ✓ | ✓ | ✓ | ✓ | – | – |
| Machine tokens with source/time policy, scoped to a folder | ✓ | API keys (org) | service accounts | – | ✓ policies | ✓ machine identities |
| HashiCorp-compatible API for apps | ✓ KV v2 facade | – | – | – | native | partial |
| Audit log in the UI with filters and CSV | ✓ | ✓ (org) | ✓ | ✓ | ✓ | ✓ |
| Webhooks | ✓ | – | ✓ events API | – | ✓ event notifications | ✓ |
| Cluster (replicas on one PostgreSQL) | ✓ | ✓ | SaaS | ✓ | ✓ | ✓ |
| Multi-user with roles, sharing per person | – (one admin, machine tokens) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Browser extension (autofill) | partial (fill from vault, own URL) | ✓ | ✓ | ✓ | – | – |
| Mobile apps | – (responsive web) | ✓ | ✓ | ✓ | – | – |
| Attachments, custom fields, item types | – | ✓ | ✓ | – | KV map | KV map |
| SSO | ✓ OIDC (node-local in a cluster) | ✓ | ✓ | ✓ | ✓ | ✓ |

## What 0.7 added, and why

The 0.6 UI was a single column of cards and a stack of modal dialogs. Everything worked, but
it was built around the API, not around how an administrator spends the day: find a thing,
read one field, copy it, move on. 0.7 reorganises around that.

- **List + detail instead of modals.** The detail card is a page with its own URL; the list
  stays in view, so comparing two secrets or moving through a folder is a keystroke, not a
  dialog dance. Mobile collapses to list → card with a back button.
- **Keyboard everywhere.** ⌘K palette (fuzzy, ⌘Enter copies without opening), `/` to search,
  `J/K` to move, `Enter` to open, `C` to copy, `N` for a new secret, `?` for the map.
- **Password generator worth the name.** Random (length, classes, look-alike filter) or a
  passphrase (dictionary words, separator, capitalisation, number) with an honest entropy
  estimate rather than a colour. The same estimator rates every stored value.
- **Breach check without leaking the password.** SHA-1 prefix of 5 characters goes to the
  server, which forwards it to Have I Been Pwned; the suffix match happens in the browser.
  Per secret, or for the whole vault in the health report. Off with `VAULT_HIBP=0`.
- **Health report.** Weak, reused, overdue, expiring, unchanged for 180 days, unopened for
  90 days — each with the secret linked and an "Edit" button. Plain text exists only in that
  tab while it is open and is discarded as soon as the report is built.
- **Rotation deadlines.** A date per secret; 30 days before, it appears in "Expiring" in the
  sidebar and in the report. For encryption keys and API tokens that is the whole point of
  having a vault.
- **Live TOTP.** Countdown ring, code refreshes at the period boundary without counting as a
  new access or writing an audit row.
- **Move between folders.** Re-encrypts under the target folder's key; tokens of the old
  folder stop seeing the secret, tokens of the new one start.
- **Settings page.** Theme, language, auto-lock, clipboard clearing, 2FA (QR), change master
  password, lock everywhere, export/import, version and node.
- **Tokens, links, webhooks, audit as pages** with tables, filters, empty states and the
  policy fields (source networks, time windows) in the token editor.
- **Design system without a framework.** One CSS file with tokens, dark/light/system, no
  build step, no CDN; CSP `script-src 'self'` unchanged.

## Still missing, on purpose or for now

- **Multi-user.** One master password, one administrator; machines get tokens. Per-person
  sharing with roles is a different product (and a much bigger attack surface). Teams who
  need it should look at Passbolt or Bitwarden; APS Vault stays the vault *for services*.
- **Custom fields and attachments.** A secret is one value plus login, notes, TOTP, URL,
  tags. Structured data goes into `value` as JSON. Attachments would need a blob store.
- **Autofill in the extension.** The extension fills from the vault; it does not capture
  new logins or match forms automatically.
- **Native mobile apps.** The web UI is responsive; there is no app and no biometric unlock.
- **Favicons.** Letter avatars instead: an icon service would tell a third party which sites
  you keep credentials for.
