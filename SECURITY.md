# Security

## Threat model

APS Vault protects **secrets at rest and in the API** against:

- theft of the database file and/or `config.json` — values are AES-256-GCM under per-folder
  keys wrapped by an Argon2id-derived master key; nothing decrypts without the master password
  or a valid service token;
- a compromised service or agent — its token unlocks one folder, read-only unless `can_write`
  was granted, and is revocable;
- CSRF, clickjacking, MIME sniffing — double-submit CSRF, `frame-ancestors 'none'`, `nosniff`,
  HSTS;
- brute force of the master password — Argon2id (~0.5 s per attempt) plus a per-IP limit.

It does **not** protect against:

- a compromised host or container runtime: the master key is in process memory while unlocked;
- a malicious administrator: whoever holds the master password sees everything, and export is
  plaintext by design;
- a compromised browser profile of the administrator (extensions, malware) while a session is
  open;
- loss of both the master password and the recovery code — the data is unrecoverable, on
  purpose.

## Known limitations (0.4.0)

- Single master password per instance; whoever unlocks sees every folder.
- Sessions and the unlocked master key live in one process — one worker only, no HA of the UI.
  The machine API does not depend on that state.
- The UI loads Tailwind from a CDN and the CSP therefore allows `'unsafe-inline'`; bundling
  it is on the roadmap.
- Share-link `used_count` is not incremented atomically; a race may allow one extra open.

Full review and what 0.4.0 fixed: [docs/SECURITY-REVIEW-2026-10-02.md](docs/SECURITY-REVIEW-2026-10-02.md).

## Reporting a vulnerability

Please do not open a public issue. Write to **kz@devkz.ru** with steps to reproduce. You will get an acknowledgement within 3 working days and
a fix or a mitigation plan within 30 days for anything rated High or above. We credit reporters
in the changelog unless asked not to.

## Cryptographic details

| Item | Choice |
|---|---|
| Password KDF | Argon2id, m = 64 MiB, t = 3, p = 4, 32-byte random salt, 32-byte output |
| Token / share-link KDF | Argon2id, m = 8 MiB, t = 2, p = 2 (inputs are ≥192-bit random strings) |
| Symmetric cipher | AES-256-GCM, 96-bit random nonce per encryption, 128-bit tag |
| Token storage | SHA-256 of the raw token |
| Recovery code | 96-bit random, Argon2 hash stored, plus master key wrapped under KDF(code) |
| Sessions | 256-bit random id, in-memory, 8 h, HttpOnly/Secure/SameSite=Lax |
| OIDC | Authorization Code + PKCE S256, RS256 via JWKS, iss/aud/exp/nonce checked, `email_verified` required |

Libraries: `cryptography`, `argon2-cffi`, `pyotp`. No home-grown primitives.
