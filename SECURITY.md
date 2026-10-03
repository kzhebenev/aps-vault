# Security

## Threat model

APS Vault protects **secrets at rest, in the API and on the way to the consumer** against:

- theft of the database (SQLite file or a PostgreSQL dump) — values are AES-256-GCM under
  per-folder keys wrapped by an Argon2id-derived master key; every alternative way in (session,
  security key, HSM, KMS, SSO) is the same master key under another key that is not in the
  database; nothing decrypts without a master password, an authenticator, a token or a key the
  database does not hold;
- a compromised service or agent — its token unlocks one folder, read-only unless `can_write`
  was granted, limited to source networks / time windows / a client certificate if configured,
  revocable at once on every replica;
- a **stolen token** — with sealed delivery (0.17) the token alone yields ciphertext: the
  values are encrypted to the consumer's X25519 key;
- an **observer on the path** (TLS-terminating proxy, load balancer, body-logging APM, a
  captured response) — sealed delivery leaves nothing readable in the response;
- a stolen master password — optional TOTP or security-key second factor; optional read
  approval by a second person for flagged secrets; machine-only secrets no person can read;
- brute force of any unlock path — Argon2id (~0.5 s per attempt) plus per-IP and global
  budgets persisted in the database; PINs are additionally protected by the token's or the
  KMS's own counters; every failure is audited and can be forwarded to a SIEM / fail2ban;
- CSRF, clickjacking, MIME sniffing — double-submit CSRF, `frame-ancestors 'none'`, `nosniff`,
  HSTS, `script-src 'self'` (no CDN, no inline scripts).

It does **not** protect against:

- a compromised vault host or container runtime: the master key is in process memory for the
  duration of a request, and the server sees plaintext before sealing it;
- a compromised **consumer** host after decryption: a sealed value is in the application's
  memory like any other secret (sealing protects the path and binds the token to a key, it is
  not DRM);
- a malicious administrator: whoever holds the master password sees everything except
  machine-only values, and export is plaintext by design;
- a compromised browser profile of the administrator (extensions, malware) while a session is
  open;
- loss of every way in — master password, recovery code, registered authenticators, HSM/KMS
  cells — the data is unrecoverable, on purpose.

## Known limitations (0.17)

- Single administrator identity per instance: one master password (plus any number of
  authenticators that open the same key); no per-person roles. Isolation is between services
  (tokens), not between people. The approver role is a second password, not an account.
- The PKCS#11 provider is tested against SoftHSM2 only; the GOST configuration (CryptoPro
  HSM, Rutoken) and the Yandex Cloud KMS provider are implemented but **not exercised against
  real services** — `docs/HSM.md`, `docs/KMS.md` say exactly what was and was not tested.
- Writes through the machine API (`POST /api/v1/m/secret/{name}`) are not sealed; they travel
  under TLS like before.
- A password change or recovery drops the cells the server cannot re-wrap (security-key PRF
  cells, HSM cells without a server-side PIN, PIN-bound KMS cells); the administrator re-enables
  them. This is deliberate — the alternative would be to keep the old master key around.
- A cluster trusts its PostgreSQL: whoever can write to `vault_config` can replace the
  verifier or a cell; protect the database as you would the vault host.

The code review of 0.4 and what it fixed: [docs/SECURITY-REVIEW-2026-10-02.md](docs/SECURITY-REVIEW-2026-10-02.md).
Features added since (cluster, WebAuthn, HSM, KMS, approvals, sealed delivery) have not had an
external review yet.

## Reporting a vulnerability

Please do not open a public issue. Write to **kz@devkz.ru** with steps to reproduce. You will
get an acknowledgement within 3 working days and a fix or a mitigation plan within 30 days for
anything rated High or above. We credit reporters in the changelog unless asked not to.

## Cryptographic details

| Item | Choice |
|---|---|
| Password KDF | Argon2id, m = 64 MiB, t = 3, p = 4, 32-byte random salt, 32-byte output |
| Token / share-link KDF | Argon2id, m = 8 MiB, t = 2, p = 2 (inputs are ≥192-bit random strings) |
| Symmetric cipher | AES-256-GCM, 96-bit random nonce per encryption, 128-bit tag |
| Verifier | constant `APS-VAULT-OK-v1` under the master key; checked on every unlock path |
| Token storage | SHA-256 of the raw token |
| Recovery code | 96-bit random, Argon2 hash stored, plus master key wrapped under KDF(code) |
| Sessions | 256-bit random id in an HttpOnly/Secure/SameSite=Lax cookie or a Bearer header; master key stored in the session row under HKDF-SHA256(id); 8 h |
| Security keys | WebAuthn (py_webauthn): ES256/RS256 assertions, single-use challenges in the DB, sign-count checked; PRF/hmac-secret output → HKDF-SHA256 → wrap key for the master-key cell |
| SSO cell | master key under HKDF-SHA256(`VAULT_SSO_UNLOCK_KEY`) |
| PKCS#11 cell | CKM_AES_CBC_PAD with a random IV under a non-extractable AES-256 key in the token (GOST28147 with a 64-bit IV configurable); integrity by the verifier |
| KMS cell | AWS KMS Encrypt/Decrypt (SigV4) or Yandex KMS encrypt/decrypt; encryption context = `HKDF-SHA256(PIN)` or a fixed marker |
| Sealed delivery | X25519 (ephemeral) → HKDF-SHA256 (`info = "aps-vault/sealed/v1" ‖ epk ‖ client_pk`) → AES-256-GCM, AAD = secret name |
| OIDC | Authorization Code + PKCE S256, RS256 via JWKS, iss/aud/exp/nonce checked, `email_verified` required |
| Transport | TLS at the proxy; optional mTLS with certificate fingerprints bound to tokens |

Libraries: `cryptography`, `argon2-cffi`, `pyotp`, `py_webauthn`, `python-pkcs11`. No
home-grown primitives; the HKDF, SigV4 and the sealed envelope are compositions of library
primitives and are cross-checked by the Go, Java and Node clients against a server-produced
fixture.
