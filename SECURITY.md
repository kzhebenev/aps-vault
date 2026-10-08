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

The token watch (0.26, `docs/TOKEN-WATCH.md`) adds detection to the policies: a token used from a
new network, from two places at once, too fast or to enumerate secrets raises an alert or is
frozen; canary tokens catch a thief reading places where no live token should be. It is
detection, not proof — a manager decides.

## Known limitations (0.17)

- One owner identity (master password plus any number of authenticators that open the same
  key) administers everything; named users (0.20) have roles per folder and sign in with a
  password, a security key or SSO (0.23), optionally with a TOTP code (0.30). Removing a user's
  grant does not rotate the folder key by itself; the owner rotates it explicitly
  (`POST /api/folders/{id}/rotate-key`, 0.30), which also revokes the folder's tokens. The
  approver role is a second password, not an account.
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
- Folders with **scheduled** rotation in target systems (0.24) keep an automation cell: their
  folder key wrapped under `VAULT_ROTATION_KEY`. Database **plus** that server key reads those
  folders — the same trust as the SSO cell. Folders without scheduled rotations have no cell;
  rotations by hand need none. The administrator credentials of database, LDAP and SSH targets
  are ordinary secrets (mark them machine-only); the SSH target pins the server's host key in the
  rotation configuration and refuses any other key. An HTTP rotation receiver gets the new value in the request body
  (https, HMAC-signed) — it is part of your trusted perimeter.

The code review of 0.4 and what it fixed: [docs/SECURITY-REVIEW-2026-10-02.md](docs/SECURITY-REVIEW-2026-10-02.md).
The white-box review of 0.36 (SAST, SCA, DAST and reading the code by four reviewers) and what 0.37 fixed —
one critical, five high, fourteen medium findings, each closed by a regression test that fails on 0.36:
[docs/SECURITY-REVIEW-2026-10-05.md](docs/SECURITY-REVIEW-2026-10-05.md) (in Russian). Live role and
boundary checks for your own stand: `ops/checks/dast.py`. No external review has been done yet.

## Rules the code enforces since 0.37

- **SSO never yields the owner by default.** Only accounts listed in `VAULT_OIDC_OWNERS` sign in as the owner;
  an e-mail that belongs (or belonged) to a named user signs in as that user or is refused.
- **Second factors are personal.** A named user's security key never satisfies the owner's second factor;
  turning a second factor off needs the password again; PRF unlock requires user verification.
- **Flags are the owner's.** Lifting *machines only* or *requires approval* needs the owner and the master
  password; tokens, enrollment codes and http rotation receivers for folders with flagged secrets are issued
  by the owner only; a share link stops working the moment its secret gets a flag.
- **Rotation through an administrator credential** (database, LDAP, SSH) is configured by the owner; the
  account it changes is fixed at configuration time.
- **Attempts are limited everywhere** a secret is checked, including inside a session (password change,
  turning 2FA off, TOTP verification); a TOTP code is accepted once; a password change closes the person's
  other sessions; deactivating a person revokes the tokens and enrollment codes they issued.
- **Outbound calls** (webhooks, approver notification, rotation, import) go over https to globally routable
  addresses and never follow redirects, unless `VAULT_WEBHOOK_ALLOW_PRIVATE=1`.
- **Clients bind the sealed value to the name they asked for** (AAD) and refuse a plaintext answer when a
  client key is configured.
- **Backups (0.39) are sealed to a key the server does not hold.** The dump is encrypted to the recipient's public
  key (post-quantum hybrid by default); a copy of the bucket, the database or the host does not open it. S3
  credentials stay in the environment; the vault only needs PutObject and never deletes. Since 0.40 the sealed payload
  also carries the VAULT_* / OIDC_* environment (switchable) — the backup private key then opens the keys around the
  database too — `docs/BACKUP.md`.
- **Updates (0.38) are decided by the agent, not by the vault.** The vault only records the owner's request (master
  password again); the update agent, which holds the Docker socket, independently checks that the version is a
  published release newer than what runs and that every image carries the release workflow's Sigstore signature for
  that tag with the pulled digest equal to the signed one — `docs/UPDATES.md`.
- **Agent keys (0.41.8) act as the owner only within an allow-list.** A session opened with `vlt_agent_…` reaches
  folders, secrets, tokens, users and grants, the audit log — and nothing else (`authz._AGENT_PATHS`, default deny):
  not the master password, recovery, cells, backups, webhooks, export, updates or other agent keys. The key is re-checked
  on every request (revoked/expired → session closed, networks), wrong keys count against the attempt limit, the audit
  names `agent:<name>`. It is owner-level read access to every secret — keep it like the master password —
  `docs/AGENT-KEYS.md`.
- **A flagged secret leaves its folder only by the owner in person (0.41.9).** Moving a 'machines only' / 'requires
  approval' secret to another folder handed its value to any token of that folder; a writer of both folders (and an
  agent key) could. Machine access to a flagged folder, rotation of a flagged secret to an http receiver and rotation
  through an administrator credential are the owner's in person, not an agent key's.
- **Review of 09.10.2026 (0.41.15).** A flag (`machines only` / `requires approval`) is refused while machine access to
  the folder handed out by someone other than the owner exists (tokens, enrolment codes, http rotation receivers) — such
  access set up before a flag used to keep reading it; an http rotation of a flagged secret runs only if the owner set
  it up. The approval gate covers the live TOTP code and the notes/login of a secret with both flags. Revoking an agent
  key revokes what it issued; a master password change revokes agent keys; an agent cannot reset a person's password;
  no user with an owner's SSO e-mail. HSM auto mode no longer opens an owner session for an empty unlock request.
  The machine audit of a folder no longer shows a folder whose name differs only in case. `backup env` keeps file names
  inside its directory; the OIDC token request is form-encoded.
- **Responses of `/api/` and `/v1/` are `no-store`;** the UI is served with a strict CSP, `X-Frame-Options`,
  COOP/CORP and a Permissions-Policy; containers run without capabilities they do not need.

## Scanner findings in the base image (0.41)

The backend image is `python:3.11-slim` (Debian 13). Its remaining critical/high findings are Debian packages with no
fixed version yet (util-linux / mount, systemd-homed libraries, ncurses, acl, perl-base). None of them is reachable: the
backend is one Python process, uid 10001, all capabilities dropped, no-new-privileges, and never runs those programs.
Each release carries `backend.openvex.json` (OpenVEX, signed with the other assets) with the reason per CVE, made by
`ops/gen-vex.py`; only listed packages get a statement, so a new finding elsewhere stays visible. With it:

```bash
trivy image --vex backend.openvex.json ghcr.io/kzhebenev/aps-vault/backend:<version>    # 0 critical/high on 0.41.0
```

0.41 removed curl from the image (the healthchecks use python3), which was 8 of the 52 findings.

## Verifying a release (0.28)

Every asset of a GitHub Release carries a Sigstore bundle (`<asset>.sigstore.json`) and every image
on `ghcr.io/kzhebenev/aps-vault/*` is signed keyless by the release workflow. Verify with cosign
against the workflow identity `https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v<version>`
and the issuer `https://token.actions.githubusercontent.com` — commands in `docs/PUBLISHING.md`.
SPDX SBOMs of the sources and of the backend image are attached to each Release. Since 0.36 every
asset and image also has a **SLSA build-provenance attestation** (GitHub-hosted runner, SLSA Build L3)
and the backend image an SBOM attestation: `gh attestation verify <asset|oci://image> --owner kzhebenev`.

## Reporting a vulnerability

Please do not open a public issue. Write to **kz@devkz.ru** with steps to reproduce. You will
get an acknowledgement within 3 working days and a fix or a mitigation plan within 30 days for
anything rated High or above. We credit reporters in the changelog unless asked not to.

## Cryptographic details

| Item | Choice |
|---|---|
| Cipher suite | `aes` (below) or `gost` (0.18): Kuznyechik-MGM (GOST R 34.12-2015, RFC 9058), Streebog-256 look-up hashes, KDF_TREE_GOSTR3411_2012_256 derivations, optional PBKDF2-HMAC-Streebog-512 — `docs/GOST.md`; chosen at init, stored, fixed |
| Password KDF | Argon2id, m = 64 MiB, t = 3, p = 4, 32-byte random salt, 32-byte output (both suites) |
| Token / share-link KDF | Argon2id, m = 8 MiB, t = 2, p = 2 (inputs are ≥192-bit random strings); gost: KDF_TREE |
| Symmetric cipher | AES-256-GCM, 96-bit random nonce per encryption, 128-bit tag; gost: Kuznyechik-MGM, 128-bit nonce, 128-bit tag |
| Verifier | constant `APS-VAULT-OK-v1` under the master key; checked on every unlock path |
| Token storage | SHA-256 of the raw token |
| Recovery code | 96-bit random, Argon2 hash stored, plus master key wrapped under KDF(code) |
| Sessions | 256-bit random id in an HttpOnly/Secure/SameSite=Lax cookie or a Bearer header; master key stored in the session row under HKDF-SHA256(id); 8 h |
| Security keys | WebAuthn (py_webauthn): ES256/RS256 assertions, single-use challenges in the DB, sign-count checked; PRF/hmac-secret output → HKDF-SHA256 → wrap key for the master-key cell |
| SSO cell | master key under HKDF-SHA256(`VAULT_SSO_UNLOCK_KEY`) |
| PKCS#11 cell | CKM_AES_CBC_PAD with a random IV under a non-extractable AES-256 key in the token (GOST28147 with a 64-bit IV configurable); integrity by the verifier |
| KMS cell | AWS KMS Encrypt/Decrypt (SigV4) or Yandex KMS encrypt/decrypt; constant encryption context; with a PIN (0.37, v2) the KMS output is additionally wrapped under Argon2id(PIN, salt) locally, so nothing derived from the PIN reaches the provider's logs |
| Sealed delivery | X25519 (ephemeral) → HKDF-SHA256 (`info = "aps-vault/sealed/v1" ‖ epk ‖ client_pk`) → AES-256-GCM, AAD = secret name (clients use the name they requested, 0.37) |
| OIDC | Authorization Code + PKCE S256, RS256 via JWKS, iss/aud/exp/nonce checked, `email_verified` required |
| Transport | TLS at the proxy; optional mTLS with certificate fingerprints bound to tokens |

Libraries: `cryptography`, `argon2-cffi`, `pyotp`, `py_webauthn`, `python-pkcs11`,
`gostcrypto` (Streebog family). The one primitive implemented in this repository is
Kuznyechik with the MGM mode (`backend/gost.py`), because no fast MIT-licensed implementation
exists for Python; it is verified against the GOST R 34.12-2015 and RFC 9058 test vectors and
cross-checked block by block against `gostcrypto`. It is table-based and the GOST R 34.10 curve
arithmetic (server and clients) is not constant-time, so the `gost` suite is **experimental**:
not hardened against side channels on a shared host (docs/GOST.md, "Side channels"); `aes` is
the recommended production profile. The HKDF/KDF_TREE compositions, SigV4 and
the sealed envelope are cross-checked by the Go, Java and Node clients against a
server-produced fixture.
