# Roadmap

What we intend to build, roughly in order. Items move to CHANGELOG.md when shipped.

## 0.5 — observability and access policy (shipped 0.5.0/0.5.1)
- [x] Syslog/SIEM forwarding of audit events (RFC 5424 over UDP/TCP, JSON or CEF payload).
- [x] Prometheus `/metrics` (token-protected).
- [x] PAM-style policies: allowed source networks and time windows per service token and for
      the human UI; denials audited and forwarded.
- [x] fail2ban: filter + jail generator on the vault's security log; `sync-bans.sh` pushes the
      vault's own lock-outs into a jail.
- [x] English UI with a language switch; Russian kept.
- [x] Browser extension configurable for any vault URL, published separately.

## 0.6 — clustering (shipped 0.6.0)
- [x] **PostgreSQL storage backend** (`VAULT_DATABASE_URL`, psycopg 3; dialect-aware migrations).
- [x] **Stateless workers**: sessions and the master-key verifier in the shared store; the master
      key wrapped into the session row under a key derived from the client's cookie — any replica
      serves any session, the database alone holds no usable key.
- [x] `/api/ready` vs `/api/health` (down vs locked); schema creation safe under concurrent start.
- [x] Reference deployment `deploy/cluster/` (two replicas, nginx LB, PostgreSQL); the
      two-node test suite; `docs/CLUSTER.md`.
- [x] OIDC master key hand-over between replicas: the SSO unlock cell under
      `VAULT_SSO_UNLOCK_KEY` (0.10.0).

## 0.8 — key rotation (shipped 0.8.0)
- [x] Secret versions addressable by the machine API and the KV facade (`?version=N`), versions
      listing, numbered history; clients updated.

## 0.9 — machine-only secrets (shipped 0.9.0)
- [x] Secrets never shown to people: hidden in the card, history, export and share links;
      server-side generation and rotation; audited un-hide.

## 0.11 — mTLS token binding (shipped 0.11.0)
- [x] Tokens bound to client-certificate fingerprints verified by the proxy.

## 0.12 — read approval (shipped 0.12.0)
- [x] Two-person rule: an approver with its own password confirms from a link; pluggable notifier.

## Next (agreed 03.10.2026)
- [x] **WebAuthn unlock** (0.13.0) — YubiKey / Touch ID / Android: PRF → one-touch unlock,
  otherwise second factor.
- **Safari web extension** — built from the Chrome extension against `docs/CLIENT-CONTRACT.md`.
- **Android app** — against the same contract (Bearer session, biometric protection of the
  stored session id, clipboard clearing).
- [x] **Share a note** (0.14.0) — one-time links for free text that is not a stored secret.

## Later
- [x] Hardware-backed master key on the server: PKCS#11 (0.15.0, tested on SoftHSM2).
- [x] Cloud KMS (AWS KMS, Yandex Cloud KMS) as a further master-key provider (0.16.0; AWS
  verified through LocalStack, Yandex implemented but **unverified** — needs a real key).
- [x] GOST PKCS#11 mechanisms for CryptoPro HSM / Rutoken (0.16.0, configuration only — not
  exercised against a real module).
- [x] **Sealed delivery to machines** (0.17.0) — a service token bound to a client public key
  (X25519); the machine API returns values encrypted to that key, so neither the proxy chain
  nor a stolen token alone yields plaintext; all four client libraries decrypt in-process.
- [x] GOST cipher suite — Kuznyechik-MGM / Streebog / KDF_TREE, algorithm-level (0.18.0).
- [x] GOST sealed-delivery envelope (VKO GOST R 34.10-2012 + Kuznyechik-MGM) in the four clients (0.19.0).
- [x] **Named users with per-folder roles** (0.20.0): reader / writer / manager, invitations, audit by e-mail.
- [x] Users: security keys (PRF one-touch / second factor) and SSO sign-in (0.23.0).
- [x] **Rotation in target systems** (0.24.0): PostgreSQL (`ALTER ROLE` + login probe + rollback) and a signed HTTP receiver; schedules through the folder automation cell (`VAULT_ROTATION_KEY`).
- Rotation targets: MySQL/MariaDB, LDAP, SSH keys; two alternating roles for zero-downtime database rotation.
- Users: managers granting others, folder-key rotation on revocation, TOTP for users.
- [x] **Node enrolment** (0.21.0): a one-time code → the node generates its key pair and receives a sealed token.
- [x] **Client key in hardware** (0.22.0): P-256 envelope + PKCS#11 key holder (TPM 2.0 via tpm2-pkcs11, HSM, smart card); Secure Enclave / Android Keystore are the mobile clients' job (`docs/CLIENT-CONTRACT.md`).
- Verify Yandex KMS and a GOST HSM against real services when credentials are available.
