# GOST cipher suite — algorithm-level conformance (0.18) · experimental (0.41.4)

> **Experimental profile.** The algorithms are verified against the standards' test vectors, but
> the implementation is not hardened against side-channel attacks — see
> [Side channels](#side-channels). For production, the default `aes` suite is the recommended
> one; choose `gost` when the GOST algorithms are a requirement and the host is not shared with
> untrusted code.

APS Vault can run entirely on the Russian GOST algorithm family instead of AES/SHA-2. The suite
is chosen once, when the vault is initialised:

```ini
VAULT_CIPHER=gost          # default: aes
```

| | `aes` (default) | `gost` |
|---|---|---|
| values, folder keys, master-key cells (AEAD) | AES-256-GCM, 96-bit nonce | **Kuznyechik** (GOST R 34.12-2015, 256-bit key) in **MGM** (R 1323565.1.026-2019 = RFC 9058), 128-bit nonce, 128-bit tag |
| key derivation: session wrap, security-key PRF cell, SSO cell, KMS PIN context | HKDF-SHA256 | **KDF_TREE_GOSTR3411_2012_256** (R 50.1.113-2016) over HMAC-Streebog-256 |
| look-up hashes: service tokens, link tokens, session ids | SHA-256 | **Streebog-256** (GOST R 34.11-2012) |
| service-token / share-link key from the random token | Argon2id (m = 8 MiB, t = 2) | KDF_TREE over the token |
| master password → master key | Argon2id (m = 64 MiB, t = 3, p = 4) | Argon2id by default; `VAULT_GOST_PBKDF2=<iterations>` switches to **PBKDF2-HMAC-Streebog-512** (R 50.1.111-2016) |

Everything else is identical: envelope structure, folder scoping, tokens, cells, versions,
approvals, cluster. The suite is stored in `vault_config.cipher_suite`; **after initialisation
the stored value wins** over `VAULT_CIPHER`, because ciphertext written by one family cannot be
read by the other. Health reports it (`GET /api/health` → `cipher`, `cipher_label`,
`cipher_experimental`), the Settings page shows it with an «экспериментальный» mark for `gost`,
and the server logs a warning at every start.

## What is and is not GOST in the gost suite

Deliberately outside the suite, because each is somebody else's protocol:

- **TOTP** — HMAC-SHA1 (RFC 6238): what Google Authenticator and every other app computes.
- **WebAuthn** — ES256 / RS256 signatures: what YubiKeys and platform authenticators produce.
- **OIDC** — PKCE S256, RS256 tokens: the identity provider's side.
- **AWS KMS** — Signature V4 (SHA-256) and the cloud's own AES key; the Yandex path likewise
  uses the cloud's key. The *content* wrapped by the KMS is the master key of a GOST vault,
  but the wrapping is the cloud's.
- **PKCS#11** — whatever mechanism the token offers; `VAULT_PKCS11_MECHANISM=GOST28147` for
  GOST tokens (docs/HSM.md).
- **Webhook signatures** — HMAC-SHA256, our published contract to receivers.
- **Sealed delivery** — the envelope type follows the *client's* key, not the vault's suite:
  an X25519 key gives X25519 + HKDF-SHA256 + AES-256-GCM, a GOST R 34.10-2012 key (0.19) gives
  VKO + KDF_TREE + Kuznyechik-MGM, a GOST ‖ ML-KEM-768 key (0.32) gives the GOST hybrid — VKO and an
  ML-KEM encapsulation both feed KDF_TREE, Kuznyechik-MGM on the wire; all in the four client
  libraries (docs/SEALED.md). A GOST vault with GOST client keys is GOST end to end; a GOST vault
  with X25519 clients is GOST at rest and X25519/AES on the wire. ML-KEM is not a GOST algorithm: the
  hybrid adds a lattice problem to the GOST key agreement, it does not replace it.
- **Recovery-code and approver-password hashes** — Argon2 (password hashing, not data
  protection).
- **Master-password KDF** — Argon2id unless you opt into PBKDF2-Streebog. Argon2id is
  memory-hard, PBKDF2 is not; R 50.1.111 is a recommendation, and the pure-Python Streebog
  makes 2 000 iterations take seconds per unlock. Both are honest choices; pick knowingly.

## Implementation and verification

- **Kuznyechik** and **MGM** are implemented in `backend/gost.py` (precomputed LS tables, ~400
  KB/s in CPython — a secret read costs about a millisecond of cipher work). The MIT-licensed
  `gostcrypto` package provides Streebog, HMAC-Streebog, KDF and PBKDF2; its Kuznyechik is
  used only as a second opinion in the tests (it is ~16× slower).
- Test vectors in `backend/tests/test_gost.py`: Kuznyechik — GOST R 34.12-2015 A.1; MGM — RFC
  9058 Appendix A (Kuznyechik example: ciphertext and tag); HMAC-Streebog-256 and KDF_TREE —
  R 50.1.113-2016. Random cross-checks against `gostcrypto`. Negative cases: tampered
  ciphertext, foreign AAD, wrong key, malformed nonce.
- The **whole test suite** runs in both modes (`./run_tests.sh`, `./run_tests.sh gost`), and the
  browser check can run against a GOST stack (`E2E_CIPHER=gost ops/checks/e2e-stack.sh up`).
- **GOST envelope across languages**: `clients/fixtures/gost-sealed.json` (server-produced
  envelope for a fixed key, VKO/KDF/HMAC/Streebog/Kuznyechik/MGM vectors) is reproduced by the
  Python, Node, Go and Java tests; the curve arithmetic is cross-checked against `gostcrypto`.
- **Compatibility**: `tests/compat_fixture_check.py` opens a database written by 0.17.1 with the
  current code — master password, recovery code, token, sealed token, links, SSO cell — and
  runs after every test mode, including `gost` (the stored `aes` wins over the environment).

## Side channels

Correct by the test vectors is not the same as safe on a shared machine. Two places leak timing
that depends on secrets:

- **Kuznyechik** (`backend/gost.py`) uses precomputed LS tables indexed by bytes of the round
  state, which depend on the key and the data. On a CPU shared with an attacker (another VM on
  the same host, another container, a co-tenant process), cache-timing of table look-ups is a
  known way to recover the key of a table-based block cipher — the same class of attack as on
  table-based AES without AES-NI. CPython adds its own data-dependent timing on top.
- **GOST R 34.10 curve arithmetic** (VKO in sealed delivery) is double-and-add over big integers:
  in the server (`backend/gostec.py`, pure Python) and in the client libraries (`clients/go/gost.go`
  on `math/big`, `clients/node/src/gost.ts` on `BigInt`, `clients/java/.../Gost.java` on
  `BigInteger`) — none of them constant-time. The server only multiplies fresh single-use
  scalars, so a trace of the server reveals nothing reused. A **long-term** GOST private key goes
  through this code on the client's machine and on the machine that opens a backup.

The `aes` suite has neither problem: `cryptography` (OpenSSL) uses AES-NI or constant-time code,
and X25519 / P-256 come from the platforms' constant-time libraries.

What follows in practice:

- run a GOST vault on a host (and CPU) you do not share with untrusted workloads;
- keep the master key in a PKCS#11 token (docs/HSM.md), so the wrapping of the master key does
  not happen in Python at all;
- for sealed delivery, prefer the X25519 or ML-KEM hybrid client keys unless GOST on the wire is
  a requirement;
- treat the suite as **experimental** until a constant-time implementation replaces the tables
  (a bit-sliced Kuznyechik or a native library) — this mark is removed only then.

## Certification — read this before promising anything

This is **соответствие по алгоритму**: the algorithms are the standards' algorithms and the
implementation is verified against the standards' test vectors. It is **not a certified
СКЗИ**. Certification in Russia means an FSB licence for the developer, a certified crypto
module (КриптоПро CSP, ViPNet, etc.), and an assessment of the execution environment's
influence on it — expensive, out of scope for an MIT project, and tied to a specific
deployment. Deployments that need the certified kind can take this code and go through that
process, or keep the master key in a certified HSM through PKCS#11 (docs/HSM.md) and treat the
vault as the storage and delivery layer. The licence allows both; the documentation does not
claim either.

## Moving an existing vault to the gost suite

There is no in-place conversion (every ciphertext and hash would change under the same keys):
export from the aes vault (Settings → Export), initialise a new vault with `VAULT_CIPHER=gost`,
import. Service tokens are re-issued (their hashes and keys are suite-specific); security keys
are re-registered.
