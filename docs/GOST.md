# GOST cipher suite — algorithm-level conformance (0.18)

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
read by the other. Health reports it (`GET /api/health` → `cipher`, `cipher_label`), and the
Settings page shows it.

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
- **Sealed delivery** — X25519 + HKDF-SHA256 + AES-256-GCM in all four client libraries. A GOST
  envelope (VKO GOST R 34.10-2012 + Kuznyechik-MGM) is possible but needs GOST libraries on the
  client side in four languages; it is on the roadmap, not in 0.18.
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
- **Compatibility**: `tests/compat_fixture_check.py` opens a database written by 0.17.1 with the
  current code — master password, recovery code, token, sealed token, links, SSO cell — and
  runs after every test mode, including `gost` (the stored `aes` wins over the environment).

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
