# Cloud KMS as a master-key provider (0.16)

The master key can be encrypted by a key that lives in a cloud KMS — **AWS KMS** or
**Yandex Cloud KMS** — and never leaves it. The vault stores the resulting ciphertext (the
*cloud cell*) next to the password-derived cell; opening it means asking the KMS to decrypt,
which the KMS does only for the vault's cloud identity and only with the right encryption
context. Every decryption shows up in the cloud's own audit log (CloudTrail / Audit Trails).

Two modes, chosen when the cell is enabled:

| | **with a PIN** | **without a PIN** (auto mode) |
|---|---|---|
| who can open the cell | someone who knows the PIN **and** reaches the vault, through the vault's cloud identity | the vault server itself |
| what the PIN does | since 0.37 (PIN v2): the master key is first wrapped locally under Argon2id(PIN, random salt), then encrypted by the KMS with a constant context. Cloud credentials alone open only the outer layer; nothing derived from the PIN is sent to the provider, so it never lands in CloudTrail / Audit Trails. Cells written by 0.36 and older (PIN → `HKDF(pin)` as the *encryption context*) still open and are re-written as v2 on the next PIN login | the context is a fixed marker |
| login screen | "Unlock with the PIN via KMS" | nothing — this cell is not a login |
| SSO (`/api/auth/oidc/status` → `sso_unlock`) | not a source | `"kms"`: any replica with the cloud credentials hands the master key to an OIDC login |
| password change / recovery | the server has no PIN → the cell is **dropped** (`auth:kms_cell_dropped`), re-enable it | re-wrapped through the KMS |
| database dump stolen | useless: the KMS key is in the cloud, the PIN is in a head | useless without the cloud credentials |

Compared with the PKCS#11 token ([HSM.md](HSM.md)) the trust moves from a device you hold to
the cloud's IAM: a key policy decides who may call `Decrypt`, and nothing on the vault host is
secret enough to open the cell by itself. With a PIN you get both: the policy **and** a secret
only people know.

## Configuration

```ini
VAULT_KMS_PROVIDER=aws              # aws | yandex
VAULT_KMS_KEY_ID=…                  # AWS: key id / ARN / alias (alias/…); Yandex: symmetric key id
VAULT_KMS_REGION=eu-central-1       # AWS only (default us-east-1)
VAULT_KMS_ENDPOINT=                 # optional: LocalStack / VPC endpoint (AWS), API base (Yandex)

# AWS credentials (any IAM principal allowed kms:Encrypt + kms:Decrypt on the key)
VAULT_KMS_AWS_ACCESS_KEY=AKIA…
VAULT_KMS_AWS_SECRET_KEY=…
VAULT_KMS_AWS_SESSION_TOKEN=        # for temporary credentials

# Yandex Cloud: an authorized key of a service account with kms.keys.encrypterDecrypter …
VAULT_KMS_YANDEX_KEY_FILE=/app/data/yc-key.json    # yc iam key create --service-account-name … -o yc-key.json
# … or a ready IAM token (e.g. from the VM metadata service; refresh it yourself)
VAULT_KMS_YANDEX_IAM_TOKEN=
```

No SDKs: AWS requests are signed with Signature V4 here, Yandex gets an IAM token minted from
the authorized key (PS256 JWT). Only `Encrypt` / `Decrypt` of a 32-byte master key are ever
called — the KMS key is a wrapping key, nothing else is sent to the cloud.

### Key policy / role

- **AWS**: `kms:Encrypt`, `kms:Decrypt` on the key for the vault's principal. With a PIN you may
  additionally require the context in the policy
  (`"Condition": {"StringLike": {"kms:EncryptionContext:aps_vault": "aps-vault:pin:*"}}`) so the
  key can *never* decrypt a cell without a PIN.
- **Yandex**: role `kms.keys.encrypterDecrypter` on the key for the service account.

## Enabling and using

Settings → *Cloud KMS* → **Enable**: master password, optional PIN (4+ characters). The
master key is derived from the password for this one request, encrypted by the KMS, the cell
is stored, the key is forgotten. With a PIN the login screen shows a PIN field.

```http
GET  /api/auth/kms/status            public: {configured, enabled, pin_bound, provider, key_id, kms:{provider,key_id,region,endpoint,credentials}}
POST /api/auth/kms/enable            session: {master_password, pin?} → {enabled, pin_bound}   502 when the KMS refuses
POST /api/auth/kms/disable           session: removes the cell (the KMS key stays)
POST /api/auth/kms/unlock            public: {pin} → session   401 "KMS refused the PIN context"   403 for a cell without a PIN
```

Audit: `auth:kms_enabled` (provider, key id, pin_bound), `auth:kms_disabled`, `auth:kms_fail`
(stage enable/unlock, the KMS error class), `auth:kms_cell_dropped`; unlock rows carry
`how: kms`. Failed PIN attempts count towards the per-IP lock-out like password attempts, and
the KMS logs each `Decrypt` call on its side.

## What was verified

- **AWS KMS — through LocalStack** (`localstack/localstack:3.8.1`, community image; the
  `latest` tag needs a licence): `backend/tests/test_kms.py` — encrypt/decrypt round trip, the
  KMS refusing a wrong PIN, no PIN and a tampered blob (`InvalidCiphertextException` from the
  emulator, not from our code), enable → PIN login → drop on password change, auto mode as SSO
  source + re-wrap, a 502 when the endpoint is unreachable. `run_tests.sh` starts the emulator
  as a sidecar; the browser check (`ops/checks/ui-e2e.mjs`) drives the Settings and login UI
  against it. LocalStack speaks the real wire protocol (SigV4, `X-Amz-Target`,
  `EncryptionContext`), so a real region differs only in credentials and endpoint — **not
  exercised against a live AWS account.**
- **Yandex Cloud KMS — implemented from the public API reference, NOT verified.** It needs a
  service-account authorized key and a symmetric key id; the IAM exchange and the
  `:encrypt`/`:decrypt` calls follow the documented shapes (`aadContext` as base64). Treat it
  as *not configured* until a round trip has been run against a real key.

## Cluster

Every replica with the same credentials can open a cell without a PIN (auto mode), which
makes the KMS a natural SSO source for a cluster — no per-node key material to distribute.
PIN-bound cells need no shared state either: the PIN is typed into whichever replica answers.
