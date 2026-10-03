# Hardware token for the master key (PKCS#11)

Since 0.15 the master key can live wrapped by an AES-256 key **inside a PKCS#11 token** — a
hardware HSM or a software one. The administrator then unlocks with the token's PIN instead
of the master password; the token decrypts the cell for one request and the AES key never
leaves it. A database dump is useless without the token, and a weak PIN is protected by the
token's own attempt counter, not ours. The password path keeps working next to it.

## Configuration

```bash
VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so   # the vendor's PKCS#11 library
VAULT_PKCS11_TOKEN_LABEL=aps-vault                     # token to use (by label)
VAULT_PKCS11_KEY_LABEL=aps-vault-master-wrap           # AES-256 key; created on first enable
# VAULT_PKCS11_PIN=…                                   # optional, see "Auto mode"
```

Then Settings → *Hardware token (PKCS#11)* → *Enable*: master password + PIN. The vault opens
a read-write session on the token, creates the wrap key if it is missing (`CKK_AES`, 256 bit,
`SENSITIVE`, not `EXTRACTABLE`), encrypts the master key with `CKM_AES_CBC_PAD` (random 16-byte IV) and stores the
ciphertext in `vault_config`. Integrity: a tampered or foreign cell yields a wrong master key,
which fails the vault's own verifier check before a session is opened. The login screen gains *Sign in with the token PIN*.

## Tested and expected to work

| Token | Status |
|---|---|
| **SoftHSM2 2.6** (OpenDNSSEC) | tested — the backend test suite and the browser check run against it; bundled in the backend image (`softhsm2` package, tokens under `data/softhsm`) |
| YubiHSM 2 (yubihsm_pkcs11), Nitrokey HSM 2 / SmartCard-HSM (OpenSC), Rutoken HSM, Utimaco, Thales Luna | expected — same calls (`C_Login`, `C_GenerateKey` AES, `C_Encrypt/Decrypt` AES-CBC-PAD); **not exercised here** |
| YubiKey PIV / smart cards via OpenSC | no — they do RSA/EC, not AES; use the WebAuthn path for a YubiKey |

SoftHSM2 is a software token: it gives the interface and the workflow, not the tamper
resistance. Treat it as a development and test aid, or as a modest improvement over a plain
database on a single server (the token files live in `data/softhsm`, protected by the PIN).

Creating a SoftHSM2 token by hand (the e2e stack does this automatically):

```bash
docker compose exec backend softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678
```

## Auto mode

With `VAULT_PKCS11_PIN` set the server may use the token on its own:

- OIDC logins get the master key from the token on any replica
  (`GET /api/auth/oidc/status` → `sso_unlock: "hsm"`), like the SSO cell but without a
  second server-side secret;
- a password change or recovery re-wraps the cell through the token. Without the PIN on the
  server the cell is dropped (`auth:hsm_cell_dropped`) and the administrator re-enables it.

Trade-off: the PIN in the environment turns "something you have + know" into "something the
server has". Appropriate for a network HSM reachable only from the vault hosts; not for a
token whose files sit next to the database.

## Cluster

Every replica must reach the same token: a network HSM, or a SoftHSM2 token directory on
shared storage (the token files are small; concurrent reads are fine, enable/disable are rare
writes). A per-replica SoftHSM2 token would wrap the master key under different AES keys and
only one replica would open the cell.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/auth/hsm/status` | public: `{configured, enabled, auto, token_label, key_label, token: {label, manufacturer, model, serial}}` |
| POST | `/api/auth/hsm/enable` | session: `{master_password, pin}` → wraps the master key |
| POST | `/api/auth/hsm/disable` | session: removes the cell (the token's key stays) |
| POST | `/api/auth/hsm/unlock` | public: `{pin}` (or `{}` in auto mode) → session |

Audit: `auth:hsm_enabled`, `auth:hsm_disabled`, `auth:hsm_fail` (stage enable/unlock, the
token's error class), `auth:hsm_cell_dropped`; unlock rows carry `how: hsm`.
