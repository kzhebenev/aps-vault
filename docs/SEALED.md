# Sealed delivery — secrets leave the vault encrypted to the application (0.17)

A service token can be bound to the **application's own X25519 public key**. For such a token
the machine API never answers with plaintext: the value (and login / notes / TOTP as granted) is
encrypted to that key, and only the process that holds the matching private key can open it.

```
                token + private key                        token only
   app ──GET /api/v1/m/secret/db──▶ proxy ──▶ LB ──▶ vault      attacker ──GET──▶ vault
   app ◀── {sealed: {epk, nonce, ct}} ◀──────────────  vault      attacker ◀── ciphertext ──
   app: X25519 → HKDF → AES-GCM → "pg-pass-2026"                 (nothing to do with it)
```

## What it protects — and what it does not

| threat | plain token | sealed token |
|---|---|---|
| TLS terminated at a proxy / load balancer that logs or is compromised | value visible there | ciphertext only |
| a captured response (debug proxy, APM body capture, core dump of the proxy) | value | ciphertext |
| a **stolen token** (CI log, `.env` in a repository, a laptop) | full read access to the folder | ciphertext — useless without the private key |
| a token used from the wrong machine | blocked only by CIDR / mTLS policies | blocked by the key as well |
| compromise of the **application host** after decryption | value in memory | value in memory — same |
| vault server compromise | plaintext available to the server anyway | same: the server decrypts before sealing |

So this is about the **path** and about **binding the token to something the application
holds**. It does not hide the secret from the application's own process, and it does not
replace TLS (TLS still protects the token and the request metadata; sealing protects the value
end-to-end regardless of what sits in between). Combine with `allowed_cidrs` / mTLS binding for
"where from" and with the key for "to whom".

Writes (`POST /api/v1/m/secret/{name}`) are not sealed: the application sends the new value
over TLS as before.

## Envelope

One envelope per response, fresh ephemeral key and nonce every time:

```
shared = X25519(ephemeral_sk, client_pk)
key    = HKDF-SHA256(ikm = shared, salt = "" (32 zero bytes), info = "aps-vault/sealed/v1" || ephemeral_pk || client_pk, L = 32)
ct     = AES-256-GCM(key, nonce = 12 random bytes, plaintext = JSON {value, login?, notes?, totp?}, aad = secret name)

GET /api/v1/m/secret/db-password  →
{
  "name": "db-password", "version": 3, "current_version": 3, "updated_at": "…",
  "sealed": {"alg": "X25519-HKDF-SHA256-AES256GCM", "v": 1, "epk": "<b64 32B>", "nonce": "<b64 12B>", "ct": "<b64>"}
}
```

Keys are **raw 32-byte X25519 keys in standard base64**, the same bytes every client library
produces. The AAD binds the envelope to the secret's name, so a blob for one secret cannot be
replayed as another. `?version=N` is sealed the same way. The HashiCorp KV facade (`/v1/…`)
has no place for an envelope and answers **403** for a sealed token.

### GOST envelope (0.19)

A **64-byte** public key on the token — a GOST R 34.10-2012 point (X ‖ Y, little-endian, curve
`id-tc26-gost-3410-2012-256-paramSetB`) — selects the GOST envelope instead, whatever the
vault's own cipher suite is:

```
kek   = VKO_GOSTR3410_2012_256(ephemeral_d, client_Q, UKM)      RFC 7836 §4.3: Streebog-256(UKM · d · Q)
key   = KDF_TREE_GOSTR3411_2012_256(kek, label = "aps-vault/sealed-gost/v1", seed = ephemeral_pk ‖ client_pk)
ct    = Kuznyechik-MGM(key, nonce = 16 random bytes (top bit clear), plaintext = JSON, aad = secret name)

→ {"alg": "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM", "v": 1, "epk": "<b64 64B>", "ukm": "<b64 8B>", "nonce": "<b64 16B>", "ct": "<b64>"}
```

Fresh ephemeral key pair and UKM per response. Private keys are 32-byte big-endian scalars.

### P-256 envelope and keys that live in hardware (0.22)

A **65-byte** public key — an uncompressed NIST P-256 point `0x04 ‖ X ‖ Y` — selects the third
envelope: ephemeral ECDH on secp256r1 → HKDF-SHA256 (`info = "aps-vault/sealed-p256/v1" ‖ epk ‖
client_pk`) → AES-256-GCM, `alg = P256-HKDF-SHA256-AES256GCM`. It exists for one reason: TPM 2.0
chips, HSMs and smart cards do ECDH on P-256 through PKCS#11 and almost never X25519. With it the
node's private key can be **generated inside the hardware and never leave it** — an image of the
node's disk no longer yields the key, and the token is bound to that particular device:

```
python3 -m aps_vault enroll https://vault… enr_… --pkcs11 /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so:node:1234     # TPM 2.0 via tpm2-pkcs11
python3 -m aps_vault enroll https://vault… enr_… --pkcs11 /usr/lib/softhsm/libsofthsm2.so:node:1234                 # SoftHSM2 (tests)
```
```python
key = Pkcs11Key(module, token_label="node", pin="1234", key_label="aps-vault-node")   # one CKM_ECDH1_DERIVE per envelope
Vault(url, token, client_private_key=key)
```

The clients expose the same seam for other holders: a `KeyProvider` (Node, Go) or a
`java.security.PrivateKey` from a SunPKCS11 key store (Java) with `publicKey()` / `ecdh(peer)`.
Software P-256 keys work everywhere too (`generate_keypair("p256")`, `generateKeyPair({ p256: true })`,
`GenerateP256KeyPair()`, `generateP256KeyPair()`). Verified: the Python client with SoftHSM2 through
`python-pkcs11`, the Java client through SunPKCS11 on SoftHSM2 (the same interface a TPM presents via
tpm2-pkcs11), Node and Go against a software provider; **not exercised on a real TPM or HSM**.

Two things the Java/SunPKCS11 path taught us, likely true for tpm2-pkcs11 as well
(`clients/java/test-softhsm.sh` is the working recipe): a private key **without a certificate is
invisible** in a SunPKCS11 `KeyStore` — write a certificate for the token's public key next to it
(any self-signed one), and the SunPKCS11 configuration needs `attributes = compatibility`, otherwise
`C_DeriveKey` produces a secret the token marks `CKA_SENSITIVE` and the agreement fails with
`CKR_ATTRIBUTE_SENSITIVE`. The Python client sets the derived-key template itself and needs neither.
All four client libraries open both envelope types and generate both kinds of key pair
(`python -m aps_vault keygen --gost`, `generateKeyPair({ gost: true })`, `GenerateGostKeyPair()`,
`generateGostKeyPair()`); their tests decrypt an envelope produced by the server for a fixed key
(`clients/fixtures/gost-sealed.json`) and reproduce every standard test vector involved —
`clients/GOST-PORTING.md` is the specification they follow. The Python client needs
`pip install 'aps-vault[gost]'` (the MIT `gostcrypto` package for Streebog); Node, Go and Java
carry their own Streebog, Kuznyechik, MGM and curve code with no dependencies. As with the
rest of the GOST suite: conformance by algorithm, not a certified module (`docs/GOST.md`).

## Setting it up

1. **Generate the key pair on the application side** — the private key never leaves it:

   ```bash
   python -m aps_vault keygen                 # Python client (add --gost for a GOST R 34.10-2012 pair → GOST envelope)
   node -e "console.log(require('@aps-vault/client').generateKeyPair())"
   # Go: vault.GenerateKeyPair()   Java: VaultClient.generateKeyPair()
   ```

2. **Issue the token with the public key**: Tokens → New token → *Sealed delivery* → paste the
   public key — or skip steps 1–3 with **enrolment** (`docs/ENROLLMENT.md`): a one-time code and
   the node does the rest with one command. Manually: paste the
   public key (API: `POST /api/tokens {"client_public_key": "<b64>"}`; a malformed key is 422).
   The token list shows a *sealed* badge. The binding is fixed for the token's life — a new key
   means a new token, which is the point.

3. **Give the application the token and the private key** (environment, a secrets file with
   0600, the platform's secret store):

   ```python
   v = Vault(url, token, client_private_key=os.environ["VAULT_CLIENT_KEY"])   # pip install 'aps-vault[sealed]'
   v.get("db-password")                                                       # decrypted in-process
   ```
   ```ts
   const v = new Vault({ baseUrl, token, clientPrivateKey: process.env.VAULT_CLIENT_KEY });
   ```
   ```go
   c, _ := vault.New(url, token, vault.Options{ClientPrivateKey: os.Getenv("VAULT_CLIENT_KEY")})
   ```
   ```java
   new VaultClient(url, token, Duration.ofMinutes(5), Duration.ofSeconds(5), 3, true, System.getenv("VAULT_CLIENT_KEY"));
   ```
   All four read `VAULT_CLIENT_KEY` by default. Without a key the client refuses a sealed
   response with a clear error instead of handing the envelope back as a "value"; with the
   wrong key it says so. The Python client needs the optional `cryptography` extra; Node, Go
   and Java use their standard libraries (`node:crypto`, `crypto/ecdh`, JDK XDH).

## Verified

`backend/tests/test_sealed.py` — no plaintext in the response body, decryption with the bound
key (value, login, notes, live TOTP), refusal with another key, with another secret's name as
AAD and with a flipped ciphertext byte, fresh ephemeral key per response, sealed older versions,
KV facade 403, plain token in the same folder unaffected, malformed public keys 422.
`test_python_client.py` runs the stdlib client against a live server over a sealed token.
The Node, Go and Java tests open the **same envelope produced by the server code** (a fixture
for a fixed key), so the HKDF / info / AAD details agree across implementations, and the
browser check creates a sealed token in the UI and decrypts a live response with the Node client.

## For the ValoCloud / IQR core

The core's Java side can take `VaultClient` as is: a key pair at install time, the public half
into the token, the private half next to the token in the node's configuration. A dump of the
proxy chain, the balancer or the token itself then yields nothing readable.
