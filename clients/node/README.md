# @aps-vault/client (Node)

Client for the APS Vault machine API (service tokens). Node 20.19+, built-in `fetch` and `node:crypto`;
the only dependency is `@noble/post-quantum` (ML-KEM-768 for the post-quantum envelope).

```bash
npm install ./clients/node          # or: npm install @aps-vault/client (once published)
```

```ts
import { Vault, VaultError } from '@aps-vault/client';

const v = new Vault({ baseUrl: 'https://vault.example.com', token: process.env.VAULT_TOKEN! });   // or Vault.fromEnv()
const dbPassword = await v.get('db-password');
const smtp = await v.getFull('smtp');        // { name, value, login, notes, totp, updated_at, ... }
```

- `get(name, version?)` / `getFull(name, version?)` — cached for `cacheTtlMs` (default 300 000). While the vault is
  unreachable a stale cached value is returned (`failOpenCache`), so a vault restart never takes your service down;
  the first fetch still fails loudly.
- `put(name, value, { login, tags, url })` — token needs `can_write`.
- `totp(name)` — current 6-digit code, never cached; token needs `can_read_totp`.
- `versions(name)`, `list()`, `health()`.
- Retries 429/5xx/network with 1 s, 2 s, 4 s back-off. Nothing is logged; `VaultError` carries `status` and the server's detail.

Tokens: pass via environment (`VAULT_TOKEN`) or a `0600` file. Never commit one, never log one. `Vault` refuses
anything that does not look like a service token (`vlt_…`).

## Sealed delivery

If the token is bound to this application's public key, values arrive encrypted and the client decrypts them
in-process — pass `clientPrivateKey` (or set `VAULT_CLIENT_KEY`). `generateKeyPair()` makes the pair, `enroll()`
makes one and redeems a one-time enrolment code in one step. Four envelopes, selected by the key the token is bound to:

| `generateKeyPair(...)`   | envelope                                       | vault | key sizes (private / public)             |
|--------------------------|------------------------------------------------|-------|------------------------------------------|
| `()`                     | X25519 → HKDF-SHA256 → AES-256-GCM             | 0.17+ | 32 / 32 bytes                            |
| `({ gost: true })`       | VKO GOST R 34.10-2012 → KDF_TREE → Kuznyechik-MGM | 0.19+ | 32 / 64 bytes (X‖Y)                      |
| `({ p256: true })`       | P-256 ECDH → HKDF-SHA256 → AES-256-GCM (TPM / PKCS#11 via `KeyProvider`) | 0.22+ | 32 / 65 bytes (0x04‖X‖Y) |
| `({ pqc: true })`        | X25519 + ML-KEM-768 hybrid → HKDF-SHA256 → AES-256-GCM | 0.27+ | 96 / 1216 bytes                   |

Without the key the client throws `VaultError('… sealed values …')` rather than returning the envelope; with the
wrong key or a tampered envelope it says `… does not open with this private key …`. See `docs/SEALED.md`.

### Post-quantum hybrid (0.27)

`generateKeyPair({ pqc: true })` (or `enroll(url, code, { pqc: true })`) makes an X25519 + ML-KEM-768 (FIPS 203) pair:
the private key is 96 bytes — X25519 sk (32) ‖ ML-KEM seed d‖z (64) — and the public key sent to the vault is 1216
bytes — X25519 pk (32) ‖ ML-KEM encapsulation key (1184). The ML-KEM half is derived deterministically from the seed,
so `pqcPublicFromPrivate(privateKey)` re-creates the public key, and the same 96 bytes work in every client port.
Opening an envelope needs both halves: the AES key is HKDF-SHA256 over the X25519 shared secret **and** the ML-KEM
shared secret, so an attacker must break both. The vault must be 0.27+ (with `kyber-py` installed) to accept a
1216-byte key; older vaults reject it at token creation.

```ts
import { generateKeyPair, pqcPublicFromPrivate } from '@aps-vault/client';
const { privateKey, publicKey } = generateKeyPair({ pqc: true });   // keep privateKey 0600 → VAULT_CLIENT_KEY; publicKey → the token
pqcPublicFromPrivate(privateKey) === publicKey;                     // true
```

## Tests

```bash
npm run build && node --test test/client.test.mjs
```

The suite opens the server-produced fixtures in `clients/fixtures/` (X25519, GOST, P-256, PQC) and refuses
tampered envelopes, wrong keys and wrong names.
