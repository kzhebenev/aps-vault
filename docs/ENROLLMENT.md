# Node enrolment (0.21)

Until 0.20 a service token travelled by hand: the administrator issued it in the UI, copied it
into the installer, and if the token was to be sealed (`docs/SEALED.md`) the node's public
key had to travel the other way first. For one node that is fine; for a cluster installer it
is the step that gets scripted badly.

Enrolment turns it into one command on the node:

```
administrator:  Tokens → Node enrolment code → folder, name prefix, validity, number of nodes   →   enr_…  (shown once)
node:           python3 -m aps_vault enroll https://vault.example.com enr_… --out /etc/app/vault
                → makes its own key pair, presents the code and the public key, receives a token sealed to that key,
                  stores /etc/app/vault/vault.token and vault.key with mode 0600
```

With `--pkcs11 <module>:<token>:<pin>[:<label>]` (0.22) the key pair is created **inside** a PKCS#11
token — a TPM 2.0 through tpm2-pkcs11, an HSM, a smart card — and the private key never leaves it
(`docs/SEALED.md`, "P-256 envelope"). The same call exists in every client library — `enroll()` in Python and Node, `Enroll()` in
Go, `VaultClient.enroll()` in Java — so an installer in any language can do it without the
Python CLI. The private key never leaves the node; the administrator never sees a token; the
code is useless after its uses are spent or its time is up.

## What the code is

An enrolment is a row with the folder, the token options the issued tokens will carry (name
prefix, notes / TOTP grants, expiry, where-and-when policy), a use counter and an expiry. The
folder key is stored encrypted under a KDF of the code itself — the share-link construction —
so a node can enrol while the vault is locked and no administrator is around. The code is a
bearer credential for *issuing sealed tokens on that folder*, limited by:

- **validity** — 15 minutes to 7 days (`ttl_minutes`);
- **uses** — 1 for a single node, N for a group of identical nodes (`max_uses`; each use is
  one atomic decrement, two nodes cannot share the last slot);
- **source networks** — `allowed_cidrs` applies to the enrolment call *and* becomes the
  policy of every issued token;
- **revocation** — a code can be revoked before it is spent.

Issued tokens are always sealed to the key the node presented: a code intercepted on the way
gives the interceptor a token sealed to *their* key, which is exactly as much as the code
itself was worth — nothing beyond its uses and lifetime. Wrong, spent, expired and revoked
codes count against the caller's failed-attempt budget (5 per 15 minutes → 429), and every
attempt is in the audit log (`enroll:issue`, `enroll:fail`).

A folder **manager** (0.20) may issue codes for their folder; the owner for any folder.

## API

```http
POST   /api/enrollments      {folder_id, name_prefix="node", ttl_minutes=60, max_uses=1, expires_days?, can_read_notes?, can_read_totp?, allowed_cidrs?, allowed_hours?}
       → {id, code, folder_name, expires_at, max_uses, command}          session (owner or manager); the code is shown once
GET    /api/enrollments      → [{id, folder_id, folder_name, name_prefix, max_uses, used_count, created_by, expires_at, revoked, active, options}]
DELETE /api/enrollments/{id} → revoke

POST   /api/enroll           {code, public_key (base64: 32 B X25519 or 64 B GOST R 34.10), name?}       public, CSRF-exempt
       → {raw_token, token_name, folder_name, sealed: true, cipher, vault_url}
       404 unknown / revoked / expired · 410 spent · 403 source address · 422 malformed key · 429 lock-out
```

The token is named `<prefix>-<name>` (the node's host name by default); a clash gets `-2`,
`-3`. The audit log records `enroll:create` (who issued the code), `enroll:issue` (which node
took a token, from where) and `enroll:fail`.

## In the clients

```python
from aps_vault import enroll, Vault
r = enroll("https://vault.example.com", code, name="app-01")            # add gost=True for a GOST pair
v = Vault(r["vault_url"], r["token"], client_private_key=r["private_key"])
```
```ts
const r = await enroll('https://vault.example.com', code, { name: 'app-01' });
```
```go
e, err := vault.Enroll(ctx, "https://vault.example.com", code, "app-01", false)
```
```java
String[] e = VaultClient.enroll("https://vault.example.com", code, "app-01", false);   // {token, privateKey, publicKey, tokenName, folderName}
```

Store `token` and `private_key` with mode 0600 and hand them to the application through
`VAULT_TOKEN` / `VAULT_TOKEN_FILE` and `VAULT_CLIENT_KEY`. The Python command line does that
with `--out <dir>`.

## Verified

`backend/tests/test_enroll.py`: an issued code enrols an X25519 node and a GOST node, the
tokens read the folder sealed, options shape the tokens, names de-duplicate, the third use of
a two-use code is 410, revoked and expired codes are 404, a source-address policy refuses,
a reader cannot issue codes, a manager can for their folder only. The Python client enrols
against a live server; the Node, Go and Java clients against a fake one; the browser check
issues a code in the UI and enrols a "node" through the Node client.
