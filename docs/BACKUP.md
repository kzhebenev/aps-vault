# Encrypted backups to S3 (0.39)

**Settings → Backups to S3** uploads the vault's database to any S3-compatible storage (AWS S3, Yandex Object Storage,
Ceph RGW, MinIO, …), encrypted to a public key whose private half is **not on the server**.

## What is in a backup

A logical dump of every application table — folders, secrets (values stay ciphertext under the folder keys), history,
tokens (hashes), users and grants, settings and cells, share links, webhooks, rotations, approvals, the audit log —
as JSON, gzip, sealed to the recipient key. It restores into **SQLite or PostgreSQL** alike. Not included: UI
sessions, WebAuthn challenges, lock-outs, TOTP replay steps, update jobs and the backup's own bookkeeping.

Also not included: whatever lives only in the environment — `VAULT_SSO_UNLOCK_KEY`, `VAULT_ROTATION_KEY`, HSM / KMS
credentials, the S3 keys. Keep them in your secret store; without them the restored vault still opens with the master
password, only the SSO / rotation / HSM / KMS cells wait for their keys.

## Encryption

The dump is sealed with the vault's own envelope to the recipient's public key: by default the **post-quantum hybrid
X25519 + ML-KEM-768** (a backup lives for years — "harvest now, decrypt later" matters), on a GOST vault the GOST hybrid
(VKO GOST R 34.10-2012 + ML-KEM-768 → Kuznyechik-MGM). X25519, P-256 and GOST keys are accepted too. The object's header
(time, version, recipient fingerprint, checksum) is bound to the ciphertext as AAD: changing any of it makes the
backup unreadable instead of misleading.

What this gives you: a copy of the bucket, of the database or of the whole vault host does **not** open a backup. Only
the private key does — keep it offline (a password safe, a hardware token, paper in a safe), never next to the vault.

### The key

- **Create a key** (Settings → Backups): the server makes the pair, keeps the public half and shows the private one
  **once** (copy / download). Convenient; the server had the private key in memory for that moment.
- **Own key** (recommended for production): make the pair where the vault is not, paste only the public half:

  ```bash
  pip install 'aps-vault[pqc]'      # or clients/python from this repository
  python3 -c "import aps_vault; sk, pk = aps_vault.generate_keypair('pqc'); print('PRIVATE', sk); print('PUBLIC', pk)"
  ```

Both need the master password. A new key applies to the next backups; older objects open with the older key — keep
it until those objects expire.

## When

| Mode | What happens |
|---|---|
| **On change** (default, recommended) | every minute one replica dumps the database and compares a hash of the *state* (without the audit log, token-watch counters and read counters — reads are not changes). Changed → one upload; edits within a minute make one object |
| **Hourly** | at most once an hour, only when changed |
| **Daily** | — |

In every mode a **full copy once a day** is uploaded even without changes: it carries the audit log and proves the
pipeline is alive. **Back up now** makes a full copy at once. Several replicas share the work through a lease in the
database: one upload per tick, not one per replica.

Object names: `<prefix>YYYY/MM/DD/aps-vault-YYYYMMDDTHHMMSS.mmm-<node>-<random>.vbak` — never overwritten.

## Settings

S3 credentials live in the **environment**, not in the database: backups run while the vault is locked, and a database
dump must not carry the key to its own bucket.

| Variable | Meaning |
|---|---|
| `VAULT_BACKUP_S3_ENDPOINT` | `https://s3.amazonaws.com`, `https://storage.yandexcloud.net`, `https://s3.example.ru` … (https and a public address, as every outbound call; private / http only with `VAULT_WEBHOOK_ALLOW_PRIVATE=1`) |
| `VAULT_BACKUP_S3_BUCKET` | bucket name (path-style requests) |
| `VAULT_BACKUP_S3_PREFIX` | folder inside the bucket, default `aps-vault/` |
| `VAULT_BACKUP_S3_REGION` | SigV4 region, default `us-east-1` (Ceph RGW and MinIO accept any) |
| `VAULT_BACKUP_S3_ACCESS_KEY`, `VAULT_BACKUP_S3_SECRET_KEY` | the key; `*_FILE` variants work (Swarm / Kubernetes secrets) |
| `VAULT_BACKUP_TICK_SEC` | how often a replica looks (60 s; 0 = scheduler off, manual backups still work) |

**Harden the bucket.** The vault needs only `s3:PutObject` on the prefix. A key without Get / Delete / List, plus
bucket versioning or an object lock (and a lifecycle rule for retention), means a compromised vault host cannot erase
or replace past backups. With a full-access key it can. The vault never deletes objects — retention is the bucket's
lifecycle rule.

## Restore

The tool ships in the backend image (`python -m backup`):

```bash
# 1. get the object (or download it with any S3 client)
docker compose exec backend python -m backup list                        # needs List permission
docker compose exec backend python -m backup fetch aps-vault/2026/10/05/aps-vault-….vbak > latest.vbak

# 2. decrypt — on a machine that has the private key, not necessarily the vault host
docker run --rm -v "$PWD:/w" ghcr.io/kzhebenev/aps-vault/backend:<version> \
  python -m backup decrypt /w/latest.vbak --key /w/backup-key.txt > dump.json

# 3. restore into an EMPTY database (a new installation before initialisation; SQLite or PostgreSQL)
docker run --rm -v "$PWD:/w" -v vault-data:/app/data ghcr.io/kzhebenev/aps-vault/backend:<version> \
  python -m backup restore /w/dump.json                                  # or -e VAULT_DATABASE_URL=postgresql+psycopg://…
```

Then start the vault on that database and unlock with the **master password** of the backed-up vault. `restore`
refuses an initialised database unless `--force` (which wipes the restored tables first). On PostgreSQL the id
sequences continue after the restored rows. `dump.json` holds metadata in clear (names, e-mails, audit) — delete it
after the restore.

## API (owner)

```http
GET  /api/backup/status          → {s3{configured, missing[], endpoint, bucket, prefix}, enabled, mode, key{set, fingerprint, kind},
                                    last_ok_at, last_full_at, last_error, runs[]}
PUT  /api/backup/config          {enabled?, mode?: change|hourly|daily}   409 without a key or S3 settings
PUT  /api/backup/key             {public_key, master_password}
POST /api/backup/keygen          {master_password, kind?} → {private_key (once), public_key, fingerprint, kind}
POST /api/backup/run             → the run {state: ok|failed, object_key, size, sha256, error}
```

Audit: `backup:config`, `backup:key_set`, `backup:keygen`, `backup:ok`, `backup:failed`, `backup:key_fail`,
`backup:keygen_fail`; webhook `backup:failed`.

## Verified how

- `backend/tests/test_backup.py` — a fake S3 that checks SigV4 with its own implementation; nothing readable in the
  object (names, values, table names); the wrong key, a changed header and a changed ciphertext do not open it; reads
  do not upload, writes do (two edits → one object), hourly waits, the daily copy comes anyway, off is off; the lease
  keeps two replicas from uploading together; SignatureDoesNotMatch / AccessDenied end as visible failed runs; a
  restored dump in a separate process opens with the master password and returns the secret's value; a second
  restore into an initialised database is refused.
- `ops/checks/ui-e2e.mjs` — the section in Chrome on AES and GOST: S3 from the environment, enabling without a key is
  refused with a visible reason, the key shown once, mode tiles, a manual copy, the object in the bucket is sealed.
- Live, 05.10.2026, Ceph RGW (`s3.ru-ix1.i4b.ru`): the dev vault uploaded a manual copy (32 KB) and, 10 s after a new
  secret, a change copy; the object was fetched, decrypted with the saved private key and restored into an empty
  SQLite **and** an empty PostgreSQL 16 — both opened with the master password, returned the new secret, refused a wrong
  password, and PostgreSQL continued the id sequence; a different private key could not open the object.
