# APS Vault

A self-hosted secrets manager for one team: a web UI for humans, a machine API with
folder-scoped service tokens for services and AI agents, and nothing that phones home.

[Русская версия](README.ru.md) · [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) ·
[Deployment](docs/DEPLOYMENT.md) · [Observability](docs/OBSERVABILITY.md) · [Access policies](docs/ACCESS-POLICIES.md) · [HashiCorp/Stronghold compatibility](docs/COMPATIBILITY.md) · [Security](SECURITY.md) · [Security review 05.10.2026](docs/SECURITY-REVIEW-2026-10-05.md) · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)

## What it is, honestly

APS Vault is for a handful of people, dozens of services and AI agents, and one server. It started as "a few
thousand lines you can read in an evening"; it is not that any more. Today the server is about **12 600 lines of
Python in 38 modules** (the largest, `api_auth.py`, is 950; `main.py` only assembles the app — [modules](docs/ARCHITECTURE.md#backend-modules-0417)), the web UI **3 600 lines** of
vanilla JavaScript, with **6 200 lines** of backend tests, four client libraries, an update agent and an MCP server
around it. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and then the module you care about.

Three things to know before you trust it with anything:

- **The server sees plaintext while it serves a request.** Values are encrypted at rest under keys derived from the
  master password, but an unlocked server decrypts them to answer. Sealed delivery protects the path to your
  application, not the server itself; whoever controls a running server can read secrets.
- **No independent audit yet.** Our own white-box reviews and their fixes are public
  ([02.10](docs/SECURITY-REVIEW-2026-10-02.md), [05.10](docs/SECURITY-REVIEW-2026-10-05.md)), each fix with a
  regression test — that is not a substitute for someone else's audit.
- **It has many features; you need few.** Start with the profile below and add a feature when you have the problem
  it solves.

## The recommended profile

| Start with | Add when you need it |
|---|---|
| the default `aes` suite | `gost` — experimental, not hardened against side channels ([docs/GOST.md](docs/GOST.md)) |
| one node on SQLite, release images via `install.sh`, updates by a click | a cluster on PostgreSQL ([docs/CLUSTER.md](docs/CLUSTER.md)) |
| a TLS reverse proxy in front | mTLS, where-and-when policies ([docs/ACCESS-POLICIES.md](docs/ACCESS-POLICIES.md)) |
| a folder and a read-only token per service | named users with roles, SSO, security keys ([docs/USERS.md](docs/USERS.md)) |
| encrypted backups to S3, private key kept off the server | HSM / cloud KMS for the master key ([docs/HSM.md](docs/HSM.md), [docs/KMS.md](docs/KMS.md)) |
| the recovery code written down and stored offline | sealed delivery, node enrolment, rotation, token watch, Terraform/Kubernetes/CI |

## The path: install → store → connect → recover

These are the steps a new installation goes through, and they are a test: `ops/checks/golden-path.sh <version>`
runs exactly them against the published release images and the PyPI package — 38 checks, each positive one next to
a negative one (a wrong init token, a token outside its folder, a revoked token, a foreign backup key, a second
restore, a wrong recovery code) — and the release workflow runs it on every tag.

### 1. Install

```bash
git clone https://github.com/kzhebenev/aps-vault.git && cd aps-vault
deploy/images/install.sh /opt/aps-vault latest https://vault.example.com   # the newest release; prints the init token
```

`install.sh` writes `/opt/aps-vault/{docker-compose.yml,.env}` with fresh random tokens and starts the backend, the
web UI on `127.0.0.1:8087` and the update agent (Settings → Updates: the agent checks the release and its Sigstore
signatures, backs up, updates and rolls back if needed — [docs/UPDATES.md](docs/UPDATES.md)). Point a TLS reverse
proxy at `127.0.0.1:8087`: cookies are `Secure`, and a browser over plain HTTP gets nowhere.

Open the address, enter the init token, choose a **master password** (≥ 12 characters) and **write down the
recovery code** — it is shown once and is the only way back if the master password is forgotten.

### 2. Store a secret

In the UI: create a folder per service (`billing`), add a secret (`db-password`). The same through the API, as the
test does it:

```bash
curl -c jar -X POST $VAULT/api/auth/unlock -H 'Content-Type: application/json' -d '{"master_password":"…"}'   # → csrf_token
curl -b jar -X POST $VAULT/api/folders -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"name":"billing"}'
curl -b jar -X POST $VAULT/api/secrets -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"folder_id":1,"name":"db-password","value":"…","login":"billing"}'
```

### 3. Connect a service

Issue a token for the folder (UI: Tokens → New token; read-only by default) and give it to the service:

```bash
curl -s -H "Authorization: Bearer vlt_…" https://vault.example.com/api/v1/m/secret/db-password
# {"name":"db-password","value":"…","login":"billing","updated_at":"…"}
```

```python
# pip install aps-vault
from aps_vault import Vault
password = Vault("https://vault.example.com", os.environ["VAULT_TOKEN"]).get("db-password")
```

The token reads its folder and nothing else; it cannot write unless you allowed it. **Revoking** a token (or
re-keying the folder) takes effect on the server at once — the next request gets 401. Know what the clients do on
their side: they cache a value for 5 minutes, and while the vault is *unreachable* they keep serving the cached value
for at most 24 hours after it was fetched (`max_stale`), so a vault restart never takes a service down. A 401/403 is
never answered from the cache. So a revoked token stops working at the client's next fetch; a rotated value reaches
the service within the cache time — restart the service if it must be sooner. Go, Node, Java: [Clients](#clients).

### 4. Recover

**Turn backups on first** — Settings → Backups to S3: put the S3 settings into `.env`
(`VAULT_BACKUP_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY`), generate a key pair, **save the private key somewhere
other than this server**, choose "on every change". Each copy is sealed to the public key; the server cannot read
its own backups. [docs/BACKUP.md](docs/BACKUP.md).

**The server is lost.** On a new machine:

```bash
deploy/images/install.sh /opt/aps-vault latest https://vault.example.com     # do NOT initialise it
cd /opt/aps-vault && cat >> .env <<'ENV'                                        # the same S3 settings
VAULT_BACKUP_S3_ENDPOINT=https://s3.example.com
VAULT_BACKUP_S3_BUCKET=…
VAULT_BACKUP_S3_ACCESS_KEY=…
VAULT_BACKUP_S3_SECRET_KEY=…
ENV
IMG=ghcr.io/kzhebenev/aps-vault/backend:$(sed -n 's/^VAULT_VERSION=//p' .env)
docker run --rm --env-file .env $IMG python -m backup list                      # the newest copy is last
docker run --rm --env-file .env $IMG python -m backup fetch <key> > latest.vbak
docker run --rm -v "$PWD:/w" $IMG python -m backup decrypt /w/latest.vbak --key /w/backup-key.txt > dump.json   # the saved private key
docker compose stop backend
docker compose run --rm -T -v "$PWD:/w" backend python -m backup restore /w/dump.json
docker compose up -d && shred -u dump.json                                      # dump.json has names and audit in clear
```

Unlock with the old master password. Services keep their tokens — only the address changed, if it did. A token
revoked before the loss stays revoked. `restore` refuses a database that is already initialised (`--force` wipes it);
`python -m backup env dump.json` gives back the rest of the old `.env` if the backup carried it.

**The master password is forgotten.** On the unlock screen choose "Recover with the recovery code" (API: `POST /api/auth/recover
{recovery_code, new_master_password}`): the master key is re-wrapped under the new password, nothing is re-encrypted,
services do not notice, and you get a new recovery code — write that one down.

**An update went wrong.** The update agent backs up the data before every update and rolls back by itself when the
new version does not come up healthy ([docs/UPDATES.md](docs/UPDATES.md)).

## Everything else, when you need it

- **Encryption that stays encrypted.** Argon2id derives a master key from a master password;
  every folder has its own random key wrapped by the master key; every value is AES-256-GCM
  with a fresh nonce. The database is useless without the master password or a token.
- **Folder-scoped service tokens.** A token unlocks exactly one folder and nothing else, and
  it works even while the vault is locked, because the token carries its own wrapped copy of
  the folder key. Read-only by default; `notes`, `totp` and `write` are opt-in per token.
- **Machine API first.** `GET /api/v1/m/secret/<name>` with a Bearer token is all a service
  needs. There is a CLI, a Python and a Node client, an MCP server for AI agents, and a browser
  extension.
- **Post-quantum ready.** The sealed envelope can be the **X25519 + ML-KEM-768 hybrid** (FIPS 203)
  or, for GOST deployments, the **GOST R 34.10-2012 + ML-KEM-768 hybrid** with Kuznyechik-MGM on the
  wire: a classical and a lattice key agreement feed one key, so recorded traffic stays closed to a
  quantum computer later. All four clients open both.
- **Sealed delivery.** Bind a token to the application's X25519 public key and values leave
  the vault encrypted to it: nothing on the path reads them and a stolen token alone is
  useless. The clients decrypt in-process. See [docs/SEALED.md](docs/SEALED.md).
- **Node enrolment.** Issue a one-time code; the node makes its own key pair and fetches a
  sealed token with one command — no tokens copied by hand. The key pair can live inside a TPM or
  any PKCS#11 token (P-256), so it never leaves the device. See [docs/ENROLLMENT.md](docs/ENROLLMENT.md).
- **Hardware token for the master key.** Wrap the master key inside a PKCS#11 token (HSM or
  SoftHSM2; GOST mechanisms configurable for CryptoPro / Rutoken HSM) and unlock with its PIN;
  the wrap key never leaves the token. See [docs/HSM.md](docs/HSM.md).
- **GOST algorithms, if you need them.** `VAULT_CIPHER=gost` runs the whole vault on
  Kuznyechik-MGM, Streebog and KDF_TREE (GOST R 34.12/34.11-2012, RFC 9058), and a GOST R 34.10
  client key gets sealed delivery over VKO + Kuznyechik-MGM in all four clients — verified against
  the standards' test vectors; conformance by algorithm, not a certified module. **Experimental:**
  the implementation is not hardened against side channels, so `aes` remains the recommended
  profile for production. See [docs/GOST.md](docs/GOST.md).
- **Encrypted backups to S3.** On every change (or hourly) plus a daily full copy, sealed to a key that is not on the
  server (post-quantum hybrid by default), with the environment settings inside; restores into SQLite or PostgreSQL. See [docs/BACKUP.md](docs/BACKUP.md).
- **Cloud KMS for the master key.** AWS KMS or Yandex Cloud KMS as the wrapping key; with a
  PIN the master key is also wrapped locally under Argon2id(PIN), so cloud credentials alone open
  nothing and the PIN never reaches the provider's logs; without one the cell serves SSO for a whole cluster. See [docs/KMS.md](docs/KMS.md).
- **Security keys and biometrics.** YubiKey, Touch ID, Windows Hello, Android via WebAuthn.
  With the PRF extension the master key is wrapped under the authenticator's secret and
  unlock is one touch; without it the key is a second factor.
- **Users with TOTP, managers who grant, folder keys you can rotate.** One-time codes on a user's
  password; folder managers give roles on their folders without the owner; the owner re-keys a
  folder after a revocation (tokens of the folder are revoked by name). See [docs/USERS.md](docs/USERS.md).
- **People with roles.** Invite users by e-mail; each gets a role per folder — reader, writer
  or manager — and sees nothing else. Folder keys reach them sealed to their own key pair, so
  the database still holds no plaintext key and the owner never learns their password. The audit
  log names the person. See [docs/USERS.md](docs/USERS.md).
- **Read approval.** A flagged secret is read by a person only after a second person
  confirms from a link — no account, just an approver password; notified through any
  webhook. See [docs/APPROVALS.md](docs/APPROVALS.md).
- **Machine-only secrets.** Flag a secret and no person ever sees its value — not in the card,
  history, export or a share link; the server can generate and rotate it, only tokens read it.
- **Rotation in the target system.** The vault changes a password *in PostgreSQL* or *MySQL/MariaDB*
  (`ALTER ROLE` / `ALTER USER`), *in an LDAP directory* (`userPassword` / `unicodePwd` through a bind
  account), *on a host over SSH* (`chpasswd` with a pinned host key) or through a signed call to your
  own HTTP receiver — by hand or on a schedule — always with a login as proof and a rollback on
  failure, and stores the new version only after the target accepted it. See [docs/ROTATION.md](docs/ROTATION.md).
- **Bring your secrets with you.** Import from Bitwarden / Vaultwarden, KeePass (XML or the `.kdbx` itself),
  1Password, LastPass, Dashlane, Keeper, Passbolt, Passwork (files or its API), CSV, `.env` files or a live
  HashiCorp Vault / Stronghold mount — with a preview before anything is written. See [docs/IMPORT.md](docs/IMPORT.md).
- **Kubernetes, Ansible, Terraform.** The External Secrets Operator syncs secrets into Kubernetes
  Secrets through its standard `vault` provider (we speak the HashiCorp KV v2 dialect) — no custom
  controller; Ansible reads secrets with the `aps_vault` lookup plugin; Terraform / OpenTofu read and
  manage secrets with the `apsvault` provider. See [docs/KUBERNETES.md](docs/KUBERNETES.md),
  [clients/ansible](clients/ansible/README.md) and [docs/TERRAFORM.md](docs/TERRAFORM.md).
- **Pipelines.** A GitHub Action and a GitLab CI template turn secrets into masked environment
  variables for the following steps, with a read-only folder-scoped token. See [docs/CI.md](docs/CI.md).
- **Versions for key rotation.** Every value change is a numbered version; the machine API and
  the HashiCorp facade read `?version=N`, so a service can decrypt old files with the old key
  while new files already use the new one.
- **TOTP inside.** Store a 2FA seed next to a password and get the current code from the API.
- **Audit everything.** Every unlock, read, write, token use and share-link open is logged
  with IP and user agent.
- **Recoverable.** A one-time recovery code re-wraps the master key without re-encrypting
  data. Optional TOTP second factor on the master password. Optional OIDC login (Keycloak and
  any other OpenID Connect provider) on top; only accounts listed in `VAULT_OIDC_OWNERS` sign in as the owner.
- **A web UI built for the daily loop.** List + detail with deep links, ⌘K palette and
  keyboard navigation, dark/light/system theme, password generator (random or passphrase)
  with an honest entropy estimate, breach check against Have I Been Pwned without sending
  the password (k-anonymity), a health report (weak, reused, overdue, stale), rotation
  deadlines, live TOTP, drag-and-drop of credentials, one-time share links, value history,
  JSON export/import. Responsive down to a phone. [docs/COMPARISON.md](docs/COMPARISON.md)
  puts it next to Bitwarden, 1Password, Passbolt, HashiCorp and Infisical.
- **Token watch.** Each token learns where it is used from and how; a new network, two places at
  once, a rate spike or an enumeration raises an alert (audit, webhook, notifier) or freezes the
  token; canary tokens trip on any use; a scanner finds leaked tokens in repositories by hash.
  See [docs/TOKEN-WATCH.md](docs/TOKEN-WATCH.md).
- **Where-and-when policies.** A token (or the whole UI) can be limited to source networks
  and time windows; a stolen token used elsewhere is refused and reported.
- **Observability.** Audit events to syslog/SIEM (JSON or CEF), Prometheus `/metrics`,
  a fail2ban-ready security log with filter and jail generator.
- **HashiCorp Vault / Deckhouse Stronghold compatible API** (`/v1/<folder>/data/<name>`,
  `LIST`, `lookup-self`, `X-Vault-Token`): `hvac` and the `vault` CLI work unchanged, so a team
  can start on APS Vault and move to Stronghold or HashiCorp later by changing the address —
  see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
- **English and Russian UI.**

![main screen](docs/img/main.png)

<p>
<img src="docs/img/detail-light.png" width="49%" alt="secret card, light theme">
<img src="docs/img/health.png" width="49%" alt="health report">
</p>

## Build from source

```bash
cp .env.example .env            # public URL, allowed origins, init token
mkdir -p data && chown 10001:10001 data
docker compose up -d --build    # then the same path as above, from step 1's "Open the address"
```

## Packages

Python: `pip install aps-vault` (PyPI, published by the release workflow with attestations; `aps-vault[pqc]` for the
post-quantum envelope). Until the other registry accounts are live (`docs/PUBLISHING.md`), install the rest from the
repository (`npm install ./clients/node`, `go get github.com/aps-vault/aps-vault/clients/go`, the single-file Java client). Each GitHub Release carries the built packages, SPDX SBOMs, Sigstore
signatures and SLSA build-provenance attestations (`gh attestation verify … --owner kzhebenev`);
container images: `ghcr.io/kzhebenev/aps-vault/backend`, `…/frontend` and `…/updater` (the update agent, 0.38).

## Clients

| Client | Where | Notes |
|---|---|---|
| Python | `clients/python/` | standard library only, 3.9+ (`cryptography` extra for sealed delivery) |
| Node | `clients/node/` | built-in `fetch` and `node:crypto`, Node 20.19+ (`@noble/post-quantum` for the post-quantum envelope) |
| Go | `clients/go/` | standard library only, 1.24+ (crypto/mlkem for the post-quantum envelope) |
| Java | `clients/java/` | `java.net.http`, Java 11+, single file (Java 24+ for the post-quantum envelope) |
| CLI `vault get/put/list` | `ops/vault-cli.sh` | token from `VAULT_TOKEN`, `~/.vault-token` or `/etc/vault.conf` |
| MCP server | `mcp/` | stdio transport; `health / list / get / put` within its token's folder, and `use` — a request made *with* a secret the agent never sees, bound to the secret's host ([docs/MCP.md](docs/MCP.md)) |
| Browser extension | [aps-vault-extension](https://github.com/kzhebenev/aps-vault-extension) | Chrome/Firefox MV3: autofill, TOTP, search palette |

All clients: in-memory cache, retries with back-off, stale-cache fail-open so a vault restart
never takes your service down (for at most 24 h after the fetch by default, `max_stale`), token-shape check so a master password cannot be pasted by
mistake, sealed delivery (key pair generation and in-process decryption). See [examples/](examples/).

## Cluster

Several replicas behind a load balancer on one PostgreSQL behave as one vault: sessions,
lock-outs and the master-key verifier live in the database, the master key travels wrapped
inside the session (unwrapping key only in the client's cookie). `deploy/cluster/` is the
reference deployment, `docs/CLUSTER.md` explains it, `./run_tests.sh pg` proves it on
PostgreSQL 16 with two real nodes.

## What it is not

- Not a directory: one owner holds the master password and administers everything; named
  users (0.20) get roles per folder but do not manage folders, users or settings. Users sign in
  with a password, a security key (Touch ID, YubiKey) or through SSO.
- Not a distributed database: a single node is one process and one SQLite file (`ops/backup.sh`);
  a cluster is identical replicas on one PostgreSQL that you operate and back up.
- Not a KMS: it stores secrets, it does not sign or encrypt your data for you. It can keep its
  own master key in a KMS or an HSM, and it can deliver secrets sealed to your application's key.

UI and API are in English and Russian (the UI follows the browser language; switch in the header).

## Status

Used in production by its authors since June 2026 for a few hundred secrets and a few dozen
service tokens. Security reviews: [docs/SECURITY-REVIEW-2026-10-02.md](docs/SECURITY-REVIEW-2026-10-02.md) (code of 0.4) and
[docs/SECURITY-REVIEW-2026-10-05.md](docs/SECURITY-REVIEW-2026-10-05.md) — a white-box review of 0.36 with SAST, SCA and DAST;
0.37 fixes its 38 findings (1 critical, 5 high), each with a regression test that fails on 0.36, and ships
`ops/checks/dast.py`, live role and boundary checks you can run against your own stand. **Upgrading from 0.36 or
older: read the breaking changes of 0.37.0 in [CHANGELOG.md](CHANGELOG.md)** (OIDC owner list, clients refuse
plaintext with a key, flags lifted by the owner only). See [SECURITY.md](SECURITY.md) for the threat model and how
to report issues.

## License

MIT — see [LICENSE](LICENSE).
