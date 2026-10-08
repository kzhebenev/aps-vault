# Changelog

All notable changes. Dates are release dates.

## 0.41.11 — 2026-10-08

- **The update agent asks GitHub for one release, not the list.** It read `releases?per_page=30` — ~2 MB with the notes
  and assets of 30 releases — to find the target tag; a cut-off answer ("Unterminated string") made it refuse an
  update (dev, 08.10, succeeded on the second try). On the GitHub API it now fetches `/releases/tags/v<version>`
  (~75 KB; 404 → "not a published release") and retries a dropped answer once. A mirror channel keeps the list format.

## 0.41.10 — 2026-10-08

- **The networks and hours of an existing token can be changed** — `PATCH /api/tokens/{id}` with `allowed_cidrs` /
  `allowed_hours` (`""` lifts the limit), audited as `token:update`. Before, the endpoint changed only `on_anomaly` and
  **silently dropped every other field with 200**: a production token "narrowed" to the tenant's network kept working
  from anywhere, and only a request from outside showed it. Unknown fields are now a 422.
- The machine API takes `tags` as a list too (`["a","b"]` → `a,b`); a list used to be a 422.

## 0.41.9 — 2026-10-08

Security fixes found by auditing every `kind == "owner"` check after agent keys (each with a test that failed first):

- **A writer could move a 'machines only' / 'requires approval' secret into a folder that has a token** — and read the
  value through that token. Moving a flagged secret between folders is now the owner's, in person. This affected named
  users with write access to two folders since 0.37, not only agent keys.
- An agent key passed the owner-only checks that keep flagged values away: issuing a token or an enrolment code for a
  folder with flagged secrets, pointing a flagged secret's rotation at an http receiver (which gets the new value),
  rotation through an administrator credential, and `lock?all=1` (locking the owner out). All require the owner in
  person now.

## 0.41.8 — 2026-10-08

- **Keys for AI agents.** An AI session or an automation can now do the owner's routine work — create folders, issue
  and revoke service tokens, create users and grant roles, read and write secrets, read the audit log — without the
  master password and without a person. The owner issues a key once (Settings → Keys for AI agents, or
  `POST /api/agent-keys`); `POST /api/auth/agent` exchanges it for a session marked `agent:<name>` in the audit log.
  What such a session may call is an allow-list (`authz._AGENT_PATHS`, default deny): never the master password,
  recovery, 2FA/WebAuthn/SSO/HSM/KMS cells, backups and their key, webhooks, export/import, updates, folder-key
  rotation or agent keys themselves (a second lock, `_human_owner_only`). The key wraps the master key under the token
  KDF with a random salt; it is re-checked on every request (revoked or expired → the session ends; allowed networks);
  wrong keys count against the attempt limit; revoking ends every session the key opened. It replaces
  `VAULT_MASTER_PASSWORD` in the environment for automation. docs/AGENT-KEYS.md.
- The confirm dialog's button carries `data-testid="confirm-ok"`; the split modules lost a duplicated
  `from __future__` line.

## 0.41.7 — 2026-10-08

- **`main.py` is split by responsibility.** The 4 200-line module is now `app_core` (app, CORS, security headers, CSRF,
  audit, models), **`authz` — every permission check of the human API in one place** (unlocked session, roles per
  folder, owner-only, attempt limits, TOTP replay), `api_auth`, `api_users`, `api_secrets`, `api_rotation`,
  `api_tokens`, `api_sharing`, `api_ops`, `webhooks`, `version`; `main.py` (110 lines) only assembles them. The largest
  module is 955 lines. The code moved mechanically and verbatim: all 249 top-level definitions are byte-identical to
  0.41.6 except one line (the event loop handle now set on `webhooks`), all 125 handlers hash-identical.
- **`tests/test_route_table.py`** holds the application's contract to the unsplit 0.41.6: 140 routes (the machine API
  included) with methods, handler names and the whole tree of their dependencies, the middleware chain, the order of
  every pair of paths that can match the same request, and every name `main` had (`sdk_api` reaches `main` through
  `__import__("main")`; after the first cut it found no `archive_value`, and the token-watch notifier, behind a broad
  `except`, would have gone silent — the token-watch tests caught it).
- The version lives in `backend/version.py` (CI checks it there); `main.VERSION` still works.

## 0.41.6 — 2026-10-07

- **MCP: `use` — the agent acts with a secret it never sees.** `get` puts the value into the model's context; `use`
  keeps it in the MCP server: the agent describes an HTTPS request with `{{secret}}` / `{{login}}` / `{{basic}}`, the
  server substitutes, sends it and returns the response with the value cut out. The request may go only to the host of
  the secret's own `url` field or to a host in `APS_MCP_USE_HOSTS` (a prompt-injected agent cannot send it to its own
  server), HTTPS only, no redirects followed, no placeholder in the host part; a JSON body is filled inside its
  strings, so the secret stays valid JSON; the vault's audit names the target host. Redaction removes any 8+ character
  run of the value or its encodings — exact-match redaction leaked a partly percent-encoded and a twice-escaped echo in
  the test and was replaced. `APS_MCP_DISABLE_GET=1` turns `get` off for agents that should only `use`.
  `health`, `list_secrets`, `get`, `put` are unchanged. docs/MCP.md.
- The MCP server is now tested through the real protocol: `backend/tests/test_mcp_server.py` runs it with the official
  `mcp` client 1.28.0 (in its own venv — its pins clash with the backend's) against a live vault and HTTPS echo targets.

## 0.41.5 — 2026-10-07

- **README around one path, and the path is a test.** The README now starts with what the project is, honestly — its
  real size (12 300 lines of server Python, `main.py` 4 200, 3 600 lines of UI), that the server sees plaintext while it
  serves a request, that there is no independent audit yet — then a recommended profile (aes, one node on SQLite,
  `install.sh` with updates by a click, encrypted S3 backups with the key off the server, the recovery code offline;
  everything else "when you need it"), then one path: install → store a secret → connect a service → recover (the
  server lost, the master password forgotten, a failed update). What the clients' cache means for revocation and
  rotation is spelled out next to "connect".
- **`ops/checks/golden-path.sh`** executes that path against the published release images and the PyPI package:
  install.sh, init, folder, secret, token, curl and `pip install aps-vault==<version>`, an encrypted backup to S3, the
  installation destroyed, a fresh one restored from `backup list/fetch/decrypt/restore`, the old token reading again,
  the recovery code — 38 checks, each with its negative (wrong init token, a token outside its folder, a read-only token
  writing, a revoked token, a foreign backup key, a second restore, a wrong recovery code, the old master password after
  recovery). The release workflow runs it on every tag (job `golden-path`). `backend/tests/test_readme_path.py` keeps
  the README and the script from drifting: the number of checks, the backup commands, the UI labels, the cache facts.

## 0.41.4 — 2026-10-07

- **The GOST profile is marked experimental.** The `gost` suite matches the standards' test vectors, but its
  implementation is not hardened against side channels: Kuznyechik uses key- and data-indexed lookup tables, and the
  GOST R 34.10 curve arithmetic (server and the four clients) is not constant-time. The comment in `gostec.mul` that
  compared it to the X25519 libraries was wrong — those are constant-time — and is corrected. Now health returns
  `cipher_experimental`, the server logs a warning at every start with `gost`, Settings shows an «экспериментальный»
  mark next to the suite, and docs/GOST.md has a "Side channels" section with what follows in practice (an unshared
  host, the master key in PKCS#11, X25519/ML-KEM client keys unless GOST on the wire is required). `aes` stays the
  recommended production profile. Nothing changes for existing data: the suite and its ciphertexts are the same.

## 0.41.3 — 2026-10-07

- **The update agent brings the compose file along.** Before, an update changed only the images and `VAULT_VERSION`;
  an installation made with `install.sh` 0.38–0.40 kept a healthcheck that calls curl, which the backend image has not
  had since 0.41.0 — after an update the backend showed as *unhealthy* (found live: a watchdog restarted a healthy
  vault every hour). Now the agent takes the release's compose file from the new, signature-checked updater image:
  an unedited file is replaced, an edited one keeps its edits and only the curl healthcheck is migrated, the result
  must pass `docker compose config` (otherwise it is put back and the update refused), a rollback restores it.
  Installations with an older agent are fixed by the handover helper of the new image at the end of the update to 0.41.3.
- Agent 0.41.3.

## 0.41.2 — 2026-10-07

Two defects of the update agent, both found in live updates on 06.10.2026.

- **A job its agent dropped no longer blocks updates.** The agent polls only between jobs, so a poll while its own job
  is still *running* means the job was lost (agent restarted, report never arrived, stand restored from the copy taken
  mid-update). The vault now closes such a job by what the installation reports — *done* when it already runs the
  target, *failed — abandoned* otherwise. An agent that never comes back: the owner can cancel its running job after
  60 minutes of silence (no poll, no report; a report now counts as a sign of life). Before, the Update button stayed
  disabled for good and «Cancel» answered 409.
- **The agent refuses to touch a compose project that is not the running vault.** Before stopping anything it checks
  that the project's running `backend` container is the one `/api/health` reports as `node`; otherwise the job ends
  *refused — nothing changed* and tells you to set `COMPOSE_PROJECT_NAME` in `.env`. And it never restores an archive
  while the vault still answers. Before, a stand started with `docker compose -p <name>` without that line in `.env`
  had the agent stop a project that did not exist and later restore the data under the running backend (SQLite: "attempt
  to write a readonly database").
- Agent 0.41.2. The server side helps every agent version; the project check needs agent 0.41.2 (it arrives with this
  update).

## 0.41.1 — 2026-10-06

- **The clients' stale fallback has a limit now: `max_stale`, default 24 hours** (Python `max_stale`, Go
  `Options.MaxStale`, Node `maxStaleMs`, Java `withMaxStale(Duration)`). While the vault is unreachable a cached value
  is still served — so a vault restart does not take the application down — but only within `max_stale` of when it was
  fetched. Before, an outage could keep a value alive indefinitely, so a rotated or revoked secret might be used long
  after the change. A 401/403 was and is never answered from the cache. **The old behaviour is one setting away:**
  Python `max_stale=None`, Go a negative `MaxStale`, Node `Infinity`, Java `withMaxStale(null)`. From the external
  review of 06.10.2026. `docs/CLIENT-CONTRACT.md` no longer tells third-party clients to answer a frozen token's 403
  from a cache — the libraries never did, and a frozen token may be a stolen one. Tests in all four clients: served inside the limit, the outage surfaces past it, the default is
  a day, "no limit" keeps the old behaviour.

## 0.41.0 — 2026-10-05

- **`VAULT_TRUSTED_PROXIES` accepts host names** next to networks, e.g. `127.0.0.1/32 vault-frontend`: resolved at start
  (logged) and every minute, so a recreated proxy container is followed; a failed lookup keeps the last answer; a name
  that never resolved trusts nobody and is retried every 10 s. For products that embed the vault in a docker network
  whose subnet differs per customer (ValoDrive). Verified in a real docker network: the named proxy's forwarded client
  address is used, a neighbour's forged `X-Forwarded-For` is ignored.
- **No curl in the backend image.** All healthchecks (compose, `deploy/images`, `deploy/cluster`, Swarm example) use
  `python3 -c "…urlopen('http://localhost:8086/api/health')…"`. **If you run the image with your own healthcheck that
  calls curl, switch it to the python form first.** Critical/high scanner findings: 52 → 44, all in Debian 13 packages
  without a fix.
- **OpenVEX for the backend image** (`security/vex/backend.openvex.json`, attached to every release, `ops/gen-vex.py`):
  a reason per CVE for the base image's unfixable findings; with `trivy image --vex …` 0 critical/high remain. Only
  packages the generator knows get a statement — a new finding elsewhere stays visible (tested both ways).

## 0.40.0 — 2026-10-05

- **Backups carry the environment settings too** (on by default, a switch in Settings → Backups): every `VAULT_*` /
  `OIDC_*` variable of the process — S3 keys, SSO and rotation keys, KMS / HSM / OIDC credentials, policies —
  `*_FILE` values resolved, key files carried as content; only inside the sealed payload, names only on the page. A
  restart with changed settings is a change. `python -m backup env DUMP [--files-dir DIR] > .env` gives them back as a
  compose `.env` (quoting checked through a real `env_file` with spaces, quotes, `$`, `#`, newlines).
- **The backup settings are in the backup** (recipient key, mode, on/off): a restored vault keeps backing up to the same
  recipient; the lease and the change hash start fresh. Before, a restored vault silently stopped backing up.

## 0.39.0 — 2026-10-05

**Encrypted backups to S3.** Settings → **Backups to S3** uploads the vault's database to any S3-compatible storage
(AWS, Yandex, Ceph RGW, MinIO), encrypted to a public key whose private half is not on the server.

- **What:** a logical dump of every application table (secret values stay ciphertext), gzip, sealed to the recipient
  key — post-quantum hybrid X25519 + ML-KEM-768 by default, GOST hybrid on a GOST vault; the header is bound as AAD.
  Restores into SQLite or PostgreSQL: `python -m backup fetch | decrypt | restore` in the backend image.
- **When:** *on change* (default — every minute a hash of the state, without the audit log and read counters; reads do
  not upload, edits within a minute make one object), *hourly*, or *daily*; in every mode a full copy once a day;
  *Back up now*. Replicas share the work through a lease; object names never repeat.
- **Key:** created in the UI (shown once) or your own public key (master password for both). S3 credentials only in
  the environment (`VAULT_BACKUP_S3_*`, `*_FILE` works). The vault never deletes objects — retention is the bucket's.
- API `/api/backup/{status,config,key,keygen,run}`; audit `backup:*`, webhook `backup:failed`. `docs/BACKUP.md`.
- **Verified live** against Ceph RGW: manual and change backups uploaded; an object fetched, decrypted and restored
  into empty SQLite and PostgreSQL 16 vaults that opened with the master password and returned the secret; a different
  key could not open it.

## 0.38.3 — 2026-10-05

- **Settings → Updates: the Update button is always visible.** Before, it appeared only when a newer release existed,
  so an up-to-date vault — or one without an agent — showed no button at all and looked unfinished. Now the button is
  there in every state and, when it cannot be pressed, the reason is written next to it: the latest version is
  installed, the update agent is not connected (and where to connect it), an update is in progress, or the channel
  gave no answer.

## 0.38.2 — 2026-10-05

- **Fixed: the update agent did not come back after an update.** It replaced itself with `docker compose up updater`
  from inside its own container; compose stopped the old container — the agent itself — halfway and left the new one
  in state *Created*. The vault was updated and healthy, only the agent was gone. Found by the first live update
  (0.38.0 → 0.38.1 by the button): the update itself took 38 s, data and session survived, the agent stayed down.
  Now the agent starts a short-lived helper from the new, already verified updater image, which recreates the
  `updater` service from outside and exits (`updater.py --handover`).
- **If you updated 0.38.0 → 0.38.1 by the button**, start the agent once by hand — the agent that runs the next update
  must already be 0.38.2 or newer:

  ```bash
  cd <install dir> && docker compose up -d updater
  ```

  Updating 0.38.1 → 0.38.2 by the button ends the same way (the 0.38.1 agent still has the old step); run the same
  command once afterwards. From 0.38.2 on the agent replaces itself.

## 0.38.1 — 2026-10-05

- **Release notes:** a link whose address holds parentheses (`[x](https://…/Foo_(bar))`, or a hostile
  `[x](javascript:alert(1))`) was cut at the first `)` and left a stray `)` in the text; the target may now hold one
  level of parentheses. Only `https://` targets become links, as before.
- **`deploy/images/install.sh`** writes `VAULT_PORT` / `VAULT_BIND` from the environment into `.env` — the agent runs
  compose without your shell's environment, so a port given only on the command line went back to 8087 on update.
- This release is the target of the first live update by the button: a stand installed with `install.sh` at 0.38.0
  is updated to it from Settings → Updates in a browser; the result is recorded in docs/UPDATES.md ("Verified how").

## 0.38.0 — 2026-10-05

**Updates by a click.** Settings → **Updates** shows the installed version, what the release channel offers with its
release notes, the history of every version with its notes, the update agent and the last update job. When a newer
release exists and an agent is connected, **Update to X** (owner, master password again) hands the job to the agent.

- **Update agent** `agent/updater.py`, image `ghcr.io/kzhebenev/aps-vault/updater` (signed and attested like the
  others). It polls the vault (the vault never calls it) and decides on its own: the version must be a published,
  non-prerelease release in the channel it reads itself, newer than what runs, and every image must carry the release
  workflow's Sigstore signature for that tag with the pulled digest equal to the signed one. Then it stops the
  backend, backs up the data volume, switches `VAULT_VERSION`, waits for `/api/health` to answer with the new version
  and replaces itself last; a version that does not come up healthy is rolled back together with its data.
- **Install from the images** with the agent: `deploy/images/install.sh <dir> [version] [public-url]` (compose file,
  `.env` with fresh tokens, named data volume, backups in `<dir>/backups`).
- **Release notes everywhere.** `backend/changelog.py` parses `CHANGELOG.md`; `backend/release_notes.json` ships the
  notes in the image (a test keeps it in sync), so the history works without network. **Fixed:** every GitHub
  Release body was just "Release X" — the workflow matched `## X.Y.Z` exactly while the headings carry a date; it now
  uses the same parser (`ops/release-notes.py section X`) and fails when the section is missing.
- API: `GET /api/update/status`, `POST /api/update/check`, `POST /api/update/apply`, `POST /api/update/jobs/{id}/cancel`;
  agent API `GET /api/agent/update`, `POST /api/agent/update/{id}` (Bearer `VAULT_UPDATE_AGENT_TOKEN`). Audit
  `update:*`, webhooks `update:done` / `update:failed`. Settings `VAULT_UPDATE_CHANNEL` (`off` = no outbound call),
  `VAULT_UPDATE_AGENT_TOKEN`. `docs/UPDATES.md`.
- `ops/checks/dast.py` covers the new endpoints (roles, agent token vs service token vs session).
- English translations for strings that were missing since 0.37 (second-factor and flag dialogs, users, KMS).

## 0.37.0 — 2026-10-05

**Security release: a white-box review of 0.36 and its fixes.** SAST (semgrep, bandit, gosec), SCA (trivy, pip-audit,
npm audit, govulncheck), secrets and configuration scans, DAST (OWASP ZAP, nuclei and the new role-aware
`ops/checks/dast.py`) and a reading of the whole code by four reviewers. 1 critical, 5 high, 14 medium and 18 low
findings fixed; each fix has a regression test that **fails on 0.36.0** (`backend/tests/test_security_review_2026_10_05.py`,
the client test suites, the extension). Full report in Russian: `docs/SECURITY-REVIEW-2026-10-05.md`.

**Breaking changes — read before upgrading:**

- **OIDC owner.** An OIDC login becomes the owner only when listed in `VAULT_OIDC_OWNERS` (e-mail or `sub:<id>`).
  Before, any allowed account that was not an active named user got the owner's session — including a person the
  owner had deactivated. Set the variable if the owner signs in through SSO.
- **Clients with a key refuse plaintext** and decrypt with the name they requested (Python, Node, Go, Java,
  Ansible, the CI step). A token configured with a client key that is answered unsealed now fails loudly.
- **Lifting a flag** (*machines only*, *requires approval*) needs the owner and `master_password` in the PATCH.
  Tokens, enrollment codes and http rotation receivers for folders with flagged secrets are the owner's.
- **Rotation through an administrator credential** (postgres, mysql, ldap, ssh) is configured by the owner; the
  account is bound at configuration time.
- **Turning a second factor off** (`POST /api/auth/webauthn/second-factor`, `{enabled: false}`) needs `password`.
- **`POST /api/me/password`** closes the person's other sessions and answers `other_sessions_closed`.
- **Managers** grant only reader and writer; appointing or removing managers is the owner's.
- **Outbound calls are https** to globally routable addresses (webhooks, approver notification, rotation, import)
  and never follow redirects; plain http and private networks only with `VAULT_WEBHOOK_ALLOW_PRIVATE=1`.
- **The client-certificate fingerprint header** is cleared by the bundled nginx unless the frontend container
  has `VAULT_PASS_CERT_FINGERPRINT=1`.
- **The MCP server** writes only with `APS_MCP_ALLOW_WRITE=1`.

Fixed besides: a named user's security key was accepted as the owner's second factor; share links kept working
after the secret got a flag; password checks inside a session (password change, 2FA off, TOTP) were not
rate-limited; a TOTP code could be replayed; the global attempt budget locked out addresses with no failures;
deactivating a person left their tokens and enrollment codes alive; spent and revoked links and enrollment codes
kept the folder key; canaries answered differently from an unknown token under a policy or with the watch off;
`/m/audit` showed neighbour folders with a common prefix; malformed JSON on KV write was a 500; SSRF guards let
100.64/10 and IPv4-mapped IPv6 through; the KMS PIN reached the provider's logs as encryption context (PIN v2:
Argon2id locally, old cells re-written on the next PIN login); KDBX, zip and HashiCorp imports had no resource
caps; unknown e-mails answered faster at login; recovery and invitations ignored the UI network policy; PRF unlock
did not require user verification; the SQLite file was world-readable.

Hardening: strict CSP (the inline theme script moved to `theme.js`), `X-Frame-Options`, COOP/CORP,
Permissions-Policy, no nginx version; `Cache-Control: no-store` for `/api/` and `/v1/`; containers with
`no-new-privileges` and `cap_drop: ALL`; image packages upgraded at build; every GitHub action pinned by SHA and
minimal workflow permissions; the GitLab template checks the script's sha256 and pins its pip packages;
Terraform provider dependencies updated (Go 1.26.8); Swarm example publishes the port in host mode; `ops/`
scripts pass tokens and values through stdin / 0600 files instead of the command line. Startup warnings for an
unset `VAULT_TRUSTED_PROXIES` and for `VAULT_MASTER_PASSWORD` outside dev.

Browser extension 0.3.0 (separate repository): unlock and the secret list only in the extension's own pages, the
content script gets values only for its tab's https host, in-page hints in a closed shadow root, a page on a parent
domain no longer gets the secrets of its subdomains.

## 0.36.0 — 2026-10-05

- **SLSA provenance.** The release workflow attests every release asset and both container images with
  `actions/attest-build-provenance` (in-toto / SLSA v1, Sigstore-signed, GitHub-hosted runner → SLSA Build
  Level 3; image attestations are also pushed to ghcr.io) and the backend image with an SBOM attestation
  (`actions/attest-sbom`). Verify: `gh attestation verify <asset> --owner kzhebenev`,
  `gh attestation verify oci://ghcr.io/kzhebenev/aps-vault/backend:<v> --owner kzhebenev`. `docs/PUBLISHING.md`, `SECURITY.md`.
- **Docker Swarm and Nomad examples** (`examples/docker-swarm/stack.yml`, `examples/nomad/aps-vault.nomad.hcl`): the
  vault as a stack / job with the images from ghcr.io, the data directory on one node, the init token and the
  server keys as Swarm secrets / Nomad variables, the backend reachable only through the frontend.

## 0.35.0 — 2026-10-04

**More import sources, and KeePass databases read directly.** `backend/kdbx.py` opens `.kdbx` files in memory:
KDBX 3.1 and 4.x, AES-KDF / Argon2d / Argon2id, AES-256-CBC / ChaCha20, Salsa20 / ChaCha20 inner streams, gzip,
HMAC block streams, key files (binary, hex, XML v1 / v2 with hash check); Twofish is refused with a pointer.
Verified against KeePassXC's published test databases and pykeepass-written files; a wrong password, a missing
key file, a damaged header or a truncated file each fail with the named reason. New parsers: **Dashlane** (zip or
credentials.csv + securenotes.csv), **Keeper** (JSON; CSV with a header), **Passbolt** (CSV (KeePass)); all
detected by content. The import drawer has the four new tiles and a password / key-file box for `.kdbx`. The
import endpoint takes `password` and `keyfile`; the Argon2 work runs off the event loop. `docs/IMPORT.md`.

## 0.34.0 — 2026-10-04

**CI steps.** `clients/ci/aps-vault-ci.py` (standard library) reads secrets with a folder-scoped token and
hands them to the pipeline: `--github` appends heredocs to `$GITHUB_ENV` and emits `::add-mask::` for every
line first, `--dotenv` writes a `KEY=value` file (mode 0600, single-line values), `--export` prints
`eval`-able exports. Items are `name[.field][:ENV]` (value / login / notes / totp). Fails closed — all
secrets are read before anything is written; the token is never printed. On top of it: the GitHub composite
action `clients/github-action` (inputs url, token, secrets, client_key for sealed tokens; output
`variables`) and the GitLab template `clients/gitlab-ci/aps-vault.gitlab-ci.yml` (`.aps-vault-secrets` for
the job's own shell, job `aps-vault-secrets` for a dotenv artifact). The repository's CI runs the action
against a throwaway vault on the runner, plain and sealed. `docs/CI.md`.

## 0.33.0 — 2026-10-04

**Terraform / OpenTofu provider** (`clients/terraform`, plugin framework, protocol 6). `data
"apsvault_secret"` reads a secret (or an older `version`), `data "apsvault_secrets"` lists the folder,
`resource "apsvault_secret"` creates / updates / deletes secrets with a can_write token and imports by
name; sealed tokens open with `client_private_key`. Configuration is checked against `/api/v1/m/health`
first, so a wrong token fails with the reason before any plan. Tested through the real CLI (OpenTofu)
against a fake machine API and, by `ops/checks/terraform-acc.sh`, against a live vault. Binaries for
linux / darwin / windows in the GitHub Release; registry listing waits for the maintainer's account.
`docs/TERRAFORM.md`. Go client: `Delete()` (machine DELETE, 0.30.1+).
**Fixes found on the way**: a second token with an existing name was a 500 from the database (names are
unique vault-wide and revoked tokens keep theirs) — now a 409 with a message; deleting a folder left its
tokens behind as revoked orphans, which PostgreSQL refused with a foreign-key error (SQLite did not enforce
it) — the folder's tokens and their watch rows now go with it and the response says how many; a secret's
`updated_at` moved on every machine read (the access counter's row update triggered the column's
auto-update) — now it changes only when the secret itself changes.

## 0.32.0 — 2026-10-04

**GOST post-quantum hybrid envelope.** A token bound to a 1248-byte key — GOST R 34.10-2012 point (64) ‖
ML-KEM-768 encapsulation key (1184) — gets `VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM`: the
vault derives the KEK with VKO as in the GOST envelope, encapsulates to the ML-KEM half, and feeds both
secrets into KDF_TREE_GOSTR3411_2012_256 (`label = aps-vault/sealed-gost-pqc/v1`, `seed = epk ‖ kem`);
Kuznyechik-MGM carries the payload. Private key 96 bytes = GOST scalar ‖ ML-KEM seed, the same seed
convention as the X25519 hybrid. Server (`sealed.py`), all four clients (`generate_keypair("gost-pqc")`,
`generateKeyPair({ gostPqc: true })`, `GenerateGostPqcKeyPair()`, `generateGostPqcKeyPair()`; public-from-
private helpers; Java opens on JDK 24+), CLI flags `--gost-pqc`, the shared fixture
`clients/fixtures/gost-pqc-sealed.json`, the token table now names the envelope kind (ГОСТ / P-256 / PQC /
ГОСТ+PQC; before, every long key was labelled ГОСТ). `docs/SEALED.md`, `docs/GOST.md`.

## 0.31.1 — 2026-10-04

- **Fix (cluster compose)**: the frontend image renders `nginx.conf.template` at start since 0.30.1;
  `deploy/cluster` mounts `nginx-lb.conf` read-only over the output path, so the renderer failed and
  the frontend container restarted in a loop. The cluster compose now sets
  `NGINX_ENVSUBST_TEMPLATE_DIR=/etc/nginx/templates-off` (the renderer skips); `docs/CLUSTER.md` and
  `docs/DEPLOYMENT.md` say so for anyone mounting their own config. `smoke_test.sh` now fails when
  the running API's version differs from the tree's `VERSION` and checks the cluster stand's frontend
  when it runs on the host — a stale or looping deployment is a red smoke, not a note.

## 0.31.0 — 2026-10-04

**Rotation targets LDAP and SSH.** *LDAP*: the bind account is a secret (login = bind DN, value =
password); `userPassword` (OpenLDAP) or `unicodePwd` (Active Directory, TLS required) is replaced on
the entry named by the secret's login or the rotation's DN, then the vault binds as that entry with
the new password and puts the old one back if the bind fails. Verified against OpenLDAP; the AD
branch is implemented per Microsoft's rules but not run against a live AD. *SSH*: the administrator
is a secret (login = user, value = password or an OpenSSH private key); the server's host key is
**required** in the configuration and a different key stops the run before anything is sent;
`chpasswd` through `sudo -n` with `user:password` on stdin, then a login as the account; a refused
login (DenyUsers, nologin) restores the old password. Verified against OpenSSH on Alpine with a
password and with a key. Both targets in the rotation dialog as tiles; `docs/ROTATION.md`.
Dependencies: `ldap3`, `paramiko`.

## 0.30.2 — 2026-10-04

- Backend image no longer carries `tests/` (the 0.17.1 compatibility fixture database was shipped
  inside the image; a delivery gate in ValoDrive caught it): `backend/.dockerignore`. Tests run
  from the source tree (`run_tests.sh`), not from the image. Frontend gets a `.dockerignore` too.

## 0.30.1 — 2026-10-04

Delivery fixes found while planning the vault inside an on-prem product (ValoDrive):

- Frontend: the backend address is `VAULT_BACKEND_URL` (default `http://backend:8086`), rendered from
  `nginx.conf.template` by the nginx image at start — the frontend can sit next to any backend
  service name; `examples/docker-compose.sidecar.yml` sets it and works as written.
- Enrolment: `can_write` in the enrolment code (default off) — a node that must write its own
  secrets (a product that migrates keys into the vault) needs no hand-made token.
- Machine API: `DELETE /api/v1/m/secret/{name}` (can_write; history and rotation rows go with it,
  the folder cell stays) and `GET /api/v1/m/audit` (can_write; rows of this folder only).
- Frontend healthcheck (image and compose); backend Dockerfile comment about workers updated.

## 0.30.0 — 2026-10-04

**Users and rotation, the smaller items.** *TOTP for named users*: one-time codes as a second factor
on the password, the seed encrypted under the user's own private key (checkable only after the
password opened it; cleared by a password reset); `401` + `X-TOTP-Required` at login. *Managers
grant*: a folder manager gives roles on the folders they manage from the folder's *Who has access*
dialog — the key is wrapped from the manager's own grant, the owner is not involved; a manager cannot
change their own grant or other folders, and sees a reduced directory. *Folder-key rotation*: the
owner re-keys a folder after a revocation — secrets, history, rotation configs re-encrypted, grants
re-wrapped, the automation cell rewritten, the folder's tokens and enrolment codes revoked by name.
*MySQL / MariaDB rotation target*: `ALTER USER … IDENTIFIED BY` with a login probe and rollback,
verified against MariaDB 11 (PyMySQL). `docs/USERS.md`, `docs/ROTATION.md`.
**Fix (SQLite)**: deleting a secret left its history rows behind, and SQLite hands a freed id to the
next row — so a new secret could show a deleted one's old values in its history (found by the key-
rotation test). Deletes now remove history, rotation, grant and enrolment rows explicitly, and the
`folders` / `secrets` tables stop reusing ids on new databases.

## 0.29.0 — 2026-10-04

**Import from other managers.** Settings → *Import from another manager*: Bitwarden / Vaultwarden
(unencrypted JSON), KeePass 2.x XML, 1Password CSV and 1PUX, LastPass CSV, any CSV with a header, `.env`
files, this vault's own export, **Passwork** (export files, or a live pull over its API with the
client-side encryption chain decrypted here), and a live pull from a **HashiCorp Vault / Deckhouse
Stronghold KV v2** mount over its API. Source tiles, a **preview** of everything that would be created (counts, logins,
TOTP, notes, warnings) before anything is written, *folders as in the source* (with a prefix) or *one
folder*, and conflict handling — skip, write as a new version (old value kept in the history), or add
with a suffix. Secure notes become secrets whose value is the note; `otpauth://` URLs are reduced to the
seed, Steam codes go to the notes with a warning; trashed and archived items are skipped; in-file
duplicates are suffixed. `POST /api/import` learns `on_conflict`; new `POST /api/import/parse`
(multipart), `POST /api/import/hashicorp` and `POST /api/import/passwork`. `docs/IMPORT.md`.

## 0.28.2 — 2026-10-04

**Fixes from the first CI runs on GitHub.** *Java client*: the flat JSON parser used a regex
alternation loop that `java.util.regex` recurses once per character, so a 1.5 KB value (the ML-KEM
`kem` field, a hybrid public key) overflowed the stack on threads with a small stack — CI's main
thread did, production threads could; rewritten as an iterative character-class loop, with a test
that parses a 200 KB value on a 256 KB stack. *Dependencies* (pip-audit): FastAPI 0.115 → 0.142.2
(Starlette 1.7.0, fixes PYSEC-2026-248/249/1941/1943/2280/2281), cryptography 43 → 50.0.2,
pyOpenSSL pinned to 26.4.0, python-multipart 0.0.12 → 0.0.31.

## 0.28.1 — 2026-10-04

First real run of the release pipeline: the Node job failed in a clean checkout because `@types/node`
was missing from the dev dependencies (the local build had picked it up from elsewhere) — added; the
GitHub Release job now runs even when a registry job fails (`!cancelled()`), so an account that does
not exist yet never costs the Release. Images on ghcr.io, their cosign signatures, the PyPI and Maven
build steps and the tag/VERSION check worked on the first run.

## 0.28.0 — 2026-10-04

**Release pipeline.** A `v*` tag now produces a GitHub Release with the Python sdist/wheel, the npm
tarball, the Java jar (with sources and javadoc), SPDX SBOMs of the sources and of the backend image,
and Sigstore keyless signatures for every asset; backend and frontend images go to
`ghcr.io/kzhebenev/aps-vault/{backend,frontend}` signed with cosign. PyPI (`aps-vault`) and npm
(`@aps-vault/client`, with provenance) are published through OIDC trusted publishing — no tokens
stored anywhere; Maven Central (`io.github.kzhebenev:aps-vault-client`) through the Central
Publisher Portal with a scoped token. Package metadata completed (URLs, classifiers, keywords,
repository, `publishConfig`). The registry accounts are the maintainer's one-time step —
`docs/PUBLISHING.md` is the fifteen-minute checklist; until then those steps fail soft and the
Release still happens. CI typo fixed (Node test file name).

## 0.27.0 — 2026-10-04

**Post-quantum hybrid envelope.** Sealed delivery gets a fourth envelope: **X25519 + ML-KEM-768**
(FIPS 203), `alg = X25519MLKEM768-HKDF-SHA256-AES256GCM`. A 1216-byte client key (X25519 pk ‖
ML-KEM encapsulation key) selects it; the AES key is derived from both shared secrets, so a
recording of today's traffic stays closed to a quantum computer later. Private key = X25519 sk ‖
ML-KEM seed (96 bytes), derived identically by all four clients (Python with `kyber-py`, Node 20.19+ with
`@noble/post-quantum` — its own HKDF, since `hkdfSync` caps `info` at 1024 bytes —, Go 1.24 `crypto/mlkem`, Java 24+ JCA); `keygen --pqc`, `enroll --pqc`,
`generate_keypair("pqc")` and friends. The server validates the ML-KEM half (FIPS 203 §7.2 check);
`client_public_key` columns widened to 2048 characters. Fixture `clients/fixtures/pqc-sealed.json`.
`docs/SEALED.md`.

## 0.26.0 — 2026-10-04

**Token watch.** Every service token gets a behaviour profile (networks, secrets, rate) and the
machine API raises alerts when a call does not fit: a **new network** after the learning period,
**two known networks within two minutes**, a **rate spike**, **enumeration** of secrets the token
never read, and **canary** tokens that trip on any use. Per token: `on_anomaly = alert | freeze`;
a frozen token answers 403 until a manager unfreezes it; a canary always freezes and gives the
caller the generic 401. Alerts fold repeats for an hour, go to the audit log (`token:anomaly`),
webhooks, the HTTP notifier, the security log and `aps_vault_token_alerts_open`. Tokens page:
alert panel with *Unfreeze / Trust network / Revoke / Dismiss*, badges, *Service / Canary* tiles,
*notify / freeze* chips. **Leak check**: `ops/leak-scan.py` finds token-shaped strings in files,
git history or stdin and asks `POST /api/tokens/leak-check` (owner) which hashes are live —
plaintext never travels; `--revoke`. `docs/TOKEN-WATCH.md`; machine-API contract: 403 "frozen"
(`docs/CLIENT-CONTRACT.md`).

## 0.25.0 — 2026-10-04

**DevOps integrations.** *Kubernetes*: the External Secrets Operator syncs vault secrets into
Kubernetes Secrets through its standard `vault` provider (our HashiCorp-compatible facade) or its
`webhook` provider (the machine API) — manifests in `deploy/k8s/external-secrets/`, guide
`docs/KUBERNETES.md`, verified in a real k3s cluster with ESO v2.11.0 against the live vault.
*Ansible*: a standard-library lookup plugin `aps_vault` (`clients/ansible/`) — value, login,
notes, TOTP or the whole record, old versions, sealed tokens with the Python client; verified with
a real `ansible-playbook` run. **Fixes found by the real runs**: the facade's `auth/token/lookup-self`
now reports `expire_time`, `ttl`, `creation_time` like HashiCorp (ESO refused the store without
them); a service token **with an expiry** made the machine API answer 500 (naive/aware datetime
comparison) — now it works until the expiry and answers 401 after.

## 0.24.0 — 2026-10-03

**Rotation in target systems.** A secret can now be rotated *where it is checked*, not only in
the vault: **PostgreSQL** (`ALTER ROLE … PASSWORD` through an administrator DSN that is itself a
secret, then a login with the new password as proof; a failed probe restores the old password)
and an **HTTP receiver** (a signed POST with the new value to a service you run — Kafka, LDAP, a
cloud; `2xx` = applied). Order is generate → apply → verify → store, so a refusal leaves the vault
and the target unchanged. By hand (writer) or on a schedule (7/30/90/180 days): the schedule
needs `VAULT_ROTATION_KEY`, under which the folders concerned keep an **automation cell** (folder
key wrapped for the scheduler — the SSO-cell construction); without the key the UI and
`/api/rotations/status` say NOT CONFIGURED. Cluster-safe claim of due rows, hourly retry of
failures, audit `rotation:*`, webhook `secret:update {rotated}` / `rotation:fail`. Secret card
row, Rotation page, English strings. `docs/ROTATION.md`.

## 0.23.0 — 2026-10-03

**Security keys and SSO for named users.** Users register YubiKey / Touch ID / Android keys in
their profile: with PRF — one-touch sign-in without a password (the key holds a cell with the
user's private key), without PRF — a second factor on the password (`X-WebAuthn-Required`).
Keys are per person (the owner's keys and cells untouched; a password reset drops the user's
keys; deleting the last key switches the second factor off). OIDC logins whose e-mail is a
user now mint a user session through a per-user SSO cell (private key under
HKDF(`VAULT_SSO_UNLOCK_KEY`, user)), written on password set / change / first password sign-in.
Sign-in screen: *Sign in with a security key* on the User tab. `docs/USERS.md`.

## 0.22.0 — 2026-10-03

**Client keys in hardware.** A third sealed-delivery envelope on NIST P-256
(`P256-HKDF-SHA256-AES256GCM`, selected by a 65-byte uncompressed point on the token) — the curve
TPM 2.0 chips, HSMs and smart cards do ECDH on through PKCS#11. The node's private key can now
be generated inside the hardware and never leave it: `python3 -m aps_vault enroll … --pkcs11
module:token:pin`, `Pkcs11Key` in the Python client (one `CKM_ECDH1_DERIVE` per envelope), a
`KeyProvider` seam in Node and Go, a `java.security.PrivateKey` from SunPKCS11 in Java. Software
P-256 keys work in all four clients. Verified on SoftHSM2 (Python via python-pkcs11, Java via
SunPKCS11); a real TPM / HSM was not at hand — the interface is the same.

## 0.21.0 — 2026-10-03

**Node enrolment.** The owner or a folder manager issues a one-time (or N-use, time-limited)
code; the node runs `python3 -m aps_vault enroll <url> <code>` — or `enroll()` in Node, Go,
Java — makes its own key pair, presents the code and the public key and receives a service
token sealed to that key. Nobody copies tokens by hand, the private key never leaves the
node, the folder key travels inside the code (encrypted under its KDF) so enrolment needs no
human session. Codes carry the token options (name prefix, grants, expiry, where-and-when
policy that also gates the enrolment call), are revocable, and failures count towards the
lock-out. Tokens page: *Node enrolment code* dialog and the list of active codes.
`docs/ENROLLMENT.md`; `/api/enrollments*`, public `/api/enroll`.

## 0.20.0 — 2026-10-03

**Named users with a role per folder.** The owner (master password) invites people by
e-mail; each gets a key pair (X25519 or GOST R 34.10-2012 by cipher suite) whose private key
is wrapped under their own password, and **grants** — the folder key sealed to their public
key — with a role: *reader* (values, TOTP, history), *writer* (+ create / change / delete /
rotate / move), *manager* (+ tokens and share links). Users see only granted folders; owner
surfaces answer 403; the audit log and history name the person. One-time invitation links
(`/invite/<token>`, 7 days), password reset by re-invitation (new key pair, grants re-created,
sessions closed), deactivation. Sign-in screen gains an Administrator / User switch; new
Users page for the owner and a profile page for users; the UI hides what the role does not
allow. `docs/USERS.md`; endpoints `/api/users*`, `/api/invite/{token}`, `/api/auth/login`,
`/api/me`. Not yet: security keys / SSO for users, managers granting others.

## 0.19.0 — 2026-10-03

**GOST sealed delivery in all four clients.** A token bound to a GOST R 34.10-2012 public key
(64 bytes, curve paramSetB) receives values sealed with VKO (RFC 7836) → KDF_TREE → Kuznyechik-MGM
instead of X25519/AES — selected by the key, independent of the vault's cipher suite, so a GOST
vault with GOST client keys is GOST end to end. The Python (`aps-vault[gost]`), Node, Go and
Java clients open both envelope types and generate both kinds of key pair; Node, Go and Java
carry their own Streebog, Kuznyechik, MGM and curve code with no dependencies (constant tables
generated by `ops/gen-gost-consts.py`, never typed by hand), verified against the standards' test
vectors and against a server-produced fixture (`clients/fixtures/gost-sealed.json`;
specification `clients/GOST-PORTING.md`). Curve arithmetic in Jacobian coordinates (~5 ms per
scalar multiplication in CPython, ~25 ms per envelope). Token dialog accepts both key sizes and
marks GOST-sealed tokens. IQR integration guide gains a GOST chapter.

## 0.18.0 — 2026-10-03

**GOST cipher suite (algorithm-level).** `VAULT_CIPHER=gost` at initialisation runs the
vault on Kuznyechik-MGM (GOST R 34.12-2015, R 1323565.1.026-2019 / RFC 9058) for every value,
folder key and master-key cell, Streebog-256 (GOST R 34.11-2012) for look-up hashes,
KDF_TREE_GOSTR3411_2012_256 (R 50.1.113) for key derivation, and optionally
PBKDF2-HMAC-Streebog-512 (R 50.1.111) for the master password. Own Kuznyechik/MGM
implementation (~400 KB/s) verified against the standards' and RFC 9058's test vectors and
cross-checked with the MIT `gostcrypto` library, which provides Streebog. The suite is stored
in `vault_config` and wins over the environment afterwards. Every symmetric primitive now goes
through `backend/suite.py`; the aes suite is byte-compatible with earlier releases, proven by
`tests/compat_fixture_check.py` opening a 0.17.1 database after every test mode (`run_tests.sh`,
`run_tests.sh pg`, `run_tests.sh gost`). TOTP, WebAuthn, OIDC, SigV4, webhook HMAC and sealed
delivery stay on their own standards — `docs/GOST.md` lists what is and is not GOST, and
states plainly that this is conformance by algorithm, not a certified СКЗИ. Health and
Settings show the active suite.

## 0.17.1 — 2026-10-03

**Documentation and tooling caught up with 0.6–0.17.** `docs/ARCHITECTURE.md` rewritten
(state in the database, master-key cells, sessions, sealed delivery, data model, cluster);
`docs/DEPLOYMENT.md` lists every environment variable incl. PKCS#11, KMS, SSO cell, approvals,
mTLS; `SECURITY.md` threat model and crypto table updated to 0.17 (what sealed delivery, HSM/KMS
cells and WebAuthn do and do not protect, untested GOST/Yandex paths named); `docs/COMPARISON.md`
gains the 0.8–0.17 rows; README (en/ru) no longer calls the vault "one SQLite file, one
process" next to the cluster section. CLI: `vault get <name> [version]`, refuses to print a
sealed envelope as a value (decrypts with `VAULT_CLIENT_KEY` when the Python client is at hand).
MCP server: `version` argument, clear error for sealed tokens. Examples index mentions
`VAULT_CLIENT_KEY`.

## 0.17.0 — 2026-10-03

**Sealed delivery.** A service token can be bound to the application's X25519 public key; the
machine API then never returns plaintext — the value (with login / notes / TOTP as granted) is
encrypted to that key (X25519 → HKDF-SHA256 → AES-256-GCM, secret name as AAD, fresh ephemeral
key per response) and only the process holding the private key opens it. Nothing on the path
sees the value (proxy, load balancer, captured responses) and a stolen token is useless
without the key; what it does not change: the value is in the application's memory after
decryption. The Python (`aps-vault[sealed]`), Node, Go and Java clients decrypt in-process and
generate key pairs (`python -m aps_vault keygen` and equivalents); their tests open the same
envelope produced by the server. UI: *Sealed delivery* field in the token dialog, *sealed*
badge. The HashiCorp KV facade answers 403 for a sealed token. `docs/SEALED.md`.

## 0.16.0 — 2026-10-03

**Cloud KMS for the master key (AWS KMS, Yandex Cloud KMS).** The master key can be encrypted
by a key that lives in a cloud KMS and never leaves it; the cell opens only through the
vault's cloud identity. **With a PIN** the PIN-derived value becomes the KMS *encryption
context*, so the KMS refuses to decrypt for anyone without it — cloud credentials alone are
not enough — and the login screen gains a PIN field. **Without a PIN** (auto mode) the server
opens the cell itself: an SSO source for a whole cluster (`sso_unlock: "kms"`) and re-wrap on
password change; not a login. No SDKs (SigV4 / PS256 IAM JWT in-house). AWS verified through
LocalStack 3.8.1 (community image; the wire protocol is the real one); Yandex implemented
from the API reference and **not verified** — needs a real service-account key.
`docs/KMS.md`; endpoints `/api/auth/kms/{status,enable,disable,unlock}`; audit
`auth:kms_*`.

**GOST tokens through PKCS#11.** `VAULT_PKCS11_MECHANISM` / `VAULT_PKCS11_KEY_TYPE`
(`GOST28147`, 64-bit IV) and `VAULT_PKCS11_CREATE_KEY=0` for keys made by the vendor's tools —
the configuration CryptoPro HSM and Rutoken HSM need instead of AES. **Not exercised**: no
GOST module was at hand; `docs/HSM.md` says exactly what was and was not tested.

Test runner: LocalStack KMS sidecar in `run_tests.sh` and in the e2e stack
(`ops/checks/e2e-stack.sh`); the browser check covers the KMS Settings and PIN login.

## 0.15.0 — 2026-10-03

**Hardware token for the master key (PKCS#11).** The master key can be wrapped by an AES-256
key inside a PKCS#11 token; the administrator unlocks with the token's PIN, the AES key never
leaves the token, a database dump is useless without it. Tested against SoftHSM2 (bundled in
the backend image, tokens in the data volume); YubiHSM 2, Nitrokey HSM, Rutoken HSM and other
AES-GCM-capable modules are expected to work unchanged but were not exercised. Optional auto
mode (`VAULT_PKCS11_PIN`) lets the token serve SSO logins and re-wrap on password change.
`docs/HSM.md`; endpoints `/api/auth/hsm/{status,enable,disable,unlock}`.

## 0.14.0 — 2026-10-03

**Share a note.** A one-time link for free text that is not a stored secret — access details
for a contractor, a temporary password, a piece of config. Same model as secret sharing
(TTL, max uses, link for a person or JSON for a machine); the text is encrypted under a key
derived from the link token and exists nowhere else. Links page button and the `S` key;
`POST /api/share/note`, `DELETE /api/shares/note/{id}`; the shares list carries `kind`.

## 0.13.0 — 2026-10-03

**Security keys and biometrics (WebAuthn).** YubiKey, Touch ID on macOS, Windows Hello,
Android — registered from Settings (master password required). With the PRF / hmac-secret
extension (YubiKey 5, passkeys in Safari 18+/Chrome) the master key is wrapped under a key
derived from the authenticator's PRF output and **unlock is one touch, no password**; the
database holds ciphertext, the secret lives in the authenticator. Keys without PRF become a
**second factor**: password sign-in then also asks for the key (`X-WebAuthn-Required: 1`).

- `GET /api/auth/webauthn/status` (public), `POST …/options?purpose=unlock|second_factor`,
  `POST …/unlock` (assertion + PRF output → session), `…/register/options|finish`,
  `GET/DELETE …/credentials`, `POST …/second-factor`.
- Challenges are stored in the database (replicas share them), single-use, 3 minutes.
  RP ID = host of `VAULT_PUBLIC_URL` (an IP address cannot be an RP ID; `localhost` works).
- Password change / recovery drop the PRF cells (they wrapped the old key) — re-register keys;
  removing the last key switches the second factor off so the administrator is never locked out.
- Tests: a software ES256 authenticator in `test_webauthn.py`; the browser check registers and
  unlocks with Chrome's virtual CTAP2 authenticator with PRF.

## 0.12.0 — 2026-10-03

**Read approval (two-person rule).** A secret flagged `require_approval` is read by a person
only after an approver — a second person with a password of their own, no account — confirms
from a link. The approver never sees the value; service tokens are not involved. The link is
delivered through a configurable HTTP notifier (`VAULT_APPROVAL_NOTIFY_URL/HEADERS/BODY`:
Telegram, Slack, ntfy, any gateway) or shown to the requester when none is configured.
Requests live 15 minutes, approvals 10, bound to the requesting session; everything is
audited. UI: Settings section with recent requests, editor toggle, request panel in the card,
public approve page. `docs/APPROVALS.md`.

## 0.11.0 — 2026-10-03

**Token binding to client certificates (mTLS).** A service token may list fingerprints
(SHA-1 or SHA-256) of client certificates; the TLS proxy verifies the certificate and forwards
the fingerprint (`X-Client-Cert-Fingerprint`, configurable), the vault refuses a bound token
without a matching one. The header counts only from trusted proxies, so a client cannot
claim a certificate. Token editor field, table display, `docs/ACCESS-POLICIES.md` with the
nginx snippet.

## 0.10.0 — 2026-10-03

**SSO unlock across replicas.** An OIDC login proves identity, not the master password; until
now an SSO sign-in worked only on the replica where a password unlock had happened. With
`VAULT_SSO_UNLOCK_KEY` (≥32 random bytes, the same on every replica, never given to the IdP)
the administrator enables "SSO unlock" in Settings (master password required): the master key
is stored in `vault_config` wrapped under HKDF(server key), and every replica can mint a
session for an allowed OIDC user.

- `GET /api/auth/sso-unlock/status`, `POST …/enable {master_password}`, `POST …/disable`;
  `GET /api/auth/oidc/status` reports `sso_unlock: node|cell|env|none` per replica.
- The cell is re-wrapped on password change and recovery (or dropped when the replica has no
  server key); disabling it also clears the node cache. Audited.
- Trade-off, stated in `docs/CLUSTER.md`: a database dump plus the server key opens the vault —
  keep the key out of database backups. Without the key the cell is ciphertext.

## 0.9.0 — 2026-10-03

**Machine-only secrets.** A secret flagged `machine_only` is never shown to a person: the
card, the history, the export and share links hide its value; only service tokens read it.
For key material the administrator issues but must not see.

- `POST /api/secrets` with `machine_only: true` and `generate: "base64:32" | "hex:32" | "alnum:40"`
  makes the value on the server — nobody ever sees it. Also usable without `machine_only`.
- `POST /api/secrets/{id}/rotate {generate}` replaces the value with a fresh server-made one;
  the old value becomes the previous version (machines keep reading it with `?version=N`).
- Export writes `"value": null` for such secrets, import skips them; sharing returns 403.
- Opening the card does not count as a read (`secret:view`); un-hiding is audited (`secret:unhide`).
- UI: "Только для машин" toggle in the editor with server-side generation chips, a "Ротация"
  button in the card, badges in the list, a separate line in the health report.

## 0.8.0 — 2026-10-03

**Secret versions.** Every value change advances a per-secret version counter; history rows
carry the number they held. For a key rotation a service can keep decrypting old files with
the old key while new files use the new one.

- Machine API: `GET /api/v1/m/secret/{name}?version=N` returns an older value (404 for an
  unknown version); `GET /api/v1/m/secret/{name}/versions` lists versions without values and
  without counting as an access; reads and writes return `version`/`current_version`.
- HashiCorp KV v2 facade: `?version=N` on `data/`, full `versions` map and `oldest_version` in
  `metadata/` — `hvac.read_secret_version(version=…)` works.
- Human API: `version` on secrets, numbered history (`current_version`); the UI shows the
  version in the card and `vN` badges in the history.
- Moving a secret between folders re-wraps its history too, so `?version=N` keeps working for
  the new folder's tokens.
- Clients (Python, Node, Go, Java): `get(name, version)` / `getFull(name, version)` and `versions(name)`.
- Migration numbers existing history rows by time and sets each secret's counter above them.

## 0.7.1 — 2026-10-03

- **Two kinds of share link**, chosen with a toggle in the Share dialog (remembered):
  *for a person* (default) — `/share/<token>` opens a page with the secret's name, login,
  value (blurred, copy button) and the sender's message; the page asks for a click before
  consuming the one-time link, so link previews do not burn it; *for a machine* —
  `/api/share/<token>` returns JSON as before. Both count opens the same way.
- Share response now includes `login`; the dialog's note is explicitly a message to the recipient.

## 0.7.0 — 2026-10-03

**New web UI.** Same vanilla JS and CSP, no framework, no build step — rebuilt around the
daily loop instead of the API (`docs/COMPARISON.md` for the feature gap analysis).

- Three-pane layout: scopes and folders · list · detail card; every screen has a URL
  (`#/folder/3/s/12`, `#/tokens`, …), browser back works; responsive down to a phone.
- Keyboard: ⌘K palette with fuzzy search and ⌘Enter-to-copy, `/` search, `J/K`, `Enter`, `C`
  copy, `N` new, `?` help; list sorting; hover quick actions (copy value/login, open URL, star).
- Theme: dark / light / system, persisted; letter avatars instead of third-party favicons.
- Password generator: random (length, classes, look-alike filter) or passphrase (words,
  separator, capitalisation, number) with an entropy estimate; strength meter on every value.
- Breach check (Have I Been Pwned, k-anonymity: 5 hex chars of the SHA-1 leave the browser,
  proxied by `GET /api/tools/hibp/{prefix}`; `VAULT_HIBP=0` disables). Per secret and for
  the whole vault.
- Health report: weak, reused, overdue, expiring, unchanged 180 d, unopened 90 d, score,
  token usage. Plain text lives only in that tab while it is open.
- Rotation deadline per secret (`expires_at`), "Expiring" scope, badges 30 days ahead.
- Live TOTP with countdown; `GET /api/secrets/{id}/totp` refreshes the code without
  counting as an access.
- Move a secret between folders (`PATCH … {"folder_id"}`) with re-encryption under the target key.
- Pages instead of modals: tokens (with policy fields), share links, webhooks, audit log
  (group filters, text filter, CSV), settings (theme, language, auto-lock, clipboard
  clearing, auto-hide, 2FA with QR, change master password, lock everywhere, export/import,
  version/node).
- `POST /api/auth/change-password`: re-wraps folder keys (tokens survive), issues a new
  recovery code, drops every session.
- Unlock screen: 2FA code field appears when required; recovery from the login screen; SSO
  button when OIDC is configured. Clipboard fallback for plain-http origins.
- Checks: `ops/checks/ui-e2e.mjs` — 56 assertions in a real browser on a fresh vault
  (`ops/checks/e2e-stack.sh`), including a real machine-API read with a token created in the
  UI and a real share-link open; `ui-i18n.mjs` adapted; English dictionary regenerated (378 keys).
- Removed: the Tailwind bundle; styles are one hand-written `app.css` with design tokens.

## 0.6.0 — 2026-10-03

**Cluster mode.** Several replicas behind a load balancer share one PostgreSQL and behave as
one vault — `docs/CLUSTER.md`, reference deployment `deploy/cluster/`.

- `VAULT_DATABASE_URL`: PostgreSQL (psycopg 3) as the store; SQLite stays the single-node default.
- UI sessions live in the database; the master key is wrapped into the session row under a key
  derived from the cookie value (HKDF-SHA256) and unwrapped per request — any replica serves any
  session, a database dump holds no usable key. `POST /api/auth/lock?all=1` drops every session.
- The master-password verifier and recovery material moved from `data/config.json` into the
  database (`vault_config`); a legacy file is imported on first start.
- `GET /api/ready` (503 when the database is unreachable) for load balancers; `/api/health` adds
  `node` and `db`. Metrics: `aps_vault_sessions_active`, `node` label on `aps_vault_info`.
- Schema creation tolerates replicas starting simultaneously; migrations are dialect-aware.
- `backend/tests/test_cluster.py`: two real nodes on one database — init, session hand-over,
  lock, shared brute-force budget, tokens/KV facade, recovery, node loss. `./run_tests.sh pg`
  runs the whole suite against PostgreSQL 16.
- **Fixed:** service tokens stopped working after a password recovery (the token key is salted
  with the folder nonce, which recovery used to regenerate). Found by the cluster test.
- OIDC: an SSO login needs a master unlock on the same replica (or `VAULT_MASTER_PASSWORD`);
  documented in `docs/CLUSTER.md`.

## 0.5.1 — 2026-10-03

- HashiCorp Vault / Deckhouse Stronghold compatibility extended: `lookup-self`,
  `sys/seal-status`, `sys/internal/ui/mounts`, `LIST`/metadata, KV v2 write; errors in
  HashiCorp's shape; verified with the official `hvac` client. `docs/COMPATIBILITY.md`.
- Backend runs uvicorn with the h11 parser (the `LIST` method).

## 0.5.0 — 2026-10-02

Observability and access control:
- Syslog/SIEM forwarding of every audit event (RFC 5424 over UDP/TCP; JSON or CEF payload).
- Prometheus `/metrics` behind `VAULT_METRICS_TOKEN`; `GET /api/security/lockdowns`.
- PAM-style policies: `allowed_cidrs` / `allowed_hours` per service token, `VAULT_UI_ALLOWED_*`
  for the human UI; denials audited, forwarded and written to the fail2ban log.
- fail2ban: security log, filter, jail generator, `sync-bans.sh`.
- Persistent lock-out now emits `auth:lockdown`.
- HashiCorp KV v2 compatible read facade: `GET /v1/<folder>/data/<name>` with `X-Vault-Token`.

UI and ecosystem:
- English UI with a language switch (RU/EN), browser-language default.
- Token form: allowed networks and hours.
- Browser extension published separately (configurable vault URL, en/ru):
  https://github.com/kzhebenev/aps-vault-extension

## 0.4.0 — 2026-10-02 (first public release)

Security (see `docs/SECURITY-REVIEW-2026-10-02.md`):
- Client IP for the brute-force limiter is taken only from a trusted proxy and only the hop we
  control (`VAULT_PROXY_HOPS`); a client-supplied `X-Forwarded-For` / `X-Real-IP` no longer
  resets the budget. Failed attempts persist in the database (per-IP and global limits).
- CORS origins come from `VAULT_ALLOWED_ORIGINS`; no implicit localhost or any-extension origin.
- `POST /api/init` requires `VAULT_INIT_TOKEN`.
- Secret and webhook URLs must be `http(s)://`; webhooks refuse private/loopback targets
  unless `VAULT_WEBHOOK_ALLOW_PRIVATE=1`.
- Webhooks are now actually delivered (`secret:*`, `token:*`) with HMAC-SHA256 signatures.
- OIDC discovery and JWKS are fetched over https only.
- Removed unused `python-jose` (known CVEs) and `slowapi`.
- Container runs as uid 10001; backend port is no longer published.
- Tailwind is bundled (no CDN at runtime), CSP `script-src 'self'`.
- Share-link use counter is consumed atomically.
- API error messages in English.

Project:
- Configuration via environment (`.env.example`), no hard-coded hostnames.
- Clients: Python (stdlib), Node, Go, Java — all dependency-free, with cache, retries and
  fail-open-on-stale-cache; examples.
- Tests: crypto, auth, brute-force budget, CSRF, CORS, token scope, share links, webhooks,
  recovery, Python client end-to-end (33 backend tests), Go/Java/Node client tests; CI.
- Documentation: README (en/ru), ARCHITECTURE, API, DEPLOYMENT, SECURITY, CONTRIBUTING.

## 0.3.3 — 2026-06-19
- OIDC login (Authorization Code + PKCE) via Keycloak or any OpenID Connect provider.

## 0.3.2 — 2026-06-18
- `login` as a separate encrypted field of a secret (UI, machine API, CLI).

## 0.3.1 — 2026-06-10
- Machine API write: `POST /api/v1/m/secret/{name}` gated by per-token `can_write`.
- `vault put` in the CLI; fixed a command-injection in `vault get-all` (`shlex.quote`).
- MCP server (`mcp/`) for AI agents: `health / list / get / put`.

## 0.3.0 — 2026-06-08
- Cmd+K search, secret history, one-time share links, stats, favorites, auto-lock after 15 min,
  JSON export/import, CLI, drag-and-drop credential parsing, folder tree.
- Browser extension 0.1.0 (Chrome/Firefox MV3), Python and Node clients, backup script.

## 0.2.0 — 2026-06-08
- Hardening: CSRF double-submit, security headers, TOTP second factor on the master password,
  recovery code with master-key re-wrap.
- Per-client session check in `/api/health`.

## 0.1.0 — 2026-06-08
- First version: Argon2id + AES-256-GCM, envelope encryption per folder, folder-scoped
  service tokens, machine API, audit log.
