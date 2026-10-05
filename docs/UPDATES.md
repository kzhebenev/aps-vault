# Updates (0.38)

**Settings → Updates** shows the installed version, what the release channel offers with its release notes, the
history of every version with its notes, and — when a newer release exists and an update agent is connected — an
**Update to X** button. The owner confirms with the master password; the agent updates the installation, keeps a
backup, and returns to the previous version if the new one does not come up healthy.

```
 browser ── owner + master password ──► vault: job "update to X" (audit: update:requested)
                                             ▲            │
                       agent polls every 15 s│            │ job
                                             │            ▼
                         ┌──────────── updater container (Docker socket) ───────────────┐
                         │ 1. X is a published release in the channel (agent's own read) │
                         │ 2. X is newer than VAULT_VERSION in .env                      │
                         │ 3. cosign: backend/frontend/updater:X signed by the release   │
                         │    workflow for tag vX; pulled digest == signed digest        │
                         │ 4. stop backend → back up the data volume → VAULT_VERSION=X   │
                         │ 5. start, wait for /api/health = X → report done → replace    │
                         │    itself;  not healthy → restore .env + data, start the old  │
                         └───────────────────────────────────────────────────────────────┘
```

## Install with the agent

The installation from the release images includes the agent:

```bash
git clone https://github.com/kzhebenev/aps-vault && cd aps-vault
deploy/images/install.sh /opt/aps-vault                       # latest release; or: install.sh /opt/aps-vault 0.38.0 https://vault.example.com
```

`install.sh` writes `/opt/aps-vault/docker-compose.yml` and `/opt/aps-vault/.env` (mode 0600) with a fresh init
token and agent token, pulls the images and starts three services: `backend`, `frontend` and `updater`. Data lives in
the named volume `<project>_vault-data`; backups made before each update go to `/opt/aps-vault/backups/` (last five,
mode 0600).

An installation of your own (Kubernetes, Swarm, Nomad, a build from source) does not need the agent: update the
image tags with your tooling. The page still shows new releases and their notes; the button stays disabled and says
why.

## Settings

| Variable | Where | Meaning |
|---|---|---|
| `VAULT_UPDATE_CHANNEL` | backend, updater | where releases are announced; default the project's GitHub Releases API. A mirror must serve the same JSON shape. `off` on the backend = no outbound call; the page shows the notes built into the image |
| `VAULT_UPDATE_AGENT_TOKEN` | backend, updater | shared secret of the agent (≥32 random characters, `install.sh` generates it). Empty on the backend = the agent API answers 401 |
| `VAULT_INSTALL_DIR` | updater | the directory with `docker-compose.yml` and `.env`, mounted into the agent **at the same path** (compose resolves paths on the host) |
| `VAULT_UPDATE_VERIFY` | updater | `cosign` (default) or `off`. `off` is for an air-gapped mirror whose images you verify yourself; the page and the agent's log say it out loud |
| `VAULT_UPDATE_IMAGE_REPO`, `VAULT_UPDATE_IDENTITY` | updater | for a fork: its registry path and the certificate identity of its release workflow (`…/release.yml@refs/tags/v{version}`) |
| `VAULT_UPDATE_POLL_SEC`, `VAULT_UPDATE_HEALTH_SEC` | updater | poll interval (15 s) and how long the new version may take to answer healthy (240 s) |

The channel follows the rules of every outbound call since 0.37: https to a globally routable address, no redirects;
plain http and private addresses only with `VAULT_WEBHOOK_ALLOW_PRIVATE=1`. The answer is capped at 2 MB, drafts and
pre-releases are never offered.

## Why the vault cannot make the agent run something else

The agent holds the Docker socket — whoever controls it controls the host. So the vault only records *which version*
the owner asked for, and the agent decides on its own:

- the version must be a published, non-prerelease release in the channel **the agent reads itself**;
- it must be newer than what runs (`VAULT_VERSION` in `.env`) — no downgrades, migrations only go forward;
- each image must carry a Sigstore signature whose certificate identity is the project's release workflow **for that
  tag** (`https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/vX`, issuer
  `https://token.actions.githubusercontent.com`), and the image Docker pulled must have exactly the signed digest;
- the image names are fixed (`ghcr.io/kzhebenev/aps-vault/{backend,frontend,updater}`); nothing in the job can change
  them.

A compromised vault process can therefore at most ask for an authentic newer release. The vault side adds its own
checks: only the owner, the master password again (wrong attempts count towards the lock-out), the version must be in
the channel and newer, one job at a time, a job is handed to exactly one agent. Every step is in the audit log:
`update:check`, `update:requested`, `update:apply_fail`, `update:picked`, `update:done` / `update:failed`,
`update:cancelled`, `update:agent_denied`; `update:done` / `update:failed` are also webhook events.

## Backups and rollback

With SQLite (the default) the agent stops the backend, archives the data volume, then switches the version. If the
new version is not healthy within `VAULT_UPDATE_HEALTH_SEC`, the agent puts back the previous `.env` and the archive
and starts the previous version; the job ends as *failed — rolled back to X* with the agent's log on the page. With
`VAULT_DATABASE_URL` (PostgreSQL) the agent does not touch the database — back it up with your own tooling before
updating; the log says so.

A refused job (not in the channel, not newer, signature or digest mismatch) changes nothing: the running vault is not
stopped.

## Known issue in 0.38.0 and 0.38.1

Agents of these two releases could not replace themselves: after an update the vault runs the new version, but the
`updater` service is left stopped. Run `docker compose up -d updater` in the installation directory once; agents from
0.38.2 on hand over to a helper container and come back by themselves.

## API

```http
GET  /api/update/status              owner → {installed, latest, available[], channel{enabled, host, checked_at, error},
                                               agent{configured, connected, agent_id, last_seen, verify, …}, job, history[]}
POST /api/update/check               owner → the same after asking the channel now
POST /api/update/apply               owner {version, master_password} → job (401 wrong password, 409 no agent / a job in
                                                                                progress, 422 not newer / not published)
POST /api/update/jobs/{id}/cancel    owner — only a job no agent has picked up yet

GET  /api/agent/update?agent_id=…&current=…&verify=…      Bearer <agent token> → {job | null}   (heartbeat)
POST /api/agent/update/{id}?agent_id=…   {state: running|done|failed, step, log}
```

## Release notes

The notes of the installed and older versions come from `backend/release_notes.json`, generated from `CHANGELOG.md`
(`ops/release-notes.py json`; a test fails when it is stale), so they are there without network. Newer versions come
from the channel: the GitHub Release body, which the release workflow fills from the same CHANGELOG section
(`ops/release-notes.py section X`; a missing section fails the release).

## Verified how

- `backend/tests/test_updates.py` — the real GitHub API answer as fixture; owner only; channel rules (http, private
  address, redirect, junk, oversize, off); wrong password, not newer, not published, no agent, CSRF; one agent gets
  the job; another agent cannot report on it; cancel.
- `agent/tests/test_updater.py` — fake docker/cosign/vault: the order pull → stop → backup → start → health → replace
  itself; refused jobs change nothing; an unsigned image or a different digest stops before the vault is touched; a
  version that does not come up is rolled back **with its data**; PostgreSQL installs are not backed up by the agent.
- `ops/checks/ui-e2e.mjs` — the page in Chrome: notes rendered without markup from the channel, the button disabled
  without an agent, wrong password visible, the job's progress and the agent's log.
- Live, 05.10.2026, real GitHub channel, real signed images, a stand made by `install.sh` with a secret in it, the
  button pressed in Chrome:
  - **0.38.0 → 0.38.1** in 38 s: three signatures, digests matched, backup, healthy, the page reloaded itself, the
    session and the secret survived — but the agent did not come back (it recreated its own container from inside;
    fixed in 0.38.2, see the known issue above);
  - **0.38.1 → 0.38.2** (agent 0.38.2) in 42 s: the same, and the agent replaced itself through the helper container
    and called in again as 0.38.2 within seconds;
  - **0.38.2 → 0.38.3** with no hand on the stand at all (installation and agent both 0.38.2): 40 s, the agent came back
    as 0.38.3 by itself.
