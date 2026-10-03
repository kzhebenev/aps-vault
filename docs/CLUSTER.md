# Running APS Vault as a cluster

Since 0.6 a vault instance keeps **nothing on the node**. Several replicas behind a load
balancer share one PostgreSQL database and behave as one vault: a session opened on replica A
is served by replica B, a lock-out counted on A protects B, recovery on B invalidates every
session on A, a lost replica changes nothing for the clients. The reference deployment is
`deploy/cluster/` (two replicas + nginx + PostgreSQL); the proof is `backend/tests/test_cluster.py`,
which starts two real nodes on one database and exercises every path across them. The suite
runs on SQLite and on PostgreSQL 16 (`./run_tests.sh pg`).

## What moved where

| Was (≤ 0.5, one process) | Now (0.6) |
|---|---|
| master key in process memory after unlock | wrapped into the **session row** under a key derived from the cookie value (HKDF-SHA256); unwrapped per request by whichever replica receives the cookie |
| sessions in a dict | table `ui_sessions` — stores `sha256(cookie)`, the wrapped key, CSRF, expiry; expired rows are dropped lazily |
| `data/config.json` (salt, verifier, recovery cell, 2FA) | table `vault_config`, one row; a legacy file is imported on first start |
| failed-attempt counters | already in the database (`lockdown`) since 0.4 |
| SQLite file | **PostgreSQL** via `VAULT_DATABASE_URL`; SQLite remains the single-node default |

Consequences worth knowing:

- **"Unlocked" is a property of the session, not of the server.** `GET /api/health` reports
  `unlocked` for the caller's cookie; `/metrics` reports `aps_vault_sessions_active` cluster-wide.
- **A database dump does not contain the master key.** It holds ciphertext and hashes of the
  cookies; the unwrapping key exists only in the client's browser for the session's lifetime.
- **Locking** (`POST /api/auth/lock`) drops the caller's session on every replica;
  `POST /api/auth/lock?all=1` drops all sessions — the old "lock the vault".
- **Service tokens** need no session and never did: the machine API and the HashiCorp KV facade
  work on any replica, locked or not.
- **OIDC** proves identity, not the master password. Since 0.10 the cluster answer is the
  **SSO unlock cell**: set `VAULT_SSO_UNLOCK_KEY` (≥32 random bytes, hex or base64, the same on
  every replica, never configured in the IdP), then enable "SSO unlock" in Settings — it asks
  for the master password once and stores the master key in `vault_config` wrapped under
  HKDF(server key). From then on any replica opens a session for an allowed OIDC user.
  Trade-off: a database dump *plus* the server key opens the vault, so keep the key away from
  database backups (an env file or the orchestrator's secret store, not the DB host). Without
  the key the cell is ciphertext; the cell is re-wrapped on password change and recovery.
  `GET /api/auth/oidc/status` shows `sso_unlock: node|cell|env|none` for the replica that
  answered. Without the key the old behaviour remains: SSO works on the replica that saw a
  password unlock, or with `VAULT_MASTER_PASSWORD` (dev).

## Deploying

```bash
cd deploy/cluster
cp .env.example .env            # VAULT_DATABASE_URL, VAULT_INIT_TOKEN, VAULT_PUBLIC_URL …
docker compose --profile standalone up -d --build     # with the bundled PostgreSQL
# or, with your own PostgreSQL in VAULT_DATABASE_URL:
docker compose up -d --build
curl -s http://127.0.0.1:8087/api/health             # {"node":"backend-a",…} / "backend-b"
```

Put your TLS-terminating proxy in front of port 8087 and set `VAULT_PROXY_HOPS=2`
(your proxy + the bundled nginx), so client addresses in the audit log and the lock-outs are
real. Initialise once through the UI or `POST /api/init` — the init token is checked, the
result is visible on every replica immediately.

**Schema**: created on first start by whichever replica wins the race; the others retry and
find the tables. Column additions of later versions are idempotent and dialect-aware. No
separate migration step.

**PostgreSQL requirements**: one database, one role with `CREATE` on it; a few MB per
thousand secrets; the audit log is the only table that grows. `pool_pre_ping` is on, so a
failover of the database (Patroni/HAProxy) needs no restart of the replicas.

**Health for the balancer**: `GET /api/ready` → 200 when the replica reaches the database,
503 otherwise. `GET /api/health` → 200 always, with `db: ok|error`, `node`, `initialized`.
The bundled nginx also takes a replica out after 3 failed requests.

**Scaling**: add a `backend-c` service (copy of `backend-b`) and a line in `nginx-lb.conf`.
Replicas are identical; `VAULT_NODE_NAME` only labels the audit log, health and metrics.

## Operations

- **Backups**: `pg_dump` of the database is a complete backup (secrets, verifier, recovery
  cell, tokens, audit). Without the master password it is ciphertext. The `data/` directory
  of a replica has nothing in it in PostgreSQL mode.
- **Restore**: restore the dump, start the replicas, unlock. Sessions are not restored on
  purpose (they expire anyway); tokens keep working.
- **Upgrading from a single node (SQLite)**: `GET /api/export` from the old instance,
  `POST /api/import` into the new cluster, re-issue service tokens (a token is bound to the
  installation's folder keys). Or keep SQLite — a single node on 0.6 behaves exactly as before,
  with `config.json` imported into the database on first start.
- **Metrics**: scrape every replica; `aps_vault_info{node=…}` tells them apart;
  `aps_vault_sessions_active` and `aps_vault_locked_ips` are cluster-wide values read from the
  shared store, event counters are per replica since its start.

## Next to a clustered application platform

The pattern for a product that already runs a PostgreSQL cluster (Patroni/HAProxy) and
several application nodes: give the vault its own database on that cluster, run one vault
replica per application node (or two dedicated ones), put them behind the same load balancer
under a `/vault/` path or a separate hostname, and hand each application node a service token
scoped to its folder. The application keeps the key cached, so a vault outage is survivable
(see the integration guide for the ValoCloud core, delivered separately).

**PKCS#11 token (0.15):** every replica must reach the same token — a network HSM, or a SoftHSM2
token directory on shared storage; see `docs/HSM.md`.
