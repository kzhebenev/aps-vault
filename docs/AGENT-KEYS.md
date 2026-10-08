# Agent keys — machine access for AI sessions and automation (0.41.8)

An AI session (or a script) that has to create a folder, issue a service token, invite a user or grant a role needs
the owner. Until 0.41.8 that meant the master password — typed by a person, or sitting in `VAULT_MASTER_PASSWORD`.
An **agent key** is the third way: the owner issues it once, and from then on the agent works on its own, within an
allow-list, under its own name in the audit log.

## Issue, use, revoke

Settings → **Keys for AI agents** → *Create key*: a name (Latin, it is what the audit log shows), optionally the
networks it may be used from and a lifetime. The key (`vlt_agent_…`) is shown **once**.

```bash
# the agent: exchange the key for a session (like unlocking with the master password)
curl -c jar -X POST $VAULT/api/auth/agent -H 'Content-Type: application/json' -d '{"key":"vlt_agent_…"}'   # → csrf_token
# then the ordinary human API with that session
curl -b jar -X POST $VAULT/api/folders -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"name":"delivery-keys"}'
curl -b jar -X POST $VAULT/api/tokens  -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
     -d '{"name":"battlecard-delivery-keys-write","folder_id":7,"can_write":true}'
```

Revoke it on the same screen (`DELETE /api/agent-keys/{id}`): the key stops working and **every session it opened
ends at once**, on every replica.

## What an agent may do — and never

| Allowed | Never |
|---|---|
| folders: list, create, delete an empty one | master password: change, recovery, 2FA, security keys |
| secrets: read, create, change, delete, history, rotation settings | SSO / HSM / KMS cells |
| service tokens: issue, change, revoke, token watch | backups: key, settings |
| users: create, invite, grants, remove | webhooks, approvals settings |
| enrolment codes | export and import |
| audit log, stats | updates |
|  | folder-key rotation |
|  | agent keys — an agent cannot mint another agent |

Inside the allowed areas an agent is held like a folder manager wherever a flag keeps a value away from people
(0.41.9): it cannot issue a token or an enrolment code for a folder that holds 'machines only' / 'requires approval'
secrets, cannot move such a secret to another folder, cannot point a rotation of such a secret at an http receiver or
configure rotation through an administrator credential, and cannot lock everyone's sessions (`lock?all=1`). Reading
such a secret it gets what the owner gets in the UI — no value for 'machines only', the approval gate for 'requires
approval' — and lifting either flag needs the master password.

The list is an allow-list in `backend/authz.py` (`_AGENT_PATHS`): anything not on it is refused, so a new endpoint is
closed to agents until someone decides otherwise. Managing agent keys additionally requires the owner in person
(`_human_owner_only`), a second lock.

## How it is protected

- The key carries the master key wrapped under the suite's token KDF of the raw key with a random salt — exactly how a
  service token carries its folder key. The database holds the ciphertext and a look-up hash; it opens nothing.
- Every request of an agent session re-checks the key: revoked or expired → the session is closed; outside the allowed
  networks → 403.
- Wrong keys count against the same attempt limit as the master password.
- The audit log names the actor `agent:<name>` (`auth:agent`, `folder:create`, `token:create`, …).

## What it means

An agent key is **owner-level access to everything on the allowed list**: whoever holds it can read every secret.
Treat it like the master password — a file readable only by the agent's account, never in a repository, a chat or
a prompt. Give each agent (or each machine) its own key, bind it to the networks it works from, and revoke it when the
agent is retired. It replaces `VAULT_MASTER_PASSWORD` in the environment, which gave the same power to anyone who could
read the environment or a backup of it, without a name in the audit log and without a way to revoke it.

## Verified how

`backend/tests/test_owner_agent_keys.py`: the key shown once, nothing usable in the database; the agent creates a folder, a
secret, a token that then reads through the machine API, a user and a grant, the audit names it; 13 owner-only actions
refused **by the allow-list** (the test fails when the allow-list is switched off — 10 of 13, the other three are held
by the second lock); wrong, malformed, revoked and expired keys refused, revocation and expiry also end open sessions;
a foreign network refused; names unique; 0.41.9 — no token or enrolment for a flagged folder, no move of a flagged
secret (also closed for a writer of both folders), no http receiver / administrator-credential rotation, no lock of
everyone — each test failed before its fix. `ops/checks/ui-e2e.mjs`: issued on the Settings screen, shown once, opens a
session that creates a folder and is refused export and minting a key, revoked on the screen → its session closed, the
key opens nothing.
