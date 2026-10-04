# Rotation in target systems (0.24)

Until 0.23 "rotation" meant a new value *inside the vault*: the server generated it, the old
one became a numbered version, and somebody still had to carry the new value into PostgreSQL,
the message broker or the API that actually checks it — or forget to. 0.24 closes the loop.
The vault changes the credential **in the target first**, proves that the new one works, and
only then stores it as the next version. If the target refuses, nothing changes anywhere.

```
                    generate ──▶ apply in the target ──▶ verify ──▶ store in the vault ──▶ webhook
   PostgreSQL:      alnum:32     ALTER ROLE … PASSWORD    log in as the role     version N+1       secret:update {rotated: true}
   HTTP receiver:   base64:32    signed POST {value}      2xx from the receiver  version N+1       secret:update {rotated: true}
   on failure:                   ◀── RotationError ───    old password restored  nothing stored    rotation:fail
```

Consumers keep working the way they already do: service tokens read the current value, caches
expire (the client libraries re-read on a `secret:update` webhook or when their TTL runs out),
and `?version=N` still returns the previous value while a slow consumer catches up.

## Targets

**PostgreSQL.** The rotation names a second secret whose value is an **administrator
connection string** (`postgresql://admin:…@host:5432/db`). The vault connects with it, runs
`ALTER ROLE "<role>" WITH PASSWORD '<new>'` — the role is the secret's *login* unless the
rotation sets its own — and then **logs in as that role with the new password**. Only a
successful probe counts as "applied". When the probe fails (the role is `NOLOGIN`, `pg_hba`
refuses, the database is wrong) the old password is put back with a second `ALTER ROLE` and
the run is reported as failed; the vault still holds the old value, which still works.
Options: `sslmode`, `connect_timeout`, `verify_dbname` (probe against another database),
`verify: false` to skip the probe (not recommended).

Mark the DSN secret **machine-only**: nobody needs to read it, the vault does. Mind that
PostgreSQL servers with `log_statement = all` write `ALTER ROLE` statements, passwords
included, into their log — that is a server setting, not something the vault can avoid.

**MySQL / MariaDB** (0.30). The same shape as PostgreSQL: a secret with an administrator DSN
(`mysql://root:…@host:3306/db`), `ALTER USER 'user'@'host' IDENTIFIED BY …` where the user is the
secret's login (or the rotation's `role`) and the host pattern is `user_host` (default `%`), a login
probe as that user, and the old password put back when the probe fails (a locked account, for
instance). Verified against MariaDB 11.

**HTTP receiver.** For everything that has no `ALTER ROLE` — Kafka and RabbitMQ users, LDAP,
a cloud console, an in-house API — you run a small service that knows how to set the password
there, and the vault calls it:

```http
POST https://rotate.example.com/hook
Content-Type: application/json
X-Vault-Event: rotation
X-Vault-Signature: sha256=<HMAC-SHA256 of the body with the signing secret>

{"event":"rotation","secret":"broker-pass","folder":"apps","login":"app_broker",
 "value":"<the new value>","version":7,"ts":"2026-10-03T20:00:00Z"}
```

Any `2xx` means "applied"; anything else (or no answer within the timeout) means "refused",
and the vault keeps its old value. The signing secret is generated when the rotation is saved
and shown **once** — the receiver uses it to verify that the call comes from the vault and that
the body was not altered. Unlike webhooks, this request **carries the value**, so the URL must
be `https://` and outside private networks unless the server sets
`VAULT_WEBHOOK_ALLOW_PRIVATE=1` (the same guard webhooks use). Method `POST`/`PUT`/`PATCH`,
up to ten extra headers (an `Authorization` for your service, for instance).

A receiver does not have to be complicated — thirty lines of Python that verify the HMAC and
call the broker's admin API are enough. What matters is that it answers `2xx` only after the
password really changed.

## Schedules and the automation cell

A rotation runs **by hand** — the *Run now* button on the card or on the Rotation page, a
`POST` to the API — or **on a schedule**: every 7, 30, 90, 180 days. By hand is easy: the
person who presses the button holds the folder key in their session. A schedule has nobody
there, and the folder key exists nowhere in clear. So a scheduled rotation needs an
**automation cell**: the folder key wrapped under HKDF(`VAULT_ROTATION_KEY`, folder id) —
exactly the construction of the SSO cell, with a server-side key the administrator sets in the
environment (≥ 32 random bytes, the same on every replica). The cell is written when a
scheduled rotation is saved (by a folder manager or the owner, who hold the key), also for the
folder of the administrator-DSN secret, and dropped with the folder's last scheduled rotation.

What this means for your threat model, plainly: a folder with scheduled rotations is readable
to someone who has **both** the database and `VAULT_ROTATION_KEY`. That is the same trust the
SSO cell and the auto-mode KMS cell already ask for; keep the key where you keep the other
server secrets (the deployment's secret store, not the repository). Folders without scheduled
rotations have no cell. Without the key the vault says so: the status endpoint and the
Rotation page show **NOT CONFIGURED**, scheduled rotations are saved but never run, and the
button still works.

The scheduler runs inside every replica (`VAULT_ROTATION_TICK_SEC`, default 60 s). A due row is
taken with one conditional `UPDATE` — the same trick as share-link uses — so two replicas never
rotate the same secret twice. A failed scheduled run is retried after an hour and stays
visible as *error* with the target's message until a run succeeds.

## Where it shows

- **Secret card** → row *Rotation in the system*: target, schedule, last result and the next
  run; *Run now* for writers, *Set up* for managers. Readers see the status.
- **Rotation page** (owner and folder managers): every rotation, status callout (scheduler
  active / not configured, due, failing, folders whose cell is missing because the key
  appeared after they were saved — one button writes them).
- **List**: a badge with the target, green or red by the last run.
- **Audit**: `rotation:set`, `rotation:delete`, `rotation:run` (actor is the person, or
  `scheduler`), `rotation:fail` with the reason, `rotation:cells`.
- **Webhooks**: `secret:update` with `rotated: true` and the target; `rotation:fail`.

## API

```http
PUT    /api/secrets/{id}/rotation      {target: "postgres"|"http", config, interval_days=0, generate?, enabled=true}   manager
       postgres config: {dsn_secret_id, role?, sslmode?, connect_timeout?, verify?, verify_dbname?}
       mysql config:    {dsn_secret_id, role?, user_host?="%", connect_timeout?, verify?}
       http config:     {url, method?="POST", headers?, timeout?}
       → rotation + config (without the signing secret) + scheduler: "active"|"manual"|"unavailable: …" + cells_written;
         signing_secret once, on the first save of an http target
GET    /api/secrets/{id}/rotation      manager — the configuration (signing secret never returned)
DELETE /api/secrets/{id}/rotation      manager
POST   /api/secrets/{id}/rotation/run  writer   → {version, previous_version, note}; 502 with the target's reason when refused
GET    /api/rotations                  everyone, scoped to granted folders → [{secret_id, secret_name, folder_name, target, interval_days, next_at, last_at, last_status, last_error, runs, …}]
GET    /api/rotations/status           → {configured, tick_sec, total, scheduled, due, failing, cells_missing: [folder names]}
POST   /api/rotations/cells            owner — (re)write the automation cells after VAULT_ROTATION_KEY was set or changed
```

`GET /api/secrets` and `GET /api/secrets/{id}` carry a `rotation` field (target, schedule,
last result) or `null`. Moving a secret to another folder moves its rotation (the
configuration is re-wrapped under the new folder's key); deleting the secret deletes it.
Export does not include rotation configurations.

## Not yet

LDAP and SSH targets natively (use an HTTP receiver); two alternating roles for zero-downtime
database rotation. Rotation of the vault's own folder keys exists since 0.30 (`docs/USERS.md`).

## Verified

`backend/tests/test_rotation.py` — against a real PostgreSQL 16 in every test mode: the role's
new password logs in, the **old one is refused**, a `NOLOGIN` role makes the probe fail and the
old password is restored, a broken administrator DSN changes nothing; the HTTP receiver gets
the value with a valid HMAC and the vault stores exactly that value, a `500` keeps the old value
and is audited; roles (reader cannot, writer runs, manager configures); the scheduler does
nothing without the server key, writes cells with it, claims a due row once, retries a failure
in an hour, and the cell disappears with the rotation. The browser check configures an HTTP
rotation from the card, runs it, verifies the signature on the receiving side, and sees the
refusal of a `500` on screen.
