# Token watch (0.26)

A service token is a bearer credential: whoever holds it reads the folder. Access policies
(`docs/ACCESS-POLICIES.md`) say where and when a token *may* be used. The token watch says
whether it is being used *as usual* — and what to do when it is not. It needs nothing
configured: every token gets a profile from its first call.

```
   machine API call ──▶ policy (where/when/mTLS) ──▶ frozen? ──▶ watch.observe ──▶ anomalies?
                                                        │403                       │
                                                        ▼                          ▼
                                                   refused               alert: audit + webhook + notifier
                                                                         freeze: … and the token stops (403)
                                                                         canary: … and the caller sees 401
```

## What it notices

| anomaly | when | typical cause |
|---|---|---|
| **new network** | a call from a /24 (IPv4) or /48 (IPv6) never seen before, once the token has a history (`VAULT_WATCH_LEARN_USES` calls, default 20) | the token left its host: a leaked `.env`, a laptop, an attacker |
| **two networks at once** | two *known* networks within `VAULT_WATCH_PARALLEL_SEC` (120 s) | the token was copied and is used in two places |
| **rate spike** | more than `VAULT_WATCH_RATE_MIN` (300) calls in 10 minutes and more than `VAULT_WATCH_RATE_FACTOR` (10) × the token's usual 10-minute rate | a script dumping the folder, a retry storm |
| **enumeration** | `VAULT_WATCH_ENUM_MIN` (10) secrets the token never read before inside one 10-minute window | someone exploring what the token can reach |
| **canary** | **any** use of a canary token | the place where the canary was planted has been read by someone |

The learning period exists because an installer, a CI runner and the application itself may
legitimately call from different places in the first minutes. After it, a network that
appears is **pending**: it keeps feeding its alert (the alert's counter grows instead of a new
line per call) until a manager presses *Trust network* — then it is known, and two known
networks seconds apart become the *two places at once* signal. Repeats of one anomaly fold into
one alert for an hour.

## What happens

Per token, `on_anomaly`:

- **alert** (default) — the call goes through; the alert is written to the audit log
  (`token:anomaly`, actor `token:<id>`), sent to webhooks (`token:anomaly` with the kind, the
  network, a one-line text) and to the HTTP notifier if one is configured
  (`VAULT_APPROVAL_NOTIFY_URL` — the same receiver as approval requests; `{reason}` carries the
  kind, `{secret}` the token name, `{url}` the Tokens page), and to the security log (`anomaly`,
  for fail2ban).
- **freeze** — the same, and the token is frozen: every call answers
  `403 token is frozen by the token watch (<kind>) — a folder manager can unfreeze it in Tokens`
  until *Unfreeze*. The audit shows `m:auth:frozen` for each refused call.

A **canary** is a token nobody should ever use: plant it where a thief would look — an old
`.env` in a repository, a CI variable of a retired pipeline, a note in a wiki — and forget it.
Any use is an alert and a freeze, and the caller gets the generic `401 invalid service token`,
nothing that says "you tripped something". Unfreezing a canary does not make it a working
token; the next use trips it again. Make the canary's folder a decoy with plausible fake
secrets, so the thief has nothing real to read even in the few milliseconds before the freeze.

## Where it shows

- **Tokens page**: open alerts on top — token, what was noticed (with the known networks, the
  two networks and the seconds between them, the counts), from where, when — and the actions:
  *Unfreeze*, *Trust network*, *Revoke*, *Dismiss*. Badges on the rows: canary, frozen,
  auto-freeze, alert count. The sidebar shows the number of open alerts.
- **New token**: *Service* / *Canary* tiles, *On anomaly: notify / freeze*.
- **Audit**: `token:anomaly`, `token:freeze`, `token:unfreeze`, `token:trust_network`,
  `token:alert_ack`, `token:leak_check`, `m:auth:frozen`. **Webhooks**: `token:anomaly`,
  `token:freeze`, `token:unfreeze`. **Metrics**: `aps_vault_token_alerts_open`.

Folder **managers** see and act on alerts of their folders; the owner on all. Revoking a token
closes its incident: its open alerts are acknowledged with it (also when `leak-check` revokes).

## Leaked tokens

Alerts catch a token that is *used*. `ops/leak-scan.py` catches a token that is *lying
around*: it scans files, directories, a git history or anything on stdin for the token shape
(`vlt_<12 base32>_<64 hex>`), hashes every hit the way the vault stores token hashes and asks
`POST /api/tokens/leak-check` which hashes belong to live tokens — the tokens themselves never
travel. `--revoke` revokes the matches on the spot; the exit status is 2 when live tokens were
found, so a CI step can fail the build.

```bash
ops/leak-scan.py . --url https://vault.example.com                 # a checkout
git log -p | ops/leak-scan.py - --url https://vault.example.com      # the whole history
gh search code 'vlt_' --owner my-org --json textMatches -q '.[].textMatches[].fragment' \
  | ops/leak-scan.py - --url https://vault.example.com --revoke     # GitHub, with the gh CLI
```

The owner's master password is asked for (or `VAULT_MASTER_PASSWORD`), because knowing which
hashes are live is an owner's question. Run it from the vault host or from a CI job that
holds the master password in its secret store — never commit it.

## Tuning and turning off

`VAULT_WATCH=0` disables the rules (profiles are still kept). `VAULT_WATCH_LEARN_USES`,
`VAULT_WATCH_PARALLEL_SEC`, `VAULT_WATCH_RATE_MIN`, `VAULT_WATCH_RATE_FACTOR`,
`VAULT_WATCH_ENUM_MIN` adjust the thresholds. A token behind NAT shared by many hosts looks like
one network — that is fine for *new network* and bad for *two places at once*; a token used from
a mobile network changes /24 often — give it a `freeze`-free policy and trust the networks, or
restrict it with `allowed_cidrs` instead.

## What it is not

Not a replacement for policies (`allowed_cidrs`, hours, mTLS) — those are enforcement, this is
detection. Not proof of compromise: a new office or a new CI runner also looks new; the
manager decides. Time-of-day anomalies are deliberately not a rule (too noisy); use
`allowed_hours` when hours matter.

## Verified

`backend/tests/test_token_watch.py`: normal use from the usual network raises nothing; a new
network after learning raises one alert (webhook and audit seen), the call still succeeds,
repeats fold into the counter, *trust network* silences it; `freeze` makes the token answer
403 for everyone until unfrozen, manual freeze works, the policy can be changed; two known
networks within seconds raise *two places at once* while a pending network does not; a rate
spike and an enumeration are caught; a canary trips on first use, is frozen, answers the
generic 401, and trips again after an unfreeze; leak-check matches a live token by hash only,
revokes on request and is the owner's; a manager sees alerts of their folders only; the metric
is exposed. The browser check creates a canary, trips it from the page's own fetch, sees the
alert and the frozen badge, and revokes from the alert.
