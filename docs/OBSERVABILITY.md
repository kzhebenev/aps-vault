# Observability: syslog/SIEM, Prometheus, fail2ban

Every audit event (unlock, failed attempt, lock-out, secret read/write, token use, policy
denial, share-link open…) is written to the database **and** fanned out to the integrations
below from a single call site, so they never disagree.

## Syslog / SIEM

```
VAULT_SYSLOG_URL=udp://siem.example.com:514     # or tcp://host:514
VAULT_SYSLOG_FORMAT=json                        # json (default) | cef
```

Messages are RFC 5424 (`<PRI>1 TIMESTAMP HOST aps-vault - ACTION - MSG`), facility `authpriv`.
Severity: failures and lock-outs 3–4 (error/warning), administrative changes 5 (notice),
reads 6 (info).

- **json** — the event as a JSON object: `{"action","actor","target","ip","ua","meta","version"}`.
- **cef** — ArcSight CEF for SIEMs that prefer it:
  `CEF:0|APS|Vault|0.5.0|auth:fail|auth fail|7|rt=… act=auth:fail suser=master src=203.0.113.5 cs1Label=target cs1=…`
  Severity 0–10 per action (lock-out 9, failed auth 7, token use 3).

Delivery is best-effort in a background thread; a SIEM outage never fails a request.
`aps_vault_siem_errors_total` counts drops. TCP uses a persistent connection with reconnect.

Actions worth alerting on: `auth:fail`, `auth:totp_fail`, `auth:recover_fail`, `m:auth:fail`,
`auth:lockdown`, `auth:policy_denied`, `m:auth:policy_denied`, `vault:init_denied`,
`export:json`, `auth:recover`, `token:create`.

## Prometheus

```
VAULT_METRICS_TOKEN=<random>        # unset → /metrics does not exist
```

```yaml
scrape_configs:
  - job_name: aps-vault
    scheme: https
    authorization: { credentials: <random> }
    static_configs: [{ targets: ['vault.example.com'] }]
```

| Metric | Type | Meaning |
|---|---|---|
| `aps_vault_info{version}` | gauge | build info |
| `aps_vault_unlocked` | gauge | 1 while the master key is in memory |
| `aps_vault_secrets`, `aps_vault_folders`, `aps_vault_tokens_active` | gauge | inventory (from the DB at scrape) |
| `aps_vault_locked_ips` | gauge | addresses currently over the failed-attempt budget |
| `aps_vault_events_total{action}` | counter | audit events since start |
| `aps_vault_auth_failures_total`, `aps_vault_policy_denials_total`, `aps_vault_lockdowns_total` | counter | security signals |
| `aps_vault_machine_reads_total` | counter | machine-API secret reads |
| `aps_vault_webhook_deliveries_total{status}` | counter | webhook attempts |
| `aps_vault_siem_events_total`, `aps_vault_siem_errors_total` | counter | forwarder health |

Suggested alerts: `increase(aps_vault_auth_failures_total[10m]) > 20`,
`aps_vault_lockdowns_total` increasing, `aps_vault_policy_denials_total` increasing (a token
used from the wrong place), `aps_vault_unlocked == 0` for longer than your restart window.

## fail2ban

```
VAULT_SECURITY_LOG=/app/data/security.log     # inside the container → ./data/security.log on the host
```

One line per failed attempt, in a fixed format:

```
2026-10-02 19:00:00 aps-vault auth-fail ip=203.0.113.5 kind=master
2026-10-02 19:00:03 aps-vault auth-fail ip=203.0.113.5 kind=token
2026-10-02 19:00:09 aps-vault auth-fail ip=203.0.113.5 kind=policy token=7
```

`ops/fail2ban/aps-vault.conf` is the filter; `ops/fail2ban/gen-jail.sh --install` writes the
jail (`LOGPATH`, `PORTS`, `MAXRETRY`, `FINDTIME`, `BANTIME` as environment variables) and
reloads fail2ban. The vault's own lock-out (5 per IP / 15 min, persisted) stays in place;
fail2ban adds a network-level ban in front of the reverse proxy.

`ops/fail2ban/sync-bans.sh` goes the other way: it reads `GET /api/security/lockdowns`
(Bearer `VAULT_METRICS_TOKEN`) and bans those addresses in the jail — useful when the
reverse proxy is on another host than the vault.

> The IP in the log is the client address as resolved through `VAULT_PROXY_HOPS`; with the
> wrong hop count you would ban your own proxy. Check `GET /api/audit` first.
