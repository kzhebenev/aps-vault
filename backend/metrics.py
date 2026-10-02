"""Prometheus exposition without a client library (text format 0.0.4).

Counters live in the process (single worker by design); gauges are computed at scrape time
from the database so a restart does not lie about the inventory. `/metrics` is protected by
`VAULT_METRICS_TOKEN` — a secrets manager must not announce its activity to anyone who can
reach the port.
"""
from __future__ import annotations

import threading
from collections import Counter

_lock = threading.Lock()
_events: Counter = Counter()          # action → count
_webhooks: Counter = Counter()        # status → count


def record(action: str) -> None:
    with _lock:
        _events[action] += 1


def record_webhook(status: str) -> None:
    with _lock:
        _webhooks[status] += 1


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(version: str, unlocked: bool, secrets: int, folders: int, tokens_active: int,
           locked_ips: int, siem_sent: int, siem_errors: int) -> str:
    with _lock:
        events = dict(_events)
        hooks = dict(_webhooks)
    out = [
        "# HELP aps_vault_info Build information.", "# TYPE aps_vault_info gauge",
        f'aps_vault_info{{version="{_esc(version)}"}} 1',
        "# HELP aps_vault_unlocked 1 when the master key is held in memory.", "# TYPE aps_vault_unlocked gauge",
        f"aps_vault_unlocked {1 if unlocked else 0}",
        "# HELP aps_vault_secrets Number of secrets stored.", "# TYPE aps_vault_secrets gauge", f"aps_vault_secrets {secrets}",
        "# HELP aps_vault_folders Number of folders.", "# TYPE aps_vault_folders gauge", f"aps_vault_folders {folders}",
        "# HELP aps_vault_tokens_active Service tokens not revoked and not expired.", "# TYPE aps_vault_tokens_active gauge",
        f"aps_vault_tokens_active {tokens_active}",
        "# HELP aps_vault_locked_ips Client addresses currently over the failed-attempt budget.", "# TYPE aps_vault_locked_ips gauge",
        f"aps_vault_locked_ips {locked_ips}",
        "# HELP aps_vault_events_total Audit events since process start, by action.", "# TYPE aps_vault_events_total counter",
    ]
    for action, n in sorted(events.items()):
        out.append(f'aps_vault_events_total{{action="{_esc(action)}"}} {n}')
    fails = sum(n for a, n in events.items() if a in ("auth:fail", "auth:totp_fail", "auth:recover_fail", "m:auth:fail"))
    denied = sum(n for a, n in events.items() if a.endswith("policy_denied") or a == "vault:init_denied")
    out += [
        "# HELP aps_vault_auth_failures_total Failed unlock/recover/token attempts since start.", "# TYPE aps_vault_auth_failures_total counter",
        f"aps_vault_auth_failures_total {fails}",
        "# HELP aps_vault_policy_denials_total Requests refused by source/time policy since start.", "# TYPE aps_vault_policy_denials_total counter",
        f"aps_vault_policy_denials_total {denied}",
        "# HELP aps_vault_lockdowns_total Lock-outs triggered since start.", "# TYPE aps_vault_lockdowns_total counter",
        f"aps_vault_lockdowns_total {events.get('auth:lockdown', 0)}",
        "# HELP aps_vault_machine_reads_total Secret reads through the machine API since start.", "# TYPE aps_vault_machine_reads_total counter",
        f"aps_vault_machine_reads_total {events.get('m:secret:read', 0)}",
        "# HELP aps_vault_webhook_deliveries_total Webhook delivery attempts by status.", "# TYPE aps_vault_webhook_deliveries_total counter",
    ]
    for st, n in sorted(hooks.items()):
        out.append(f'aps_vault_webhook_deliveries_total{{status="{_esc(st)}"}} {n}')
    out += [
        "# HELP aps_vault_siem_events_total Events forwarded to syslog/SIEM.", "# TYPE aps_vault_siem_events_total counter",
        f"aps_vault_siem_events_total {siem_sent}",
        "# HELP aps_vault_siem_errors_total Syslog/SIEM forwarding errors.", "# TYPE aps_vault_siem_errors_total counter",
        f"aps_vault_siem_errors_total {siem_errors}",
    ]
    return "\n".join(out) + "\n"
