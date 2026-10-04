"""Security-event forwarding: syslog/SIEM (RFC 5424 over UDP or TCP, payload JSON or CEF) and
a fail2ban-friendly local log.

Everything here is best-effort and never raises into a request: a SIEM outage must not stop
the vault, and a missing event is reported through the `aps_vault_siem_errors_total` metric
rather than by failing the operation that produced it.

Severity (RFC 5424 / CEF 0-10): failures and lock-outs are the events a SIEM should alert on;
reads are informational; administrative changes sit in between.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import settings

APP = "aps-vault"
FACILITY_AUTH = 10  # authpriv

# action → (syslog severity 0-7, CEF severity 0-10)
_SEVERITY = {
    "auth:fail": (4, 7), "auth:totp_fail": (4, 7), "auth:recover_fail": (4, 7),
    "auth:lockdown": (3, 9), "auth:policy_denied": (4, 8),
    "m:auth:fail": (4, 7), "m:auth:policy_denied": (4, 8),
    "vault:init_denied": (3, 9), "oidc:bad_master_env": (3, 9),
    "auth:recover": (5, 6), "vault:init": (5, 5), "token:create": (5, 5), "token:revoke": (5, 5),
    "export:json": (5, 6), "import:json": (5, 5), "share:create": (5, 4), "share:read": (6, 3),
    "secret:delete": (5, 4), "secret:update": (6, 3), "secret:create": (6, 3),
}
_DEFAULT_SEV = (6, 2)

_lock = threading.Lock()
_tcp_sock: socket.socket | None = None
errors = 0          # counted by metrics
sent = 0


def _severity(action: str) -> tuple[int, int]:
    return _SEVERITY.get(action, _DEFAULT_SEV)


def _cef_escape(v: str, header: bool = False) -> str:
    v = str(v).replace("\\", "\\\\")
    v = v.replace("|", "\\|") if header else v.replace("=", "\\=")
    return v.replace("\r", " ").replace("\n", " ")


def format_cef(ev: dict, version: str) -> str:
    """ArcSight CEF: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension."""
    _, cef_sev = _severity(ev["action"])
    ext = {
        "rt": ev["ts_ms"], "act": ev["action"], "suser": ev.get("actor", ""), "src": ev.get("ip", ""),
        "requestClientApplication": ev.get("ua", "")[:200], "cs1Label": "target", "cs1": ev.get("target", ""),
    }
    if ev.get("meta"):
        ext["cs2Label"] = "meta"
        ext["cs2"] = json.dumps(ev["meta"], ensure_ascii=False)[:1000]
    ext_s = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v not in ("", None))
    return (f"CEF:0|APS|Vault|{_cef_escape(version, True)}|{_cef_escape(ev['action'], True)}|"
            f"{_cef_escape(ev['action'].replace(':', ' '), True)}|{cef_sev}|{ext_s}")


def format_rfc5424(ev: dict, version: str) -> str:
    sev, _ = _severity(ev["action"])
    pri = FACILITY_AUTH * 8 + sev
    ts = datetime.fromtimestamp(ev["ts_ms"] / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    host = socket.gethostname()
    if settings.SETTINGS.syslog_format == "cef":
        msg = format_cef(ev, version)
    else:
        msg = json.dumps({k: v for k, v in ev.items() if k != "ts_ms"} | {"version": version}, ensure_ascii=False)
    return f"<{pri}>1 {ts} {host} {APP} - {ev['action']} - {msg}"


def _send_raw(line: str) -> None:
    global _tcp_sock, errors, sent
    url = urlparse(settings.SETTINGS.syslog_url)
    host, port = url.hostname, url.port or 514
    data = line.encode("utf-8")
    try:
        if url.scheme == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data[:8192], (host, port))
        elif url.scheme == "tcp":
            with _lock:
                if _tcp_sock is None:
                    _tcp_sock = socket.create_connection((host, port), timeout=3)
                try:
                    _tcp_sock.sendall(data + b"\n")        # octet-stuffing framing, non-transparent
                except OSError:
                    _tcp_sock.close(); _tcp_sock = None
                    _tcp_sock = socket.create_connection((host, port), timeout=3)
                    _tcp_sock.sendall(data + b"\n")
        else:
            errors += 1
            return
        sent += 1
    except OSError:
        errors += 1


def send(action: str, actor: str = "", target: str = "", ip: str = "", ua: str = "",
         meta: dict | None = None, version: str = "") -> None:
    """Forward one event to syslog if configured. Never raises."""
    if not settings.SETTINGS.syslog_url:
        return
    ev = {"ts_ms": int(time.time() * 1000), "action": action, "actor": actor, "target": target,
          "ip": ip, "ua": ua, "meta": meta or {}}
    try:
        line = format_rfc5424(ev, version)
        threading.Thread(target=_send_raw, args=(line,), daemon=True).start()
    except Exception:
        global errors
        errors += 1


def security_log(kind: str, ip: str, detail: str = "") -> None:
    """One stable line per failed attempt for fail2ban (ops/fail2ban/aps-vault.conf):
    `2026-10-02 19:00:00 aps-vault auth-fail ip=203.0.113.5 kind=master`"""
    path = settings.SETTINGS.security_log
    if not path:
        return
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{ts} {APP} auth-fail ip={ip} kind={kind}{(' ' + detail) if detail else ''}\n")
    except OSError:
        pass
