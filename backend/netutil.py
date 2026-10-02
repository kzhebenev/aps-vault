"""Client address resolution and brute-force accounting.

Client IP
---------
`X-Forwarded-For` is appended to by every proxy on the way, so the rightmost entries are the
ones our own proxies wrote and the leftmost is whatever the client chose to send. Taking the
first element — as 0.3.x did — let anyone reset the unlock rate limit by sending a header.
Rule here: trust `X-Forwarded-For` only when the TCP peer is a trusted proxy, and then take
the element that is exactly VAULT_PROXY_HOPS positions from the right — the one written by
the outermost proxy we control. "First address from the right that is not a trusted proxy"
is NOT used on purpose: when the real client is itself inside a trusted range (docker host
gateway, office NAT) that heuristic hands the decision back to the attacker's header.
`X-Real-IP` is ignored because plain nginx forwards a client-supplied one untouched.

Failed attempts
---------------
Kept in the `lockdown` table rather than in process memory so that a restart (or a second
worker) does not forget them. Two limits: per IP and global, both over a sliding window — the
global one is what stops a distributed guess from many addresses.
"""
from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import Request

import db
import settings


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in settings.SETTINGS.trusted_proxies)


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if not _trusted(peer):
        return peer or "?"
    hops = settings.SETTINGS.proxy_hops
    chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if hops >= 1 and len(chain) >= hops:
        cand = chain[-hops]
        if _is_ip(cand):
            return cand
    # header shorter than the configured chain (or malformed) — never fall back to a
    # client-supplied value; the peer is the only thing we actually know
    return peer or "?"


def _window_start():
    return db.utcnow().replace(tzinfo=None) - timedelta(seconds=settings.SETTINGS.fail_window_sec)


def is_locked(ip: str) -> bool:
    """True when this IP, or everyone, has exceeded the failed-attempt budget."""
    cfg = settings.SETTINGS
    since = _window_start()
    with db.get_session() as s:
        row = s.get(db.Lockdown, ip)
        if row and row.last_fail and row.last_fail >= since and (row.fail_count or 0) >= cfg.fail_limit_per_ip:
            return True
        total = 0
        for r in s.query(db.Lockdown).filter(db.Lockdown.last_fail >= since).all():
            total += r.fail_count or 0
        return total >= cfg.fail_limit_global


def record_fail(ip: str) -> int:
    """Count a failed attempt; returns attempts of this IP in the current window."""
    since = _window_start()
    now = db.utcnow().replace(tzinfo=None)
    with db.get_session() as s:
        row = s.get(db.Lockdown, ip)
        if not row:
            row = db.Lockdown(ip=ip, fail_count=0)
            s.add(row)
        if not row.last_fail or row.last_fail < since:
            row.fail_count = 0           # window expired — start over
        row.fail_count = (row.fail_count or 0) + 1
        row.last_fail = now
        if row.fail_count >= settings.SETTINGS.fail_limit_per_ip:
            row.locked_until = now + timedelta(seconds=settings.SETTINGS.fail_window_sec)
        s.commit()
        return row.fail_count


def clear_fails(ip: str) -> None:
    with db.get_session() as s:
        row = s.get(db.Lockdown, ip)
        if row:
            s.delete(row)
            s.commit()
