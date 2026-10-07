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


_HOST_CACHE: dict[str, tuple[float, frozenset]] = {}
HOST_TTL, HOST_RETRY = 60.0, 10.0


def _resolve(host: str) -> frozenset:
    """Addresses of a trusted proxy given by name, cached for a minute (a container gets a new IP when it is
    recreated). A failed lookup keeps the last good answer; a name that never resolved trusts nobody (fail closed)
    and is retried after 10 s — the proxy container may simply not be up yet."""
    import socket
    import time
    now = time.monotonic()
    hit = _HOST_CACHE.get(host)
    if hit and hit[0] > now:
        return hit[1]
    try:
        addrs = frozenset(ipaddress.ip_address(ai[4][0].split("%")[0]) for ai in socket.getaddrinfo(host, None))
        _HOST_CACHE[host] = (now + HOST_TTL, addrs)
        return addrs
    except (OSError, ValueError):
        old = hit[1] if hit else frozenset()
        _HOST_CACHE[host] = (now + HOST_RETRY, old)
        return old


def _trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in settings.SETTINGS.trusted_proxies):
        return True
    return any(addr in _resolve(h) for h in settings.SETTINGS.trusted_proxy_hosts)


def from_trusted_proxy(request: Request) -> bool:
    """True when the TCP peer is one of our proxies — the only case in which forwarded headers
    (client IP, client-certificate fingerprint) mean anything."""
    return _trusted(request.client.host if request.client else "")


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
    """True when this IP exceeded its budget, or when everyone together exceeded the global budget AND this IP
    has failed at least once in the window. 0.37: the global limit used to lock out every address, the owner's
    included — 50 junk requests from anywhere were a denial of service. Under a global flood each address now gets
    one try per window; an address with no failures (the owner at their desk) is not blocked by others."""
    cfg = settings.SETTINGS
    since = _window_start()
    with db.get_session() as s:
        row = s.get(db.Lockdown, ip)
        mine = (row.fail_count or 0) if row and row.last_fail and row.last_fail >= since else 0
        if mine >= cfg.fail_limit_per_ip:
            return True
        if mine == 0:
            return False
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


# ─── outbound HTTP without redirects (0.37) ───────────────────────────────────
class _NoRedirect(__import__("urllib.request").request.HTTPRedirectHandler):
    """Every outbound call of the vault (webhooks, rotation receivers, import sources, approval notifications) checks
    the target address first. A redirect would take the request — and its Authorization / X-Vault-Token / signature
    headers — to an address nobody checked (169.254.169.254, an internal service). Redirects are refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl[:120]} refused (outbound calls do not follow redirects)", headers, fp)


def urlopen_noredirect(req, timeout: float):
    import urllib.request
    return urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout)


def address_is_public(host: str) -> bool:
    """True when every address the name resolves to is globally routable (not private, loopback, link-local,
    carrier-grade NAT 100.64/10, reserved, multicast; IPv4-mapped IPv6 unwrapped)."""
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            return False
    return bool(infos)
