"""PAM-style access policy: where a caller may come from and when.

Two inputs, both optional (empty = unrestricted):
  * `cidrs` — "10.0.0.0/8 203.0.113.7" (space or comma separated; a bare address is /32)
  * `hours` — one or more windows separated by ";", each "<days> <HH:MM>-<HH:MM>" where days is
    a range or list of Mon,Tue,…,Sun ("Mon-Fri", "Sat,Sun", or omitted = every day) and the
    window may wrap midnight ("22:00-06:00"). Evaluated in `settings.timezone`.

Service tokens store their own policy; the human UI uses the global one from the
environment. Denials are audited as `*:policy_denied` so a SIEM sees a token being used from
the wrong place at the wrong time — which is exactly the signal a stolen token produces.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from zoneinfo import ZoneInfo

import settings

_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_WINDOW = re.compile(r"^(?:(?P<days>[A-Za-z,\-]+)\s+)?(?P<h1>\d{1,2}):(?P<m1>\d{2})-(?P<h2>\d{1,2}):(?P<m2>\d{2})$")


def parse_cidrs(spec: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for tok in re.split(r"[\s,]+", spec or ""):
        if not tok:
            continue
        out.append(ipaddress.ip_network(tok, strict=False))   # ValueError for garbage → caller returns 422
    return out


def _parse_days(spec: str | None) -> set[int]:
    if not spec:
        return set(range(7))
    days: set[int] = set()
    for part in spec.lower().split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ia, ib = _DAYS.index(a[:3]), _DAYS.index(b[:3])
            rng = range(ia, ib + 1) if ia <= ib else list(range(ia, 7)) + list(range(0, ib + 1))
            days.update(rng)
        elif part:
            days.add(_DAYS.index(part[:3]))
    return days


def parse_hours(spec: str) -> list[tuple[set[int], int, int]]:
    """→ [(weekdays, start_minute, end_minute)]; end < start means the window wraps midnight."""
    out = []
    for win in (spec or "").split(";"):
        win = win.strip()
        if not win:
            continue
        m = _WINDOW.match(win)
        if not m:
            raise ValueError(f"bad time window: {win!r} (expected e.g. 'Mon-Fri 08:00-20:00')")
        h1, m1, h2, m2 = (int(m.group(k)) for k in ("h1", "m1", "h2", "m2"))
        if not (0 <= h1 <= 24 and 0 <= h2 <= 24 and m1 < 60 and m2 < 60):
            raise ValueError(f"bad time window: {win!r}")
        out.append((_parse_days(m.group("days")), h1 * 60 + m1, h2 * 60 + m2))
    return out


def validate(cidrs: str, hours: str) -> None:
    """Raise ValueError with a readable message if either spec is malformed."""
    parse_cidrs(cidrs)
    parse_hours(hours)


def ip_allowed(cidrs: str, ip: str) -> bool:
    nets = parse_cidrs(cidrs)
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False       # unknown/unparseable source is not "anywhere"
    return any(addr in n for n in nets)


def time_allowed(hours: str, now: datetime | None = None) -> bool:
    windows = parse_hours(hours)
    if not windows:
        return True
    tz = ZoneInfo(settings.SETTINGS.timezone)
    now = (now or datetime.now(tz)).astimezone(tz)
    minute, wd = now.hour * 60 + now.minute, now.weekday()
    for days, start, end in windows:
        if start <= end:
            if wd in days and start <= minute < end:
                return True
        else:  # wraps midnight: evening part belongs to `days`, morning part to the next day
            if (wd in days and minute >= start) or (((wd - 1) % 7) in days and minute < end):
                return True
    return False


def check(cidrs: str, hours: str, ip: str, now: datetime | None = None) -> str | None:
    """None when allowed, else a short reason."""
    if not ip_allowed(cidrs, ip):
        return f"source {ip} not in allowed networks"
    if not time_allowed(hours, now):
        return "outside allowed hours"
    return None


# ── mTLS binding (0.11) ─────────────────────────────────────────────────────
import re as _re
_FP = _re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def normalize_fingerprint(raw: str) -> str:
    """'AB:CD:…' / 'abcd…' / 'sha256/…' → lowercase hex (40 = SHA-1, 64 = SHA-256); '' when it is not one."""
    v = (raw or "").strip().lower()
    v = v.split("/", 1)[1] if v.startswith(("sha1/", "sha256/")) else v
    v = v.replace(":", "").replace(" ", "")
    return v if _FP.match(v) else ""


def parse_fingerprints(spec: str) -> list[str]:
    out = []
    for tok in (spec or "").replace(",", " ").split():
        fp = normalize_fingerprint(tok)
        if not fp:
            raise ValueError(f"not a certificate fingerprint (40 or 64 hex chars): {tok}")
        out.append(fp)
    return out


def cert_allowed(spec: str, presented: str | None) -> bool:
    """True when the token has no binding, or the proxy-verified certificate's fingerprint is
    one of the bound ones. A bound token with no certificate presented is refused."""
    bound = parse_fingerprints(spec) if spec else []
    if not bound:
        return True
    fp = normalize_fingerprint(presented or "")
    return bool(fp) and fp in bound
