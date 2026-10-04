"""Token watch (0.26): notice when a service token stops behaving like itself.

A service token is a bearer credential: whoever holds it reads the folder. The access policies
(docs/ACCESS-POLICIES.md) say where and when it *may* be used; the watch says whether it is being
used *as usual*. It keeps a small profile per token — the networks it comes from (/24 for IPv4,
/48 for IPv6), the secrets it reads, its 10-minute rate — and raises an alert when a call does not
fit:

  new_network        a network never seen before, once the token has a history (learn_uses calls)
  parallel_networks  two different networks within parallel_sec — the token is in two places
  rate_spike         more calls in 10 minutes than rate_min and than rate_factor × its usual rate
  enumeration        enum_min secrets it never read before inside one 10-minute window
  canary             ANY use of a canary token — a token nobody should ever use

What happens is the token's `on_anomaly`: `alert` (audit + webhook + notifier, the call goes
through) or `freeze` (the same, and the token answers 403 until a manager unfreezes it). A canary
always freezes and answers the attacker with the generic 401, not with a hint. Repeats of the same
anomaly (token, kind, network) within an hour fold into one alert with a counter — a leaked token
hammering the API produces one line, not a thousand.

The watch is advisory: it never blocks a token by itself unless asked (`freeze`), it never
changes policies, and a manager can mark a network as trusted when a new office goes live.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone

import db
import settings as cfgmod

WINDOW = timedelta(minutes=10)
FOLD = timedelta(hours=1)
KINDS = ("new_network", "parallel_networks", "rate_spike", "enumeration", "canary")


def now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def network_of(ip: str) -> str:
    """/24 for IPv4, /48 for IPv6; anything that is not an address stays as is (tests, sockets)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "?"
    if a.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/48", strict=False))


def secret_from_path(path: str) -> str:
    """The secret a machine-API call is about, or '' for list/health calls."""
    for marker in ("/api/v1/m/secret/", "/data/"):
        if marker in path:
            rest = path.split(marker, 1)[1]
            return rest.split("?", 1)[0].strip("/")
    return ""


class Anomaly:
    __slots__ = ("kind", "detail", "action")

    def __init__(self, kind: str, detail: dict, action: str):
        self.kind, self.detail, self.action = kind, detail, action


def observe(session, token, ip: str, path: str) -> list[Anomaly]:
    """Update the token's profile with this call and return the anomalies it triggers. Runs inside
    the request's DB session; the caller decides how to react (sdk_api._validate_token)."""
    cfg = cfgmod.SETTINGS
    if not cfg.watch_enabled:
        return []
    now = now_naive()
    net = network_of(ip)
    secret = secret_from_path(path)
    prof = session.get(db.TokenProfile, token.id)
    if prof is None:
        prof = db.TokenProfile(token_id=token.id, uses=0, first_seen=now, networks="{}", secrets="{}", window_new_secrets="[]")
        session.add(prof)
    networks = json.loads(prof.networks or "{}")
    secrets = json.loads(prof.secrets or "{}")
    out: list[Anomaly] = []
    action = "freeze" if getattr(token, "on_anomaly", "alert") == "freeze" else "alert"

    if getattr(token, "canary", False):
        out.append(Anomaly("canary", {"ip": ip, "network": net, "path": path}, "freeze"))

    learned = (prof.uses or 0) >= cfg.watch_learn_uses
    # a network is "known" when it was seen during learning or a manager trusted it; a network that
    # appeared after learning stays "pending" (and keeps feeding its alert) until someone trusts it
    known = net in networks and not networks[net].get("pending")
    new_net = learned and not known
    if new_net:
        out.append(Anomaly("new_network", {"ip": ip, "network": net, "known_networks": sorted(n for n, e in networks.items() if not e.get("pending"))[:10],
                                           "uses": prof.uses}, action))
    # two KNOWN networks within the window = the token is in two places (a pending network is already
    # covered by its new_network alert, so it is not counted here)
    last_known = prof.last_network in networks and not networks[prof.last_network].get("pending")
    if learned and not new_net and last_known and prof.last_network != net and prof.last_seen \
            and (now - prof.last_seen).total_seconds() <= cfg.watch_parallel_sec:
        out.append(Anomaly("parallel_networks", {"ip": ip, "network": net, "other_network": prof.last_network, "other_ip": prof.last_ip,
                                                 "seconds_apart": int((now - prof.last_seen).total_seconds())}, action))

    # 10-minute window: rate and enumeration
    if not prof.window_start or now - prof.window_start > WINDOW:
        prof.window_start, prof.window_count, prof.window_new_secrets = now, 0, "[]"
    prof.window_count = (prof.window_count or 0) + 1
    new_in_window = json.loads(prof.window_new_secrets or "[]")
    if secret and secret not in secrets and secret not in new_in_window:
        new_in_window.append(secret)
        prof.window_new_secrets = json.dumps(new_in_window)
    if learned:
        lifetime_min = max(1.0, (now - (prof.first_seen or now)).total_seconds() / 60.0)
        usual_per_window = (prof.uses or 0) / lifetime_min * 10.0
        if prof.window_count >= cfg.watch_rate_min and prof.window_count >= cfg.watch_rate_factor * max(usual_per_window, 1.0):
            out.append(Anomaly("rate_spike", {"ip": ip, "network": net, "calls_10min": prof.window_count, "usual_10min": round(usual_per_window, 1)}, action))
        if len(new_in_window) >= cfg.watch_enum_min:
            out.append(Anomaly("enumeration", {"ip": ip, "network": net, "new_secrets_10min": len(new_in_window), "sample": new_in_window[:8]}, action))

    # record the call
    entry = networks.setdefault(net, {"n": 0, "first": now.isoformat(timespec="seconds"), "trusted": False, "pending": learned})
    entry["n"] = entry.get("n", 0) + 1
    entry["last"] = now.isoformat(timespec="seconds")
    if secret:
        secrets[secret] = secrets.get(secret, 0) + 1
    prof.networks = json.dumps(networks)
    prof.secrets = json.dumps(secrets)
    prof.uses = (prof.uses or 0) + 1
    prof.last_seen, prof.last_ip, prof.last_network = now, ip[:64], net[:64]
    return out


def record(session, token, anomaly: Anomaly, ip: str) -> tuple[db.TokenAlert, bool]:
    """Store the anomaly as an alert, folding repeats (same token, kind, network within an hour).
    Returns (alert, is_new)."""
    now = now_naive()
    net = anomaly.detail.get("network", "")
    q = session.query(db.TokenAlert).filter(db.TokenAlert.token_id == token.id, db.TokenAlert.kind == anomaly.kind,
                                            db.TokenAlert.acknowledged == False, db.TokenAlert.last_at >= now - FOLD)   # noqa: E712
    if anomaly.kind != "parallel_networks":          # a pair of networks is one incident whichever side calls next
        q = q.filter(db.TokenAlert.network == net)
    row = q.first()
    if row:
        row.count = (row.count or 1) + 1
        row.last_at = now
        row.detail = json.dumps(anomaly.detail, ensure_ascii=False)
        return row, False
    row = db.TokenAlert(token_id=token.id, kind=anomaly.kind, detail=json.dumps(anomaly.detail, ensure_ascii=False), ip=ip[:64],
                        network=net[:64], created_at=now, last_at=now, count=1, action=anomaly.action)
    session.add(row)
    session.flush()
    return row, True


def trust_network(session, token_id: int, network: str) -> bool:
    prof = session.get(db.TokenProfile, token_id)
    if prof is None:
        prof = db.TokenProfile(token_id=token_id, uses=0, first_seen=now_naive(), networks="{}", secrets="{}", window_new_secrets="[]")
        session.add(prof)
    networks = json.loads(prof.networks or "{}")
    net = normalize_network(network)
    if not net:
        return False
    e = networks.setdefault(net, {"n": 0, "first": now_naive().isoformat(timespec="seconds")})
    e["trusted"] = True
    e.pop("pending", None)
    prof.networks = json.dumps(networks)
    return True


def normalize_network(value: str) -> str:
    """'203.0.113.7' → '203.0.113.0/24'; '203.0.113.0/24' stays; garbage → ''."""
    value = (value or "").strip()
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return network_of(value) if ipaddress.ip_address(value) else ""
    except ValueError:
        return ""


def alert_to_dict(a: db.TokenAlert, token=None, folder_name: str = "") -> dict:
    return {"id": a.id, "token_id": a.token_id, "token_name": token.name if token else "", "folder_id": token.folder_id if token else None,
            "folder_name": folder_name, "kind": a.kind, "detail": json.loads(a.detail or "{}"), "ip": a.ip, "network": a.network,
            "created_at": a.created_at.isoformat() if a.created_at else "", "last_at": a.last_at.isoformat() if a.last_at else "",
            "count": a.count or 1, "action": a.action, "acknowledged": bool(a.acknowledged),
            "token_frozen": bool(getattr(token, "frozen", False)) if token else None, "token_canary": bool(getattr(token, "canary", False)) if token else None}


def profile_to_dict(p: db.TokenProfile | None) -> dict:
    if p is None:
        return {"uses": 0, "networks": {}, "secrets": {}, "first_seen": None, "last_seen": None}
    return {"uses": p.uses or 0, "networks": json.loads(p.networks or "{}"), "secrets": json.loads(p.secrets or "{}"),
            "first_seen": p.first_seen.isoformat() if p.first_seen else None, "last_seen": p.last_seen.isoformat() if p.last_seen else None,
            "last_ip": p.last_ip or "", "window_calls": p.window_count or 0}


def human(kind: str, detail: dict, token_name: str) -> str:
    """One line for the notifier / webhook text."""
    if kind == "canary":
        return f"CANARY token '{token_name}' was used from {detail.get('ip')} — someone has a token nobody should have; it is frozen"
    if kind == "new_network":
        return f"token '{token_name}' used from a new network {detail.get('network')} (ip {detail.get('ip')}); known: {', '.join(detail.get('known_networks') or []) or '—'}"
    if kind == "parallel_networks":
        return f"token '{token_name}' used from two networks within {detail.get('seconds_apart')} s: {detail.get('other_network')} and {detail.get('network')}"
    if kind == "rate_spike":
        return f"token '{token_name}': {detail.get('calls_10min')} calls in 10 min (usual ≈ {detail.get('usual_10min')})"
    if kind == "enumeration":
        return f"token '{token_name}' read {detail.get('new_secrets_10min')} secrets it never read before within 10 min"
    return f"token '{token_name}': {kind}"
