"""Updates (0.38): what is installed, what the release channel offers, and the jobs the update agent carries out.

Trust model. The vault only *records* the owner's request "update to X". The agent (agent/updater.py) pulls the
request and checks it on its own before touching anything: X must be a published, non-prerelease release in the
channel the agent reads itself, newer than what runs, and every image must carry the release workflow's Sigstore
signature. A compromised vault process can therefore at most ask for an authentic newer release — it cannot make the
agent (which holds the Docker socket) run an arbitrary image.

Release notes: versions up to the installed one come from release_notes.json (generated from CHANGELOG.md, shipped
in the image, works without network); newer ones from the channel (the GitHub Release body = the CHANGELOG section)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import changelog
import db
import netutil
import settings as cfgmod

CHECK_EVERY = timedelta(hours=6)          # a page view refreshes the channel when the last look is older
AGENT_ONLINE = timedelta(seconds=90)      # the agent polls every 15 s; three missed polls = not connected
MAX_CHANNEL_BYTES = 2 * 1024 * 1024
MAX_NOTES = 60_000
MAX_LOG = 64_000
ACTIVE = ("requested", "running")


class UpdateError(Exception):
    def __init__(self, msg: str, status: int = 422):
        super().__init__(msg)
        self.status = status


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── versions and notes ──────────────────────────────────────────────────────
def installed() -> str:
    import main
    return main.VERSION


def newer(a: str, b: str) -> bool:
    """a > b (both X.Y.Z); unparsable → False."""
    pa, pb = changelog.parse_version(a), changelog.parse_version(b)
    return bool(pa and pb and pa > pb)


def bundled_notes() -> list[dict]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release_notes.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


# ── the channel ─────────────────────────────────────────────────────────────
def channel_allowed(url: str) -> bool:
    """Same rules as every outbound call of 0.37: https to a globally routable address; http and private networks
    only with VAULT_WEBHOOK_ALLOW_PRIVATE=1 (a mirror inside the company) or in dev."""
    st = cfgmod.SETTINGS
    u = urllib.parse.urlparse(url or "")
    if u.scheme == "https":
        pass
    elif u.scheme == "http" and (st.webhook_allow_private or st.dev):
        pass
    else:
        return False
    return bool(u.hostname) and (st.webhook_allow_private or netutil.address_is_public(u.hostname))


def parse_channel(raw: bytes) -> list[dict]:
    """GitHub Releases API JSON (or a mirror serving the same shape) → [{version, date, notes, url}], newest first.
    Drafts, pre-releases and tags that are not X.Y.Z are skipped."""
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, list):
        raise UpdateError("the channel did not answer with a list of releases")
    out = []
    for r in data:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        tag = str(r.get("tag_name") or "")
        if not changelog.parse_version(tag):
            continue
        out.append({"version": tag.lstrip("v"), "date": str(r.get("published_at") or "")[:10],
                    "notes": str(r.get("body") or "")[:MAX_NOTES], "url": str(r.get("html_url") or "")[:512]})
    out.sort(key=lambda x: changelog.parse_version(x["version"]), reverse=True)
    return out


def fetch_channel(url: str) -> list[dict]:
    if not channel_allowed(url):
        raise UpdateError("the update channel must be https:// to a public address (VAULT_UPDATE_CHANNEL)")
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": f"aps-vault/{installed()}"})
    try:
        with netutil.urlopen_noredirect(req, timeout=10) as r:
            raw = r.read(MAX_CHANNEL_BYTES + 1)
    except Exception as e:                           # network, TLS, HTTP status, a refused redirect
        raise UpdateError(f"the update channel did not answer: {str(e)[:200]}")
    if len(raw) > MAX_CHANNEL_BYTES:
        raise UpdateError("the update channel answer is too large")
    try:
        return parse_channel(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise UpdateError(f"the update channel answer is not release JSON: {str(e)[:120]}")


def check(force: bool = False) -> dict:
    """Refresh the cached channel when forced or stale. Errors are kept (shown on the page), never raised."""
    url = cfgmod.SETTINGS.update_channel
    with db.get_session() as s:
        row = s.get(db.UpdateState, 1)
        if row is None:
            row = db.UpdateState(id=1, releases="[]", error="")
            s.add(row)
            s.commit()
        stale = row.checked_at is None or now() - row.checked_at > CHECK_EVERY
        if url and (force or stale):
            try:
                rel = fetch_channel(url)
                row.releases, row.error = json.dumps(rel, ensure_ascii=False), ""
            except UpdateError as e:
                row.error = str(e)[:500]
            row.checked_at = now()
            s.commit()
        return {"checked_at": row.checked_at, "releases": json.loads(row.releases or "[]"), "error": row.error or ""}


# ── agent authentication ────────────────────────────────────────────────────
def agent_token_ok(presented: str) -> bool:
    expected = cfgmod.SETTINGS.update_agent_token
    if not expected or not presented:
        return False
    return hmac.compare_digest(hashlib.sha256(presented.encode()).digest(), hashlib.sha256(expected.encode()).digest())


def agent_seen(agent_id: str, mode: str, agent_version: str, current: str, verify: str, host: str) -> None:
    with db.get_session() as s:
        a = s.get(db.UpdateAgent, agent_id) or db.UpdateAgent(agent_id=agent_id)
        a.last_seen, a.mode, a.agent_version, a.current_version, a.verify, a.host = now(), mode[:16], agent_version[:32], current[:32], verify[:16], host[:128]
        s.merge(a)
        s.commit()


def online_agent() -> dict | None:
    with db.get_session() as s:
        a = s.query(db.UpdateAgent).order_by(db.UpdateAgent.last_seen.desc()).first()
        if not a:
            return None
        return {"agent_id": a.agent_id, "last_seen": a.last_seen.isoformat() + "Z" if a.last_seen else None,
                "connected": bool(a.last_seen and now() - a.last_seen < AGENT_ONLINE), "mode": a.mode,
                "agent_version": a.agent_version, "current_version": a.current_version, "verify": a.verify, "host": a.host}


# ── jobs ────────────────────────────────────────────────────────────────────
def job_dict(j) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None
    return {"id": j.id, "target_version": j.target_version, "from_version": j.from_version, "state": j.state, "step": j.step,
            "requested_by": j.requested_by, "requested_at": iso(j.requested_at), "picked_at": iso(j.picked_at),
            "finished_at": iso(j.finished_at), "agent_id": j.agent_id, "log": j.log or ""}


def last_job() -> dict | None:
    with db.get_session() as s:
        j = s.query(db.UpdateJob).order_by(db.UpdateJob.id.desc()).first()
        return job_dict(j) if j else None


def request(version: str, actor: str) -> dict:
    """Create the job after the vault's own checks (the agent repeats them independently)."""
    version = (version or "").strip().lstrip("v")
    if not changelog.parse_version(version):
        raise UpdateError("version must look like X.Y.Z")
    cur = installed()
    if not newer(version, cur):
        raise UpdateError(f"{version} is not newer than the installed {cur} — downgrades are not done by the agent")
    st = check(force=False)
    if version not in {r["version"] for r in st["releases"]}:
        st = check(force=True)                              # a release published minutes ago
        if version not in {r["version"] for r in st["releases"]}:
            raise UpdateError(f"{version} is not a published release in the update channel")
    ag = online_agent()
    if not ag or not ag["connected"]:
        raise UpdateError("no update agent is connected — see Settings → Updates for how to run it", 409)
    with db.get_session() as s:
        if s.query(db.UpdateJob).filter(db.UpdateJob.state.in_(ACTIVE)).first():
            raise UpdateError("an update is already in progress", 409)
        j = db.UpdateJob(target_version=version, from_version=cur, state="requested", requested_by=actor, log="")
        s.add(j)
        s.commit()
        s.refresh(j)
        return job_dict(j)


def cancel(job_id: int) -> dict:
    with db.get_session() as s:
        n = s.query(db.UpdateJob).filter_by(id=job_id, state="requested").update(
            {"state": "cancelled", "finished_at": now(), "step": "cancelled by the owner"}, synchronize_session=False)
        s.commit()
        if not n:
            raise UpdateError("only a job the agent has not picked up yet can be cancelled", 409)
        s.expire_all()                                   # the bulk UPDATE bypassed the identity map
        return job_dict(s.get(db.UpdateJob, job_id))


def pick(agent_id: str) -> dict | None:
    """Hand the oldest requested job to this agent — exactly once, even with several agents or replicas."""
    with db.get_session() as s:
        j = s.query(db.UpdateJob).filter_by(state="requested").order_by(db.UpdateJob.id).first()
        if not j:
            return None
        n = s.query(db.UpdateJob).filter_by(id=j.id, state="requested").update(
            {"state": "running", "picked_at": now(), "agent_id": agent_id, "step": "picked up by the agent"}, synchronize_session=False)
        s.commit()
        s.expire_all()                                   # the bulk UPDATE bypassed the identity map: re-read the row
        return job_dict(s.get(db.UpdateJob, j.id)) if n else None


def report(job_id: int, agent_id: str, state: str, step: str, log: str) -> dict:
    if state not in ("running", "done", "failed"):
        raise UpdateError("state must be running, done or failed")
    with db.get_session() as s:
        j = s.get(db.UpdateJob, job_id)
        if not j or j.agent_id != agent_id or j.state != "running":
            raise UpdateError("no running job with this id for this agent")
        j.step = (step or "")[:64]
        if log:
            j.log = ((j.log or "") + log.rstrip() + "\n")[-MAX_LOG:]
        j.state = state
        if state in ("done", "failed"):
            j.finished_at = now()
        s.commit()
        return job_dict(j)


# ── the page ────────────────────────────────────────────────────────────────
def status() -> dict:
    cur = installed()
    url = cfgmod.SETTINGS.update_channel
    ch = check(force=False) if url else {"checked_at": None, "releases": [], "error": ""}
    by_version: dict[str, dict] = {}
    for r in bundled_notes():                       # what this build knows about itself and its past
        by_version[r["version"]] = {"version": r["version"], "date": r.get("date", ""), "notes": r.get("notes", ""), "url": ""}
    for r in ch["releases"]:                        # newer releases (and links for the published ones)
        e = by_version.get(r["version"])
        if e is None or (newer(r["version"], cur) and r["notes"]):
            by_version[r["version"]] = dict(r)
        else:
            e["url"] = e.get("url") or r["url"]
    history = sorted(by_version.values(), key=lambda x: changelog.parse_version(x["version"]) or (0, 0, 0), reverse=True)
    for h in history:
        h["state"] = "installed" if h["version"] == cur else ("newer" if newer(h["version"], cur) else "older")
    available = [h for h in history if h["state"] == "newer"]
    host = urllib.parse.urlparse(url).hostname if url else ""
    return {
        "installed": cur,
        "latest": available[0]["version"] if available else cur,
        "available": [h["version"] for h in available],
        "channel": {"enabled": bool(url), "host": host or "", "checked_at": ch["checked_at"].isoformat() + "Z" if ch["checked_at"] else None,
                    "error": ch["error"]},
        "agent": {"configured": bool(cfgmod.SETTINGS.update_agent_token), **(online_agent() or {"connected": False})},
        "job": last_job(),
        "history": history,
    }
