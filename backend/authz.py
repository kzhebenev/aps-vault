"""Who may do what: the unlocked-session dependency, roles of named users per folder, the owner-only checks,
attempt limits, TOTP replay protection. Every permission check of the human API lives here.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import hmac
import time

from fastapi import (Cookie, Header, HTTPException, Request)
import pyotp

import db
import netutil
import policy
import sessions
from state import Identity, current_identity, set_current_identity
import users as _users

from app_core import SESSION_COOKIE, _client_ip, _ui_policy_check, audit  # noqa: F401

async def require_unlocked(
    request: Request,
    vault_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> str:
    """Resolve the session row (shared by all replicas) and make its master key available to
    the request via `current_master_key()`. Async on purpose: the contextvar must be set in
    the request's own context, not in a worker thread."""
    sid = vault_session
    if not sid and authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            sid = parts[1]
    found = sessions.resolve(sid) if sid else None
    if not found:
        set_current_identity(None)
        raise HTTPException(401, "vault is locked or the session is invalid — unlock first")
    row, key = found
    if getattr(row, "user_id", None):
        # 0.20: a named user — the session carries their private key, not the master key
        with db.get_session() as s:
            u = s.get(db.User, row.user_id)
            if not u or not u.is_active:
                sessions.revoke(sid)
                set_current_identity(None)
                raise HTTPException(401, "user is deactivated — session closed")
            ident = Identity("user", key, user_id=u.id, email=u.email, name=u.name or "")
        set_current_identity(ident)
        if not _user_may(request.method, request.url.path):
            raise HTTPException(403, "this action belongs to the vault owner (master password)")
    elif getattr(row, "agent_key_id", None):
        # 0.41.8: a session opened by an agent key — the owner's key, but only what _AGENT_PATHS allows, and only
        # while the key itself is alive and the caller is where the key may be used from (checked on every request)
        with db.get_session() as s:
            ak = s.get(db.AgentKey, row.agent_key_id)
            dead = (not ak or ak.revoked or (ak.expires_at and ak.expires_at.replace(tzinfo=None) < db.utcnow().replace(tzinfo=None)))
            if dead:
                sessions.revoke(sid)
                set_current_identity(None)
                raise HTTPException(401, "the agent key of this session is revoked or expired — session closed")
            name, cidrs = ak.name, ak.allowed_cidrs or ""
        if cidrs and policy.check(cidrs, "", _client_ip(request)):
            set_current_identity(None)
            raise HTTPException(403, "this agent key may not be used from this address")
        set_current_identity(Identity("owner", key, name=name, agent=name))
        request.state.master_key = key
        if not _agent_may(request.method, request.url.path):
            raise HTTPException(403, "an agent key may not do this — it belongs to the vault owner (master password)")
    else:
        set_current_identity(Identity("owner", key))
        request.state.master_key = key
    request.state.session_row = row
    _ui_policy_check(request)
    return sid


# What a named user may call at all; the role on the folder is checked inside the endpoint.
# Everything else — users, folders, settings, cells, webhooks, export/import, audit — is the owner's.
_USER_PATHS = (
    ("GET", "/api/folders"), ("GET", "/api/secrets"), ("POST", "/api/secrets"), ("GET", "/api/secrets/"), ("PATCH", "/api/secrets/"),
    ("DELETE", "/api/secrets/"), ("POST", "/api/secrets/"), ("GET", "/api/tokens"), ("POST", "/api/tokens"), ("DELETE", "/api/tokens/"),
    ("POST", "/api/share"), ("POST", "/api/share/note"), ("GET", "/api/shares"), ("DELETE", "/api/shares/"),
    ("GET", "/api/approvals/"), ("GET", "/api/me"), ("POST", "/api/me/password"), ("POST", "/api/auth/lock"), ("GET", "/api/tools/hibp/"),
    ("GET", "/api/enrollments"), ("POST", "/api/enrollments"), ("DELETE", "/api/enrollments/"),
    ("GET", "/api/auth/webauthn/credentials"), ("DELETE", "/api/auth/webauthn/credentials/"), ("POST", "/api/auth/webauthn/register/options"),
    ("POST", "/api/auth/webauthn/register/finish"), ("POST", "/api/auth/webauthn/second-factor"),
    ("PUT", "/api/secrets/"), ("GET", "/api/rotations"), ("GET", "/api/rotations/status"),     # 0.24: rotation (role checked inside)
    ("GET", "/api/tokens/"), ("POST", "/api/tokens/"), ("PATCH", "/api/tokens/"),              # 0.26: token watch (manager of the folder)
    ("GET", "/api/users"), ("PUT", "/api/users/"), ("DELETE", "/api/users/"),                  # 0.30: managers grant on their folders (checked inside)
    ("GET", "/api/me/totp"), ("POST", "/api/me/totp/"),                                         # 0.30: TOTP for users
)


# 0.41.8: what a session opened by an agent key may call. Allow-list, default deny: the work an AI session or an
# automation does on the owner's behalf — folders, secrets, service tokens, users and their grants, enrolment codes,
# the audit log. Never: the master password and recovery, 2FA/WebAuthn/SSO/HSM/KMS cells, backups and their key,
# webhooks, export/import, approvals settings, updates, folder-key rotation, and the agent keys themselves (an agent
# cannot mint another agent). Roles inside the endpoints see the owner.
_AGENT_PATHS = (
    ("GET", "/api/folders"), ("POST", "/api/folders"), ("DELETE", "/api/folders/"),
    ("GET", "/api/secrets"), ("POST", "/api/secrets"), ("GET", "/api/secrets/"), ("PATCH", "/api/secrets/"),
    ("DELETE", "/api/secrets/"), ("POST", "/api/secrets/"), ("PUT", "/api/secrets/"),
    ("GET", "/api/tokens"), ("POST", "/api/tokens"), ("GET", "/api/tokens/"), ("POST", "/api/tokens/"),
    ("PATCH", "/api/tokens/"), ("DELETE", "/api/tokens/"),
    ("GET", "/api/users"), ("POST", "/api/users"), ("POST", "/api/users/"), ("PUT", "/api/users/"), ("DELETE", "/api/users/"),
    ("GET", "/api/enrollments"), ("POST", "/api/enrollments"), ("DELETE", "/api/enrollments/"),
    ("GET", "/api/audit"), ("GET", "/api/stats"), ("GET", "/api/rotations"), ("GET", "/api/rotations/status"),
    ("GET", "/api/me"), ("POST", "/api/auth/lock"),
)


def _agent_may(method: str, path: str) -> bool:
    for m, p in _AGENT_PATHS:
        if m == method and (path == p or (p.endswith("/") and path.startswith(p))):
            return True
    return False


def _human_owner_only() -> None:
    """0.41.8: the owner in person (master password, a cell, SSO) — an agent key acting as the owner is refused."""
    ident = current_identity()
    if ident.kind != "owner" or ident.agent:
        raise HTTPException(403, "this action belongs to the vault owner in person, not to an agent key")


def _user_may(method: str, path: str) -> bool:
    for m, p in _USER_PATHS:
        if m == method and (path == p or (p.endswith("/") and path.startswith(p))):
            return True
    return False


def _require_role(folder_id: int, need: str) -> None:
    """Owner: always. User: a grant on the folder with at least `need` (reader < writer < manager)."""
    ident = current_identity()
    if ident.kind == "owner":
        return
    role = _users.grants_of(ident.user_id).get(folder_id)
    if not _users.role_at_least(role, need):
        raise HTTPException(403, f"your role on this folder does not allow this ({need} needed)" if role else "no access to this folder")


def _visible_folder_ids() -> set[int] | None:
    """None for the owner (everything); the granted folders for a user."""
    ident = current_identity()
    if ident.kind == "owner":
        return None
    return set(_users.grants_of(ident.user_id))


def _guard_attempts(request: Request) -> None:
    """0.37: every check of a secret (password, TOTP, recovery code) — also inside a session — goes through the
    same lockout as the sign-in; a stolen session must not be a free oracle for the password or the 6 digits."""
    if netutil.is_locked(_client_ip(request)):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")


def _attempt_failed(request: Request, action: str) -> int:
    ip = _client_ip(request)
    n = netutil.record_fail(ip)
    audit(action, ip=ip, meta={"attempts": n})
    return n


def _owner_only_if_flagged(s, folder_id: int) -> None:
    """0.37: a service token / enrolment code reads every value of its folder, 'machines only' and 'requires approval'
    included. For a folder holding such secrets only the owner hands that out — a manager used to issue a token to
    themselves and read what the flags keep away from people."""
    ident = current_identity()
    if ident.kind == "owner" and not ident.agent:       # 0.41.9: the owner in person — an agent key is held like a manager
        return
    flagged = s.query(db.Secret).filter(db.Secret.folder_id == folder_id,
                                         (db.Secret.machine_only == True) | (db.Secret.require_approval == True)).count()  # noqa: E712
    if flagged:
        raise HTTPException(403, "this folder holds 'machines only' / 'requires approval' secrets — only the owner issues machine access to it")


def _wipe_spent_keys(s) -> None:
    """0.37: share links and enrolment codes carry the folder key (encrypted under the link / code). Once a link or
    code is revoked, spent or expired, that copy is erased — a later database dump plus an old chat message must not
    give the whole folder."""
    now = db.utcnow().replace(tzinfo=None)
    for model in (db.ShareLink, db.Enrollment):
        q = s.query(model).filter(model.folder_key_enc != b"").filter(
            (model.revoked == True) | (model.used_count >= model.max_uses) | (model.expires_at < now))  # noqa: E712
        for row in q.all():
            row.folder_key_enc = b""; row.folder_key_nonce = b""
    q = s.query(db.NoteShare).filter(db.NoteShare.payload_enc != b"").filter(
        (db.NoteShare.revoked == True) | (db.NoteShare.used_count >= db.NoteShare.max_uses) | (db.NoteShare.expires_at < now))  # noqa: E712
    for row in q.all():
        row.payload_enc = b""; row.payload_nonce = b""
    s.commit()


def _totp_accept(subject: str, secret: str, code: str) -> bool:
    """0.37: TOTP with ±1 step and NO replay — the accepted step is stored per subject and a code for that step or
    an earlier one is refused (an intercepted code was reusable for ~90 s)."""
    code = (code or "").strip()
    if not secret or not code.isdigit():
        return False
    t = pyotp.TOTP(secret)
    now = int(time.time()) // t.interval
    for step in (now - 1, now, now + 1):
        if hmac.compare_digest(t.generate_otp(step), code):
            with db.get_session() as s:
                row = s.get(db.TotpStep, subject)
                if row and (row.last_step or 0) >= step:
                    return False
                if not row:
                    row = db.TotpStep(subject=subject, last_step=step); s.add(row)
                else:
                    row.last_step = step
                s.commit()
            return True
    return False


def _owner_only() -> None:
    if current_identity().kind != "owner":
        raise HTTPException(403, "this action belongs to the vault owner (master password)")
