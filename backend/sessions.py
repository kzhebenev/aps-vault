"""UI sessions shared by every replica (v0.6).

Before 0.6 the master key lived in the process (`STATE.master_key`) and sessions in a dict, so a
second replica behind the load balancer knew nothing about an unlock done on the first one.
Now a session row carries the master key wrapped under a key that is derived from the cookie
value itself (HKDF-SHA256) and never stored: whichever replica receives the cookie can unwrap
the key for the duration of the request; the database alone holds ciphertext and a hash of the
cookie. Logging out deletes the row, recovery deletes all rows — on every node at once.

Only the sha256 of the cookie value is stored, so a database read does not yield usable cookies.
"""
from __future__ import annotations

import secrets as pysecrets
from datetime import timedelta


import crypto
import db

SESSION_TTL_SEC = 8 * 3600
_WRAP_INFO = b"aps-vault/ui-session/master-key-wrap/v1"


def _sid_hash(sid: str) -> str:
    import suite
    return suite.hexdigest(sid.encode("utf-8"))


def _wrap_key(sid: str) -> bytes:
    import suite
    return suite.kdf(sid.encode("utf-8"), _WRAP_INFO)


def _now():
    return db.utcnow().replace(tzinfo=None)


def issue(master_key: bytes, csrf: str, *, oidc_user: str = "", ip: str = "",
          ttl: int = SESSION_TTL_SEC, user_id: int | None = None) -> str:
    """Create a session; returns the cookie value (shown to the client, never stored). For a
    named user (0.20) `master_key` is that user's private key and `user_id` is set."""
    sid = pysecrets.token_urlsafe(32)
    enc, nonce = crypto.encrypt(_wrap_key(sid), master_key)
    with db.get_session() as s:
        s.add(db.UiSession(sid_hash=_sid_hash(sid), master_key_enc=enc, master_key_nonce=nonce,
                           csrf=csrf, oidc_user=oidc_user or "", ip=ip[:64], user_id=user_id,
                           expires_at=_now() + timedelta(seconds=ttl)))
        s.commit()
    return sid


def resolve(sid: str) -> tuple[db.UiSession, bytes] | None:
    """(row, master_key) for a live session; None when unknown, expired or tampered with.
    Expired rows met on the way are deleted (lazy garbage collection — no cron needed)."""
    if not sid:
        return None
    with db.get_session() as s:
        row = s.get(db.UiSession, _sid_hash(sid))
        if not row:
            return None
        if row.expires_at <= _now():
            s.delete(row); s.commit()
            return None
        try:
            key = crypto.decrypt(_wrap_key(sid), row.master_key_enc, row.master_key_nonce)
        except Exception:
            return None
        row.last_seen = _now(); s.commit()
        return row, key


def revoke(sid: str) -> None:
    with db.get_session() as s:
        row = s.get(db.UiSession, _sid_hash(sid))
        if row:
            s.delete(row); s.commit()


def revoke_user(user_id: int) -> int:
    with db.get_session() as s:
        n = s.query(db.UiSession).filter_by(user_id=user_id).delete()
        s.commit()
        return n


def revoke_all() -> int:
    with db.get_session() as s:
        n = s.query(db.UiSession).delete()
        s.commit()
        return n


def active_count() -> int:
    with db.get_session() as s:
        return s.query(db.UiSession).filter(db.UiSession.expires_at > _now()).count()


def purge_expired() -> int:
    with db.get_session() as s:
        n = s.query(db.UiSession).filter(db.UiSession.expires_at <= _now()).delete()
        s.commit()
        return n
