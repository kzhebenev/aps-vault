"""Process-local state — deliberately small since 0.6.

Everything a second replica must know lives in the database (sessions.py, netutil lock-outs,
vault_config). What stays here:

* the master key of the *current request*, set by `require_unlocked` from the session row and
  read by helpers deep in the call stack (`current_master_key`) — a contextvar, so concurrent
  requests never see each other's key;
* `node_master_key`: a convenience cache for OIDC logins on this node only. OIDC gives us an
  identity, not the master password, so an SSO login can mint a session only if this node has
  seen a master unlock (or VAULT_MASTER_PASSWORD is set — dev). Documented in docs/CLUSTER.md.
"""
from __future__ import annotations

import contextvars
import hashlib
from dataclasses import dataclass

_current: contextvars.ContextVar[bytes | None] = contextvars.ContextVar("aps_vault_master_key", default=None)


@dataclass
class VaultState:
    node_master_key: bytes | None = None

    def lock(self) -> None:
        """Forget the node cache (lock-all / recovery). Zeroize as far as Python allows."""
        if self.node_master_key is not None:
            try:
                ba = bytearray(self.node_master_key)
                for i in range(len(ba)):
                    ba[i] = 0
            except Exception:
                pass
        self.node_master_key = None


STATE = VaultState()


def set_current_master_key(key: bytes | None) -> None:
    _current.set(key)


def current_master_key() -> bytes:
    """Master key of the session that made this request; HTTP 401 when there is none."""
    key = _current.get()
    if key is None:
        from fastapi import HTTPException
        raise HTTPException(401, "vault is locked — unlock first")
    return key


def hash_token(token: str) -> str:
    """SHA-256 для service-token хеша (для look-up в БД)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
