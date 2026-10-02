"""In-memory state: master_key + список последних попыток unlock + сессии."""
from __future__ import annotations

import hashlib
import secrets as pysecrets
import time
from dataclasses import dataclass, field


@dataclass
class VaultState:
    """Не-БД состояние сервера. Сбрасывается на рестарте — нужен повторный unlock."""
    master_key: bytes | None = None
    sessions: dict[str, dict] = field(default_factory=dict)
    # IP → последние таймштампы фейлов
    fail_history: dict[str, list[float]] = field(default_factory=dict)

    def is_unlocked(self) -> bool:
        return self.master_key is not None

    def lock(self) -> None:
        if self.master_key is not None:
            # Zeroize в меру возможностей Python
            try:
                ba = bytearray(self.master_key)
                for i in range(len(ba)):
                    ba[i] = 0
            except Exception:
                pass
        self.master_key = None

    def issue_session(self, ttl: int = 8 * 3600) -> str:
        sid = pysecrets.token_urlsafe(32)
        self.sessions[sid] = {"created": time.time(), "ttl": ttl}
        return sid

    def is_session_valid(self, sid: str) -> bool:
        s = self.sessions.get(sid)
        if not s:
            return False
        if time.time() - s["created"] > s["ttl"]:
            del self.sessions[sid]
            return False
        return True

    def revoke_session(self, sid: str) -> None:
        self.sessions.pop(sid, None)

    def record_fail(self, ip: str) -> int:
        now = time.time()
        hist = self.fail_history.setdefault(ip, [])
        # сбрасываем старше 15 минут
        cutoff = now - 15 * 60
        hist[:] = [t for t in hist if t > cutoff]
        hist.append(now)
        return len(hist)

    def clear_fails(self, ip: str) -> None:
        self.fail_history.pop(ip, None)


STATE = VaultState()


def hash_token(token: str) -> str:
    """SHA-256 для service-token хеша (для look-up в БД)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
