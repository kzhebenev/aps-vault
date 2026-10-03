"""APS Vault client for Python 3.9+ — standard library only.

    from aps_vault import Vault
    v = Vault("https://vault.example.com", os.environ["VAULT_TOKEN"])
    db_password = v.get("db-password")             # str
    full = v.get_full("db-password")               # {"name","value","login"?,"notes"?,"totp"?,"updated_at"}
    v.put("db-password", "new-value", login="app")  # token needs can_write

Behaviour:
    * token must be a service token (``vlt_…``) — the master password never belongs in code;
    * in-memory cache (``cache_ttl``, default 300 s; 0 disables) so a restart storm does not
      hammer the vault, and a vault restart does not take the application down;
    * retries with exponential back-off on 429/5xx/network errors (``max_retries``);
    * ``fail_open_cache=True`` returns the last cached value when the vault is unreachable
      and the entry is stale — the right trade-off for an encryption key at startup;
    * nothing is logged; exceptions carry the HTTP status and the server's ``detail``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

__version__ = "0.15.0"


class VaultError(Exception):
    """HTTP-level error from the vault (status + server detail)."""

    def __init__(self, status: int, message: str, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class _Entry:
    value: dict
    expires_at: float


class Vault:
    def __init__(self, base_url: str, token: str, *, cache_ttl: float = 300.0,
                 timeout: float = 5.0, max_retries: int = 3, fail_open_cache: bool = True,
                 user_agent: str = f"aps-vault-python/{__version__}") -> None:
        if not base_url:
            raise ValueError("vault: base_url required")
        if not token or not token.startswith("vlt_"):
            raise ValueError("vault: a service token (vlt_…) is required, not a master password")
        self._base = base_url.rstrip("/")
        self._token = token
        self._ttl = cache_ttl
        self._timeout = timeout
        self._retries = max_retries
        self._fail_open = fail_open_cache
        self._ua = user_agent
        self._cache: dict[str, _Entry] = {}

    @classmethod
    def from_env(cls, **kw: Any) -> "Vault":
        """VAULT_URL + VAULT_TOKEN, or VAULT_TOKEN_FILE pointing at a 0600 file."""
        url = os.environ.get("VAULT_URL", "")
        token = os.environ.get("VAULT_TOKEN", "")
        if not token and os.environ.get("VAULT_TOKEN_FILE"):
            with open(os.environ["VAULT_TOKEN_FILE"], encoding="utf-8") as f:
                token = f.read().strip()
        return cls(url, token, **kw)

    # ── public API ────────────────────────────────────────────────────────────
    def health(self) -> dict:
        return self._req("GET", "/api/v1/m/health")

    def list(self) -> list[dict]:
        return self._req("GET", "/api/v1/m/secrets")

    def get(self, name: str, version: int | None = None) -> str:
        """Current value, or an older one by number (`version`) — e.g. the previous encryption
        key while files encrypted with it are still being re-wrapped."""
        return self.get_full(name, version)["value"]

    def versions(self, name: str) -> dict:
        """{"current_version": N, "versions": [{"version", "current", "changed_at", ...}]} — no decrypt."""
        return self._req("GET", "/api/v1/m/secret/" + urllib.parse.quote(name, safe="") + "/versions")

    def get_full(self, name: str, version: int | None = None) -> dict:
        if not name:
            raise ValueError("vault: name required")
        now = time.time()
        key = f"{name}@{version}" if version else name
        hit = self._cache.get(key)
        if hit and hit.expires_at > now:
            return hit.value
        try:
            data = self._req("GET", "/api/v1/m/secret/" + urllib.parse.quote(name, safe="") + (f"?version={int(version)}" if version else ""))
        except (VaultError, OSError) as e:
            if hit and self._fail_open and (not isinstance(e, VaultError) or e.status >= 500 or e.status == 429):
                return hit.value          # stale but known-good beats an outage
            raise
        if self._ttl > 0:
            self._cache[key] = _Entry(data, now + self._ttl)
        return data

    def put(self, name: str, value: str, *, login: str = "", tags: str = "", url: str = "") -> dict:
        """Create or update a secret in the token's folder (token must have can_write)."""
        body = {"value": value, "login": login, "tags": tags, "url": url}
        data = self._req("POST", "/api/v1/m/secret/" + urllib.parse.quote(name, safe=""), body)
        self._cache.pop(name, None)
        return data

    def totp(self, name: str) -> Optional[str]:
        """Current TOTP code (token must have can_read_totp); None if the secret has no seed."""
        self._cache.pop(name, None)       # codes change every 30 s — never serve from cache
        return self._req("GET", "/api/v1/m/secret/" + urllib.parse.quote(name, safe="")).get("totp")

    def clear_cache(self) -> None:
        self._cache.clear()

    # ── transport ─────────────────────────────────────────────────────────────
    def _req(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        last: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(self._base + path, data=payload, method=method, headers={
                "Authorization": f"Bearer {self._token}", "Accept": "application/json",
                "Content-Type": "application/json", "User-Agent": self._ua,
            })
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as r:   # nosec — URL is the configured vault
                    return json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                raw = e.read()
                try:
                    parsed: Any = json.loads(raw)
                    detail = parsed.get("detail") if isinstance(parsed, dict) else None
                except Exception:
                    parsed, detail = raw.decode("utf-8", "replace"), None
                if (e.code == 429 or e.code >= 500) and attempt < self._retries:
                    time.sleep(2 ** attempt)
                    continue
                raise VaultError(e.code, f"vault {method} {path}: HTTP {e.code} {detail or e.reason}", parsed) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
                if attempt < self._retries:
                    time.sleep(2 ** attempt)
                    continue
        raise OSError(f"vault: request failed after {self._retries + 1} attempts: {last}")


__all__ = ["Vault", "VaultError", "__version__"]
