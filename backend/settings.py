"""Runtime configuration from environment variables — the only place that reads os.environ
for deployment-specific values. Everything that used to be hard-coded to one installation
(allowed origins, public URL, trusted proxies) lives here.

Why a module and not pydantic-settings: four variables do not justify a dependency, and the
test-suite needs to re-read the environment after monkeypatching, hence `reload()`.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Docker bridge networks and loopback: the reverse proxy / frontend container that forwards
# to us normally lives there. Override with VAULT_TRUSTED_PROXIES when the proxy is elsewhere.
_DEFAULT_TRUSTED = "127.0.0.1/32 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


@dataclass
class Settings:
    dev: bool = False
    public_url: str = ""
    allowed_origins: list[str] = field(default_factory=list)
    init_token: str = ""
    trusted_proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    # how many proxies append to X-Forwarded-For before us: 1 = only the bundled frontend
    # nginx; 2 = your reverse proxy + bundled nginx. See netutil.client_ip.
    proxy_hops: int = 1
    webhook_allow_private: bool = False
    # brute-force limits for /auth/unlock and /auth/recover
    fail_limit_per_ip: int = 5
    fail_limit_global: int = 50
    fail_window_sec: int = 15 * 60
    # observability: syslog/SIEM forwarder, Prometheus scrape token, fail2ban-friendly log
    syslog_url: str = ""          # udp://host:514 | tcp://host:514 ; empty = off
    syslog_format: str = "json"   # json | cef
    metrics_token: str = ""       # Bearer for GET /metrics and /api/security/*; empty = endpoints disabled
    security_log: str = ""        # path of the fail2ban-friendly log; empty = off
    # access policy for the human UI (PAM-style); tokens carry their own policy in the DB
    ui_allowed_cidrs: str = ""    # "10.0.0.0/8 203.0.113.7/32"; empty = anywhere
    ui_allowed_hours: str = ""    # "Mon-Fri 08:00-20:00"; empty = always
    timezone: str = "UTC"         # for the time windows
    # password-leak check in the UI: the server forwards a 5-hex-char SHA-1 prefix to
    # api.pwnedpasswords.com (k-anonymity) — nothing identifiable leaves the vault. Off → 404.
    hibp_enabled: bool = True
    # SSO unlock across replicas: a server-side secret (≥32 random bytes, hex or base64, the
    # same on every replica, NOT known to the IdP). The master key is kept in the database
    # wrapped under HKDF(this key) once the administrator enables it from Settings; an
    # OIDC-verified login on any replica can then mint a session. Empty = feature unavailable.
    sso_unlock_key: bytes = b""
    # mTLS token binding (0.11): the TLS-terminating proxy verifies the client certificate and
    # passes its fingerprint in this header (nginx: $ssl_client_fingerprint = SHA-1 hex;
    # a SHA-256 hex is accepted too). Honoured only from trusted proxies (VAULT_TRUSTED_PROXIES).
    client_cert_header: str = "x-client-cert-fingerprint"

    @property
    def public_host(self) -> str:
        return urlparse(self.public_url).hostname or "vault"


def _networks(spec: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for tok in spec.split():
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue   # a typo in the list must not take the service down; it only narrows trust
    return out


def _sso_key(raw: str) -> bytes:
    """Accept hex or base64; refuse anything shorter than 32 bytes so a weak value cannot be
    used by accident (a short key would make the database dump the whole secret)."""
    import base64, binascii
    raw = raw.strip()
    if not raw:
        return b""
    try:
        b = bytes.fromhex(raw)
    except ValueError:
        try:
            b = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
        except (binascii.Error, ValueError):
            b = raw.encode("utf-8")
    return b if len(b) >= 32 else b""


def load() -> Settings:
    env = os.environ
    dev = env.get("VAULT_DEV", "") in ("1", "true", "yes")
    origins = env.get("VAULT_ALLOWED_ORIGINS", "").split()
    if dev:
        origins += ["http://localhost:8087", "http://127.0.0.1:8087", "http://localhost:5173"]
    return Settings(
        dev=dev,
        public_url=env.get("VAULT_PUBLIC_URL", "").rstrip("/"),
        allowed_origins=origins,
        init_token=env.get("VAULT_INIT_TOKEN", ""),
        trusted_proxies=_networks(env.get("VAULT_TRUSTED_PROXIES", _DEFAULT_TRUSTED)),
        proxy_hops=max(0, int(env.get("VAULT_PROXY_HOPS", "1"))),
        webhook_allow_private=env.get("VAULT_WEBHOOK_ALLOW_PRIVATE", "") in ("1", "true", "yes"),
        fail_limit_per_ip=int(env.get("VAULT_FAIL_LIMIT_PER_IP", "5")),
        fail_limit_global=int(env.get("VAULT_FAIL_LIMIT_GLOBAL", "50")),
        fail_window_sec=int(env.get("VAULT_FAIL_WINDOW_SEC", str(15 * 60))),
        syslog_url=env.get("VAULT_SYSLOG_URL", "").strip(),
        syslog_format=env.get("VAULT_SYSLOG_FORMAT", "json").strip().lower() or "json",
        metrics_token=env.get("VAULT_METRICS_TOKEN", "").strip(),
        security_log=env.get("VAULT_SECURITY_LOG", "").strip(),
        ui_allowed_cidrs=env.get("VAULT_UI_ALLOWED_CIDRS", "").strip(),
        ui_allowed_hours=env.get("VAULT_UI_ALLOWED_HOURS", "").strip(),
        timezone=env.get("VAULT_TIMEZONE", "UTC").strip() or "UTC",
        hibp_enabled=env.get("VAULT_HIBP", "1") not in ("0", "false", "no", "off"),
        sso_unlock_key=_sso_key(env.get("VAULT_SSO_UNLOCK_KEY", "")),
        client_cert_header=(env.get("VAULT_CLIENT_CERT_HEADER", "X-Client-Cert-Fingerprint").strip() or "X-Client-Cert-Fingerprint").lower(),
    )


SETTINGS = load()


def reload() -> Settings:
    """Re-read the environment (tests)."""
    global SETTINGS
    SETTINGS = load()
    return SETTINGS
