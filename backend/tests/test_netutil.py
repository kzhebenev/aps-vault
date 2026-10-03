"""Client-IP resolution: the rate limiter is only as good as this function."""
from types import SimpleNamespace

import netutil
import settings


def _req(peer, xff=None, real=None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    if real is not None:
        headers["x-real-ip"] = real
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


def _with(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    settings.reload()


def test_untrusted_peer_headers_are_ignored(monkeypatch):
    _with(monkeypatch, VAULT_TRUSTED_PROXIES="10.0.0.0/8", VAULT_PROXY_HOPS="1")
    assert netutil.client_ip(_req("203.0.113.5", xff="1.2.3.4", real="9.9.9.9")) == "203.0.113.5"


def test_trusted_peer_takes_the_hop_we_control(monkeypatch):
    _with(monkeypatch, VAULT_TRUSTED_PROXIES="10.0.0.0/8", VAULT_PROXY_HOPS="1")
    # bundled nginx appended the real client last
    assert netutil.client_ip(_req("10.0.0.2", xff="198.51.100.7")) == "198.51.100.7"
    # client prepended a spoof: still the last element wins
    assert netutil.client_ip(_req("10.0.0.2", xff="1.1.1.1, 198.51.100.7")) == "198.51.100.7"
    # X-Real-IP from the client is never used
    assert netutil.client_ip(_req("10.0.0.2", xff="198.51.100.7", real="1.1.1.1")) == "198.51.100.7"


def test_two_proxy_hops(monkeypatch):
    _with(monkeypatch, VAULT_TRUSTED_PROXIES="10.0.0.0/8 172.16.0.0/12", VAULT_PROXY_HOPS="2")
    # client → edge proxy (writes client) → bundled nginx (writes edge) → us
    assert netutil.client_ip(_req("172.18.0.3", xff="spoofed, 198.51.100.7, 172.31.0.32")) == "198.51.100.7"


def test_short_chain_never_falls_back_to_client_value(monkeypatch):
    _with(monkeypatch, VAULT_TRUSTED_PROXIES="10.0.0.0/8", VAULT_PROXY_HOPS="2")
    # only one element but two hops configured → cannot be trusted → peer
    assert netutil.client_ip(_req("10.0.0.2", xff="1.1.1.1")) == "10.0.0.2"
    assert netutil.client_ip(_req("10.0.0.2")) == "10.0.0.2"
    assert netutil.client_ip(_req("10.0.0.2", xff="not-an-ip, also-not")) == "10.0.0.2"


def test_client_inside_trusted_range_is_not_exploitable(monkeypatch):
    """Docker host gateway (172.18.0.1) talks to the bundled nginx directly. The old
    'rightmost non-trusted' heuristic would have returned the spoofed 1.1.1.1 here."""
    _with(monkeypatch, VAULT_TRUSTED_PROXIES="172.16.0.0/12", VAULT_PROXY_HOPS="1")
    assert netutil.client_ip(_req("172.18.0.3", xff="1.1.1.1, 172.18.0.1")) == "172.18.0.1"
    settings.reload()


def teardown_module(module):
    # restore the conftest environment for the rest of the suite
    import os
    os.environ["VAULT_TRUSTED_PROXIES"] = "10.0.0.0/8"
    os.environ["VAULT_PROXY_HOPS"] = "1"
    settings.reload()
