"""0.41: VAULT_TRUSTED_PROXIES accepts host names (e.g. "vault-frontend") next to networks."""
import socket
import types

import netutil
import settings


def _req(peer, xff=None):
    return types.SimpleNamespace(client=types.SimpleNamespace(host=peer), headers={"x-forwarded-for": xff} if xff else {})


def test_settings_split_networks_and_names():
    spec = "127.0.0.1/32 vault-frontend proxy.internal 10.0.0.0/8 not_a/net 999.1.1.1 ::1/128"
    assert [str(n) for n in settings._networks(spec)] == ["127.0.0.1/32", "10.0.0.0/8", "::1/128"]
    assert settings._proxy_hosts(spec) == ["vault-frontend", "proxy.internal"], "a bad network or a dotted number is not a name"


def test_a_named_proxy_is_trusted_at_its_current_address_only(monkeypatch):
    table = {"vault-frontend": ["172.20.0.5"]}
    calls = []

    def fake_getaddrinfo(host, port, *a, **k):
        calls.append(host)
        if host not in table:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[host]]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(settings.SETTINGS, "trusted_proxies", settings._networks("127.0.0.1/32"))
    monkeypatch.setattr(settings.SETTINGS, "trusted_proxy_hosts", ["vault-frontend", "late-proxy"])
    monkeypatch.setattr(settings.SETTINGS, "proxy_hops", 1)
    netutil._HOST_CACHE.clear()
    clock = [1000.0]
    import time
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    # the named proxy: its forwarded client address is used
    assert netutil.client_ip(_req("172.20.0.5", "203.0.113.7")) == "203.0.113.7"
    # a neighbour on the same network is NOT trusted — its X-Forwarded-For is ignored
    assert netutil.client_ip(_req("172.20.0.6", "203.0.113.99")) == "172.20.0.6"
    # cached: no new lookup within a minute
    n = len(calls); netutil.client_ip(_req("172.20.0.5", "1.2.3.4")); assert len(calls) == n
    # the proxy container is recreated with a new address: after the TTL the new one is trusted, the old one not
    table["vault-frontend"] = ["172.20.0.9"]
    clock[0] += netutil.HOST_TTL + 1
    assert netutil.client_ip(_req("172.20.0.9", "198.51.100.1")) == "198.51.100.1"
    assert netutil.client_ip(_req("172.20.0.5", "198.51.100.2")) == "172.20.0.5"
    # DNS hiccup: the last good answer stays
    table.pop("vault-frontend")
    clock[0] += netutil.HOST_TTL + 1
    assert netutil.client_ip(_req("172.20.0.9", "198.51.100.3")) == "198.51.100.3"
    # a name that never resolved trusts nobody, and is retried after 10 s
    assert netutil.client_ip(_req("172.20.0.50", "198.51.100.4")) == "172.20.0.50"
    table["late-proxy"] = ["172.20.0.50"]
    clock[0] += netutil.HOST_RETRY + 1
    assert netutil.client_ip(_req("172.20.0.50", "198.51.100.5")) == "198.51.100.5"
    # networks still work as before
    assert netutil.client_ip(_req("127.0.0.1", "192.0.2.1")) == "192.0.2.1"
    netutil._HOST_CACHE.clear()
