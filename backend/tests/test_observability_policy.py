"""Syslog/SIEM forwarding (JSON and CEF), Prometheus metrics, fail2ban log, lock-out listing
and PAM-style policies for tokens and the UI."""
import json
import os
import socket
import threading
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import metrics
import netutil
import policy
import settings
import siem
from conftest import MASTER, unlock


# ── policy parsing / evaluation ──────────────────────────────────────────────
def test_policy_cidrs():
    assert policy.ip_allowed("", "203.0.113.5")
    assert policy.ip_allowed("10.0.0.0/8 203.0.113.5", "203.0.113.5")
    assert not policy.ip_allowed("10.0.0.0/8", "203.0.113.5")
    assert not policy.ip_allowed("10.0.0.0/8", "testclient"), "unparseable source is not 'anywhere'"
    with pytest.raises(ValueError):
        policy.validate("10.0.0.0/8 not-a-net", "")


def test_policy_hours(monkeypatch):
    monkeypatch.setenv("VAULT_TIMEZONE", "Europe/Moscow"); settings.reload()
    tz = ZoneInfo("Europe/Moscow")
    wed_noon = datetime(2026, 10, 7, 12, 0, tzinfo=tz)     # Wednesday
    sat_noon = datetime(2026, 10, 10, 12, 0, tzinfo=tz)
    wed_night = datetime(2026, 10, 7, 23, 30, tzinfo=tz)
    thu_early = datetime(2026, 10, 8, 3, 0, tzinfo=tz)
    assert policy.time_allowed("Mon-Fri 08:00-20:00", wed_noon)
    assert not policy.time_allowed("Mon-Fri 08:00-20:00", sat_noon)
    assert policy.time_allowed("Sat,Sun 00:00-24:00", sat_noon)
    assert policy.time_allowed("Wed 22:00-06:00", wed_night) and policy.time_allowed("Wed 22:00-06:00", thu_early)
    assert not policy.time_allowed("Wed 22:00-06:00", wed_noon)
    assert policy.time_allowed("Mon-Fri 08:00-12:00; Mon-Fri 13:00-20:00", wed_noon) is False
    # UTC interpretation differs: 12:00 MSK is 09:00 UTC
    monkeypatch.setenv("VAULT_TIMEZONE", "UTC"); settings.reload()
    assert not policy.time_allowed("Mon-Fri 10:00-20:00", wed_noon)
    with pytest.raises(ValueError):
        policy.parse_hours("Mon-Fri 8-20")
    settings.reload()


# ── token policy end-to-end ──────────────────────────────────────────────────
def test_token_policy_source_and_time(client, session):
    fid = client.post("/api/folders", json={"name": "pam"}, headers=session).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "k", "value": "v"}, headers=session)
    # bad specs are refused at creation
    r = client.post("/api/tokens", json={"name": "bad", "folder_id": fid, "allowed_cidrs": "nope/99"}, headers=session)
    assert r.status_code == 422
    r = client.post("/api/tokens", json={"name": "bad2", "folder_id": fid, "allowed_hours": "always"}, headers=session)
    assert r.status_code == 422
    # source policy: testclient's address is the literal "testclient" → never inside a CIDR
    t = client.post("/api/tokens", json={"name": "src", "folder_id": fid, "allowed_cidrs": "10.0.0.0/8"}, headers=session).json()
    r = client.get("/api/v1/m/secret/k", headers={"Authorization": f"Bearer {t['raw_token']}"})
    assert r.status_code == 403 and "allowed networks" in r.text
    # time policy: a window that is never "now" (zero-length) → denied; an all-day window → allowed
    t2 = client.post("/api/tokens", json={"name": "time", "folder_id": fid, "allowed_hours": "Mon-Sun 03:00-03:00"}, headers=session).json()
    assert client.get("/api/v1/m/secret/k", headers={"Authorization": f"Bearer {t2['raw_token']}"}).status_code == 403
    t3 = client.post("/api/tokens", json={"name": "allday", "folder_id": fid, "allowed_hours": "00:00-24:00"}, headers=session).json()
    assert client.get("/api/v1/m/secret/k", headers={"Authorization": f"Bearer {t3['raw_token']}"}).json()["value"] == "v"
    # policy is visible in the token list and audited on denial
    row = next(x for x in client.get("/api/tokens").json() if x["name"] == "src")
    assert row["allowed_cidrs"] == "10.0.0.0/8"
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 50}).json()]
    assert "m:auth:policy_denied" in actions


def test_ui_policy_blocks_unlock_and_requests(client, initialized, monkeypatch):
    unlock(client)
    assert client.get("/api/folders").status_code == 200
    monkeypatch.setenv("VAULT_UI_ALLOWED_CIDRS", "10.0.0.0/8"); settings.reload()
    try:
        assert client.get("/api/folders").status_code == 403, "existing session from a disallowed source is cut"
        netutil.clear_fails("testclient")
        r = client.post("/api/auth/unlock", json={"master_password": MASTER})
        assert r.status_code == 403
    finally:
        monkeypatch.delenv("VAULT_UI_ALLOWED_CIDRS"); settings.reload()
    unlock(client)
    assert client.get("/api/folders").status_code == 200


# ── syslog / SIEM ────────────────────────────────────────────────────────────
@pytest.fixture
def udp_sink():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); s.settimeout(3)
    got = []
    def rx():
        try:
            while True:
                got.append(s.recv(65535).decode("utf-8"))
        except (socket.timeout, OSError):
            pass
    th = threading.Thread(target=rx, daemon=True); th.start()
    yield s.getsockname()[1], got
    s.close()


def _wait(got, n, timeout=3.0):
    import time
    end = time.time() + timeout
    while len(got) < n and time.time() < end:
        time.sleep(0.02)


def test_syslog_json_and_cef(client, session, udp_sink, monkeypatch):
    port, got = udp_sink
    monkeypatch.setenv("VAULT_SYSLOG_URL", f"udp://127.0.0.1:{port}"); monkeypatch.setenv("VAULT_SYSLOG_FORMAT", "json"); settings.reload()
    try:
        client.post("/api/folders", json={"name": "siem"}, headers=session)
        _wait(got, 1)
        assert got, "no syslog datagram received"
        head, _, body = got[-1].partition(" - ")
        assert head.startswith("<") and " aps-vault " in got[-1]
        ev = json.loads(got[-1].split(" - ", 2)[2])
        assert ev["action"] == "folder:create" and ev["target"] == "siem" and ev["version"] == "0.28.1"
        # CEF
        monkeypatch.setenv("VAULT_SYSLOG_FORMAT", "cef"); settings.reload()
        n = len(got)
        netutil.clear_fails("testclient")
        client.post("/api/auth/unlock", json={"master_password": "wrong wrong wrong"})
        _wait(got, n + 1)
        cef = [g for g in got[n:] if "CEF:0|APS|Vault|" in g]
        assert cef, got[n:]
        line = cef[-1]
        assert "|auth:fail|auth fail|7|" in line and "src=testclient" in line and "act=auth:fail" in line
        # priority: authpriv(10)*8 + severity 4 = 84 for a failure
        assert line.startswith("<84>1 ")
        netutil.clear_fails("testclient")
    finally:
        monkeypatch.delenv("VAULT_SYSLOG_URL"); monkeypatch.delenv("VAULT_SYSLOG_FORMAT"); settings.reload()


def test_cef_escaping():
    ev = {"ts_ms": 0, "action": "secret:read", "actor": "master", "target": "f/a=b|c", "ip": "1.2.3.4", "ua": "x\ny", "meta": {}}
    line = siem.format_cef(ev, "0.28.1")
    assert "cs1=f/a\\=b|c" in line and "requestClientApplication=x y" in line


# ── security log for fail2ban ────────────────────────────────────────────────
def test_security_log_lines_match_fail2ban_filter(client, initialized, monkeypatch, tmp_path):
    log = tmp_path / "security.log"
    monkeypatch.setenv("VAULT_SECURITY_LOG", str(log)); settings.reload()
    try:
        netutil.clear_fails("testclient")
        client.post("/api/auth/unlock", json={"master_password": "wrong wrong wrong"})
        client.get("/api/v1/m/secret/x", headers={"Authorization": "Bearer vlt_garbage"})
        lines = log.read_text().splitlines()
        assert any("auth-fail ip=testclient kind=master" in l for l in lines)
        assert any("auth-fail ip=testclient kind=token" in l for l in lines)
        import re
        rx = re.compile(r"^\S+ \S+ aps-vault auth-fail ip=(\S+) kind=\S+")
        assert all(rx.match(l) for l in lines), lines
        netutil.clear_fails("testclient")
    finally:
        monkeypatch.delenv("VAULT_SECURITY_LOG"); settings.reload()


# ── metrics and lock-out listing ─────────────────────────────────────────────
def test_metrics_and_lockdowns_require_token(client, session, monkeypatch):
    assert client.get("/metrics").status_code == 404, "disabled when no token is configured"
    monkeypatch.setenv("VAULT_METRICS_TOKEN", "scrape-me"); settings.reload()
    try:
        assert client.get("/metrics").status_code == 401
        r = client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
        body = r.text
        assert 'aps_vault_info{version="0.28.1",node=' in body
        assert "aps_vault_secrets " in body and "aps_vault_unlocked 1" in body
        assert 'aps_vault_events_total{action="folder:create"}' in body
        assert "aps_vault_auth_failures_total" in body
        # lock an address, see it listed
        netutil.clear_fails("198.51.100.1")
        for _ in range(5):
            netutil.record_fail("198.51.100.1")
        lk = client.get("/api/security/lockdowns", headers={"Authorization": "Bearer scrape-me"}).json()
        assert any(x["ip"] == "198.51.100.1" and x["fail_count"] == 5 for x in lk["locked"])
        assert "aps_vault_locked_ips 1" in client.get("/metrics", headers={"Authorization": "Bearer scrape-me"}).text
        netutil.clear_fails("198.51.100.1")
    finally:
        monkeypatch.delenv("VAULT_METRICS_TOKEN"); settings.reload()



# ── mTLS binding (0.11) ──────────────────────────────────────────────────────
def test_fingerprint_parsing():
    sha1 = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01"
    assert policy.normalize_fingerprint(sha1) == "abcdef0123456789abcdef0123456789abcdef01"
    assert policy.normalize_fingerprint("sha256/" + "0" * 64) == "0" * 64
    assert policy.normalize_fingerprint("not-a-print") == ""
    with pytest.raises(ValueError):
        policy.parse_fingerprints("abc")
    assert policy.cert_allowed("", None) is True, "no binding → any client"
    assert policy.cert_allowed("0" * 40, None) is False, "bound token without a certificate is refused"
    assert policy.cert_allowed("0" * 40 + " " + "1" * 64, "11:11" + ":11" * 30) is True


def test_token_bound_to_client_certificate(client, session, monkeypatch):
    import netutil
    fid = client.post("/api/folders", json={"name": "mtls"}, headers=session).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "k", "value": "v"}, headers=session)
    fp = "a1" * 20
    assert client.post("/api/tokens", json={"name": "bad-fp", "folder_id": fid, "allowed_cert_fingerprints": "zzz"}, headers=session).status_code == 422
    t = client.post("/api/tokens", json={"name": "bound", "folder_id": fid, "allowed_cert_fingerprints": "A1:" * 19 + "A1"}, headers=session).json()
    H = {"Authorization": f"Bearer {t['raw_token']}"}
    row = next(x for x in client.get("/api/tokens").json() if x["name"] == "bound")
    assert row["allowed_cert_fingerprints"] == fp, "normalised to lowercase hex"
    # no certificate → refused; the header from an UNTRUSTED peer (the test client) is ignored → still refused
    assert client.get("/api/v1/m/secret/k", headers=H).status_code == 403
    assert client.get("/api/v1/m/secret/k", headers={**H, "X-Client-Cert-Fingerprint": fp}).status_code == 403, "a client cannot claim a certificate by itself"
    # the same header from a trusted proxy → allowed; a different certificate → refused
    monkeypatch.setattr(netutil, "from_trusted_proxy", lambda request: True)
    assert client.get("/api/v1/m/secret/k", headers={**H, "X-Client-Cert-Fingerprint": "A1:" * 19 + "A1"}).json()["value"] == "v"
    assert client.get("/api/v1/m/secret/k", headers={**H, "X-Client-Cert-Fingerprint": "b2" * 20}).status_code == 403
    assert client.get("/api/v1/m/health", headers={**H, "X-Client-Cert-Fingerprint": fp}).json().get("cert_bound") in (True, None)
    # unbound tokens are untouched by all this
    u = client.post("/api/tokens", json={"name": "unbound", "folder_id": fid}, headers=session).json()
    assert client.get("/api/v1/m/secret/k", headers={"Authorization": f"Bearer {u['raw_token']}"}).status_code == 200
    actions = [a["action"] for a in client.get("/api/audit", params={"limit": 30}).json()]
    assert "m:auth:policy_denied" in actions
