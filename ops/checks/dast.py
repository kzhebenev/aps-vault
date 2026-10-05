#!/usr/bin/env python3
"""Live behaviour checks (DAST) against a running APS Vault — what a scanner cannot know: roles, scopes, flags.

    E2E_ALLOW_PRIVATE=0 ops/checks/e2e-stack.sh up && python3 ops/checks/dast.py http://localhost:8189

Needs a throwaway instance: fresh (initialised here with the init token) or initialised with the given master password (it creates folders, users, tokens and changes settings — never point it at
production). Every check prints PASS / FAIL with the observed status; the exit code is the number of failures.
Covers: UI and API security headers, CSRF, unauthenticated access, role boundaries of named users (reader / writer /
manager vs owner-only endpoints), IDOR by id across folders, service-token scope (machine API and the HashiCorp
facade, path tricks), canary tokens, the two-person rule and machine-only flags, share links, SSRF guards on webhooks
and rotation receivers, attempt lockout, error hygiene (no stack traces, no 500 on malformed input)."""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8189").rstrip("/")
MASTER = sys.argv[2] if len(sys.argv) > 2 else "dast master password 2026!"
INIT_TOKEN = sys.argv[3] if len(sys.argv) > 3 else "e2e-init-token"
FAILS: list[str] = []


class Client:
    """A cookie-carrying client. Session cookies are Secure; over plain http a cookie jar drops them, so they are
    carried by hand."""

    def __init__(self, token: str | None = None):
        self.cookies: dict[str, str] = {}
        self.csrf = ""
        self.token = token

    def req(self, method: str, path: str, body=None, headers=None, csrf=True, raw: bytes | None = None):
        h = {"Accept": "application/json", **(headers or {})}
        data = None
        if raw is not None:
            data = raw; h.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
        try:
            resp = urllib.request.urlopen(r, timeout=20)
            status, hdrs, text = resp.status, resp.headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, hdrs, text = e.code, e.headers, e.read().decode("utf-8", "replace")
        for sc in hdrs.get_all("Set-Cookie") or []:
            k, _, v = sc.split(";", 1)[0].partition("=")
            self.cookies[k.strip()] = v.strip()
        try:
            js = json.loads(text) if text else None
        except ValueError:
            js = None
        return status, hdrs, js, text


def check(name: str, cond: bool, observed: object = ""):
    print(("PASS " if cond else "FAIL ") + name + (f"   [{observed}]" if observed != "" else ""))
    if not cond:
        FAILS.append(name)


def init_if_needed() -> None:
    """A fresh stack (ops/checks/e2e-stack.sh with E2E_ALLOW_PRIVATE=0) is initialised here with the init token."""
    st, _, js, _ = Client().req("GET", "/api/health")
    if js and not js.get("initialized"):
        st, _, js, _ = Client().req("POST", "/api/init", {"master_password": MASTER, "init_token": INIT_TOKEN}, csrf=False)
        assert st == 200, f"init failed: {st} {js}"


def owner() -> Client:
    c = Client()
    st, _, js, _ = c.req("POST", "/api/auth/unlock", {"master_password": MASTER}, csrf=False)
    assert st == 200, f"owner unlock failed: {st}"
    c.csrf = js["csrf_token"]
    return c


def user(o: Client, email: str, grants: list[dict]) -> tuple[Client, int]:
    st, _, js, _ = o.req("POST", "/api/users", {"email": email, "grants": grants})
    assert st == 200, (st, js)
    uid, invite = js["id"], js["invite_url"].rsplit("/", 1)[-1]
    pw = "dast user password 2026!"
    st, _, _, _ = Client().req("POST", f"/api/invite/{invite}", {"password": pw}, csrf=False)
    c = Client()
    st, _, js, _ = c.req("POST", "/api/auth/login", {"email": email, "password": pw}, csrf=False)
    assert st == 200, (st, js)
    c.csrf = js["csrf_token"]
    return c, uid


def main() -> int:
    import time
    run = str(int(time.time()))[-6:]
    # ── headers ──
    st, h, _, body = Client().req("GET", "/")
    csp = h.get("Content-Security-Policy") or ""
    check("UI: CSP header with script-src 'self' and frame-ancestors 'none'", "script-src 'self'" in csp and "frame-ancestors 'none'" in csp, csp[:60])
    check("UI: X-Frame-Options DENY", (h.get("X-Frame-Options") or "").upper() == "DENY", h.get("X-Frame-Options"))
    check("UI: X-Content-Type-Options nosniff", (h.get("X-Content-Type-Options") or "") == "nosniff")
    check("UI: no inline <script> in index.html (the CSP would block it)", "<script>" not in body)
    check("UI: nginx version not disclosed", "/" not in (h.get("Server") or "nginx"), h.get("Server"))
    st, h, _, _ = Client().req("GET", "/app.js")
    check("UI: scripts carry nosniff and the CSP", (h.get("X-Content-Type-Options") == "nosniff") and bool(h.get("Content-Security-Policy")))
    st, h, _, _ = Client().req("GET", "/api/health")
    check("API: Cache-Control no-store", (h.get("Cache-Control") or "") == "no-store", h.get("Cache-Control"))
    for p in ("/docs", "/openapi.json", "/redoc"):
        st, _, _, b = Client().req("GET", p)
        check(f"API docs not exposed through the frontend: {p}", st in (200, 404) and "swagger" not in b.lower() and '"openapi"' not in b, st)

    # ── unauthenticated / CSRF ──
    for m, p in (("GET", "/api/folders"), ("GET", "/api/secrets"), ("GET", "/api/audit"), ("GET", "/api/export"), ("GET", "/api/tokens"), ("GET", "/api/users")):
        st, _, _, _ = Client().req(m, p)
        check(f"anonymous {m} {p} refused", st in (401, 403, 423), st)
    init_if_needed()
    o = owner()
    c_nocsrf = Client(); c_nocsrf.cookies = dict(o.cookies)
    st, _, _, _ = c_nocsrf.req("POST", "/api/folders", {"name": "csrf-probe"}, csrf=False)
    check("CSRF: a state change without X-CSRF-Token is refused", st == 403, st)
    st, _, _, _ = c_nocsrf.req("POST", "/api/folders", {"name": "csrf-probe"}, headers={"X-CSRF-Token": "forged"}, csrf=False)
    check("CSRF: a wrong X-CSRF-Token is refused", st == 403, st)

    # ── world ──
    fa = o.req("POST", "/api/folders", {"name": f"dast-a-{run}"})[2]["id"]
    fb = o.req("POST", "/api/folders", {"name": f"dast-b-{run}"})[2]["id"]
    sa = o.req("POST", "/api/secrets", {"folder_id": fa, "name": "a-secret", "value": "value-of-a"})[2]["id"]
    sb = o.req("POST", "/api/secrets", {"folder_id": fb, "name": "b-secret", "value": "value-of-b"})[2]["id"]
    sflag = o.req("POST", "/api/secrets", {"folder_id": fa, "name": "a-guarded", "value": "two-person-value", "require_approval": True})[2]["id"]
    rdr, _ = user(o, f"dast-reader-{run}@example.com", [{"folder_id": fa, "role": "reader"}])
    wrt, _ = user(o, f"dast-writer-{run}@example.com", [{"folder_id": fa, "role": "writer"}])
    mgr, _ = user(o, f"dast-manager-{run}@example.com", [{"folder_id": fa, "role": "manager"}])

    # ── role boundaries ──
    for who, c in (("reader", rdr), ("writer", wrt), ("manager", mgr)):
        for m, p, b in (("GET", "/api/audit", None), ("GET", "/api/export", None), ("POST", "/api/import", {"folders": []}),
                        ("POST", "/api/webhooks", {"name": "x", "url": "https://example.com/h"}),
                        ("POST", f"/api/folders/{fa}/rotate-key", {}), ("POST", "/api/auth/change-password", {"current_password": "x", "new_password": "y" * 12})):
            st, _, _, _ = c.req(m, p, b)
            check(f"{who}: owner-only {m} {p} refused", st in (401, 403), st)
        st, _, js, txt = c.req("GET", f"/api/secrets/{sb}")
        check(f"{who}: IDOR — secret of a folder without a grant is not readable by id", st in (403, 404) and "value-of-b" not in txt, st)
        st, _, js, txt = c.req("GET", "/api/secrets")
        check(f"{who}: list shows no secret of another folder", st == 200 and "b-secret" not in txt, st)
        st, _, _, txt = c.req("GET", f"/api/secrets/{sflag}")
        check(f"{who}: a 'requires approval' value is not in the card", "two-person-value" not in txt, st)
    st, _, _, _ = rdr.req("PATCH", f"/api/secrets/{sa}", {"value": "reader-wrote"})
    check("reader cannot write", st == 403, st)
    st, _, _, _ = wrt.req("PATCH", f"/api/secrets/{sflag}", {"require_approval": False})
    check("writer cannot lift 'requires approval'", st == 403, st)
    st, _, _, _ = mgr.req("POST", "/api/tokens", {"name": f"mgr-tok-{run}", "folder_id": fa})
    check("manager cannot issue a token for a folder with flagged secrets", st == 403, st)
    st, _, _, _ = mgr.req("POST", "/api/tokens", {"name": f"mgr-tok-b-{run}", "folder_id": fb})
    check("manager cannot issue a token for a folder they do not manage", st in (403, 404), st)

    # ── service-token scope ──
    tok = o.req("POST", "/api/tokens", {"name": f"dast-tok-{run}", "folder_id": fb})[2]["raw_token"]
    m = Client(token=tok)
    st, _, js, _ = m.req("GET", "/api/v1/m/secret/b-secret")
    check("token reads its own folder", st == 200 and js and js.get("value") == "value-of-b", st)
    for p in ("/api/v1/m/secret/a-secret", "/api/v1/m/secret/..%2Fa-secret", f"/api/v1/m/secret/%2e%2e%2f{fa}"):
        st, _, _, txt = m.req("GET", p)
        check(f"token cannot leave its folder: {p}", st in (403, 404) and "value-of-a" not in txt, st)
    st, _, _, txt = m.req("GET", f"/v1/dast-a-{run}/data/a-secret")
    check("KV facade: another mount is refused", st == 403 and "value-of-a" not in txt, st)
    st, _, _, _ = m.req("POST", "/api/v1/m/secret/new-one", {"value": "x"})
    check("token without can_write cannot write", st == 403, st)
    st, _, _, _ = m.req("GET", "/api/folders")
    check("a service token is not a session for the human API", st in (401, 403), st)
    can = o.req("POST", "/api/tokens", {"name": f"dast-canary-{run}", "folder_id": fb, "canary": True, "allowed_cidrs": "10.123.0.0/16"})[2]["raw_token"]
    st, _, js, _ = Client(token=can).req("GET", "/api/v1/m/secret/b-secret")
    check("canary answers like an unknown token", st == 401 and js and js.get("detail") == "invalid service token", (st, (js or {}).get("detail")))
    st, _, js, _ = Client(token="vlt_" + "0" * 40).req("GET", "/api/v1/m/secret/b-secret")
    check("unknown token: 401", st == 401, st)

    # ── share link ──
    link = o.req("POST", "/api/share", {"secret_id": sb, "max_uses": 1, "ttl_minutes": 5})[2]["url"].rsplit("/", 1)[-1]
    st1 = Client().req("GET", f"/api/share/{link}")[0]
    st2 = Client().req("GET", f"/api/share/{link}")[0]
    check("share link opens once, then 410", (st1, st2) == (200, 410), (st1, st2))
    st, _, _, _ = Client().req("GET", "/api/share/" + "A" * 32)
    check("unknown share link: 404", st == 404, st)

    # ── SSRF guards ──
    for url in ("https://169.254.169.254/latest/meta-data/", "https://127.0.0.1/", "https://100.64.0.1/", "http://example.com/"):
        st, _, _, _ = o.req("POST", "/api/webhooks", {"name": f"ssrf-{run}", "url": url})
        check(f"webhook to {url} refused", st in (400, 422), st)
    st, _, _, _ = o.req("PUT", f"/api/secrets/{sb}/rotation", {"target": "http", "config": {"url": "https://10.0.0.1/rotate"}})
    check("rotation receiver in a private network refused", st == 422, st)

    # ── error hygiene ──
    st, _, _, txt = o.req("POST", "/api/folders", raw=b"{not json")
    check("malformed JSON → 4xx, no stack trace", 400 <= st < 500 and "Traceback" not in txt, st)
    wtok = o.req("POST", "/api/tokens", {"name": f"dast-writer-tok-{run}", "folder_id": fb, "can_write": True})[2]["raw_token"]
    st, _, _, txt = Client(token=wtok).req("POST", f"/v1/dast-b-{run}/data/x", raw=b"{not json")
    check("KV write with malformed JSON → 4xx (was 500)", 400 <= st < 500, st)
    st, _, _, txt = o.req("GET", "/api/secrets/999999999")
    check("unknown id → 404", st == 404 and "Traceback" not in txt, st)
    st, _, _, txt = o.req("POST", "/api/secrets", {"folder_id": fa, "name": "x' OR '1'='1", "value": "v"})
    st2, _, js, _ = o.req("GET", "/api/secrets")
    check("SQL metacharacters in a name are stored literally", st == 200 and any(s.get("name") == "x' OR '1'='1" for s in (js or [])), st)
    st, _, _, _ = o.req("PATCH", f"/api/secrets/{sa}", {"url": "javascript:alert(1)"})
    check("javascript: URL refused", st == 422, st)

    # ── lockout (last: it locks this address for the window) ──
    codes = [Client().req("POST", "/api/auth/unlock", {"master_password": "wrong wrong wrong"}, csrf=False)[0] for _ in range(6)]
    check("unlock attempts are limited (401… then 429)", codes[:5].count(401) >= 4 and codes[-1] == 429, codes)
    print(f"\nDAST: {len(FAILS)} failure(s)")
    return len(FAILS)


if __name__ == "__main__":
    sys.exit(main())
