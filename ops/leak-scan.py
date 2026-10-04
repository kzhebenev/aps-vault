#!/usr/bin/env python3
"""Find APS Vault service tokens that leaked into files, repositories or logs — and check with the
vault which of them are live, without ever sending the tokens themselves.

    ops/leak-scan.py PATH [PATH …] [--url https://vault.example.com] [--revoke] [--json]
    git log -p | ops/leak-scan.py -                      # stdin: a git history, CI logs, a chat export
    gh search code 'vlt_' --json textMatches -q '.[].textMatches[].fragment' | ops/leak-scan.py -

What it does: scans for the token shape (vlt_<12 base32>_<64 hex>), hashes every hit the way the
vault stores token hashes (SHA-256 in the aes suite, Streebog-256 in the gost suite — learnt from
/api/health), and asks POST /api/tokens/leak-check with the owner's session which hashes belong to
live tokens. `--revoke` revokes them on the spot. The master password comes from VAULT_MASTER_PASSWORD
or a prompt; the vault URL from --url or VAULT_URL.

Exit status: 0 nothing live, 2 live tokens found (so a CI step can fail), 1 error.
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

TOKEN_RE = re.compile(r"vlt_[a-z2-7]{12}_[0-9a-f]{64}")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
MAX_FILE = 20 * 1024 * 1024


def _streebog256(data: bytes) -> str:
    try:
        import gostcrypto  # type: ignore
        return gostcrypto.gosthash.new("streebog256", data=data).hexdigest()
    except ImportError:
        sys.exit("the vault runs the gost suite: install gostcrypto (pip install gostcrypto) to hash tokens with Streebog-256")


def scan_text(text: str, where: str, hits: dict) -> None:
    for m in TOKEN_RE.finditer(text):
        hits.setdefault(m.group(0), []).append(where)


def scan_path(path: str, hits: dict) -> None:
    if os.path.isfile(path):
        try:
            if os.path.getsize(path) > MAX_FILE:
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                scan_text(f.read(), path, hits)
        except OSError:
            pass
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            scan_path(os.path.join(root, fn), hits)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="files / directories, or - for stdin")
    ap.add_argument("--url", default=os.environ.get("VAULT_URL", ""), help="vault URL (VAULT_URL)")
    ap.add_argument("--revoke", action="store_true", help="revoke the live tokens that were found")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    a = ap.parse_args()
    hits: dict = {}
    for p in a.paths:
        if p == "-":
            scan_text(sys.stdin.read(), "stdin", hits)
        else:
            scan_path(p, hits)
    if not hits:
        print(json.dumps({"candidates": 0, "live": []}) if a.json else "no token-shaped strings found")
        return 0
    if not a.url:
        sys.exit("--url or VAULT_URL is required to check the candidates with the vault")
    ctx = None
    if a.insecure:
        import ssl
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    url = a.url.rstrip("/")

    def req(method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url + path, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:   # nosemgrep: dynamic-urllib-use — the administrator's own vault
                cookies = resp.headers.get_all("Set-Cookie") or []
                return json.loads(resp.read().decode() or "null"), cookies
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode()).get("detail", "")
            except Exception:
                detail = ""
            if e.code == 405 and path.endswith("/leak-check"):
                detail = detail or "this vault is older than 0.26 — no /api/tokens/leak-check"
            sys.exit(f"vault answered HTTP {e.code} on {method} {path}: {detail or e.reason}")
        except urllib.error.URLError as e:
            sys.exit(f"cannot reach {url}: {e.reason}")

    health, _ = req("GET", "/api/health")
    suite = health.get("cipher", "aes")
    digest = (lambda t: hashlib.sha256(t.encode()).hexdigest()) if suite != "gost" else (lambda t: _streebog256(t.encode()))
    by_hash = {digest(t): t for t in hits}
    pw = os.environ.get("VAULT_MASTER_PASSWORD") or getpass.getpass("master password (owner session, to ask which hashes are live): ")
    login, cookies = req("POST", "/api/auth/unlock", {"master_password": pw})
    cookie = "; ".join(c.split(";", 1)[0] for c in cookies)
    hdr = {"Cookie": cookie, "X-CSRF-Token": login["csrf_token"]}
    try:
        res, _ = req("POST", "/api/tokens/leak-check", {"hashes": list(by_hash), "revoke": a.revoke}, hdr)
    finally:
        try:
            req("POST", "/api/auth/lock", {}, hdr)
        except Exception:
            pass
    live = []
    for f in res["found"]:
        tok = by_hash.get(f["hash"], "")
        live.append({**f, "token_prefix": tok[:17] + "…", "where": sorted(set(hits.get(tok, [])))[:10]})
    if a.json:
        print(json.dumps({"candidates": len(hits), "checked": res["checked"], "live": live, "revoked": res["revoked"]}, ensure_ascii=False, indent=2))
    else:
        print(f"{len(hits)} token-shaped string(s) found, {len(live)} belong(s) to live tokens" + (f", {res['revoked']} revoked" if a.revoke else ""))
        for f in live:
            print(f"  {f['token_prefix']}  token '{f['name']}' (folder {f['folder_name']}, {'REVOKED' if f['revoked'] or a.revoke else 'LIVE'}) in: {', '.join(f['where'])}")
    return 2 if any(not f["revoked"] for f in live) and not a.revoke else 0


if __name__ == "__main__":
    sys.exit(main())
