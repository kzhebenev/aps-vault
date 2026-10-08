"""Regression tests for the white-box security review of 05.10.2026 (docs/SECURITY-REVIEW-2026-10-05.md).
Each test reproduces the attack from the review and asserts it is refused now."""
import os

import pytest
from fastapi.testclient import TestClient

import netutil
import settings
from conftest import MASTER, unlock
from test_webauthn import ORIGIN, SoftKey, b64u

PW = "review user password 2026!"


def _user(client, hdr, email, fid, role="reader"):
    r = client.post("/api/users", json={"email": email, "grants": [{"folder_id": fid, "role": role}]}, headers=hdr).json()
    import main
    with TestClient(main.app, base_url=ORIGIN) as anon:
        assert anon.post(f"/api/invite/{r['invite_url'].rsplit('/', 1)[-1]}", json={"password": PW}).status_code == 200
    return r["id"]


def _login(email, pw=PW, **extra):
    import main
    c = TestClient(main.app, base_url=ORIGIN)
    netutil.clear_fails("testclient")
    r = c.post("/api/auth/login", json={"email": email, "password": pw, **extra})
    return c, r


@pytest.fixture(scope="module")
def world(client, initialized):
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "review-0510"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "review-secret", "value": "crown-jewels"}, headers=hdr)
    return {"hdr": hdr, "fid": fid}


def test_sso_never_falls_through_to_the_owner(client, world, monkeypatch):
    """Finding A1 (Critical): with OIDC on and an owner key source on the replica, an IdP account that was not an
    ACTIVE named user got an OWNER session — including a user the owner had just deactivated. Now the owner path
    needs an explicit VAULT_OIDC_OWNERS entry, and any e-mail that ever belonged to a user is refused."""
    import main
    import oidc
    from state import STATE
    fid = world["fid"]
    monkeypatch.setattr(oidc, "is_enabled", lambda: True)
    hdr = unlock(client)                                      # with OIDC on, an owner unlock caches the master key on the node
    world["hdr"] = hdr
    assert STATE.node_master_key is not None, "precondition: the owner unlocked this node — the master key is cached"
    who = {"email": "stranger@example.com", "name": "S", "sub": "idp-123"}
    monkeypatch.setattr(oidc, "exchange_code", lambda request: dict(who))
    monkeypatch.delenv("VAULT_OIDC_OWNERS", raising=False)
    # 1) an IdP account unknown to the vault: refused, no session (it was an owner session before)
    with TestClient(main.app, base_url=ORIGIN) as anon:
        r = anon.get("/api/auth/oidc/callback", follow_redirects=False)
        assert r.status_code == 403 and not anon.cookies.get("vault_session"), (r.status_code, r.text)
        assert anon.get("/api/folders").status_code in (401, 423)
    # 2) a user who was deactivated: refused (the deactivation used to PROMOTE them to owner)
    uid = _user(client, hdr, "former@example.com", fid)
    client.delete(f"/api/users/{uid}", headers=hdr)
    who.update(email="former@example.com", sub="idp-former")
    monkeypatch.setenv("VAULT_OIDC_OWNERS", "former@example.com")        # even if someone lists them by mistake
    with TestClient(main.app, base_url=ORIGIN) as anon:
        r = anon.get("/api/auth/oidc/callback", follow_redirects=False)
        assert r.status_code == 403 and "deactivated" in r.text and not anon.cookies.get("vault_session")
    # 3) the listed owner (by e-mail, and by sub) gets the owner session, as before
    for owners, w in (("boss@example.com", {"email": "boss@example.com", "sub": "x"}), ("sub:idp-boss", {"email": "other@example.com", "sub": "idp-boss"})):
        monkeypatch.setenv("VAULT_OIDC_OWNERS", owners)
        who.clear(); who.update(name="B", **w)
        with TestClient(main.app, base_url=ORIGIN) as anon:
            r = anon.get("/api/auth/oidc/callback", follow_redirects=False)
            assert r.status_code == 302 and anon.cookies.get("vault_session"), (owners, r.text)
            assert anon.get("/api/me").json()["kind"] == "owner"
    acts = [a["action"] for a in client.get("/api/audit", params={"limit": 80}, headers=hdr).json()]
    assert "oidc:not_allowed" in acts and "oidc:user_inactive" in acts


def test_a_users_security_key_is_not_the_owners_second_factor(client, world):
    world["hdr"] = unlock(client)
    """Finding A2 (High): the owner's WebAuthn second factor accepted an assertion from ANY registered key —
    a named user's own key included. An insider who learned the master password bypassed the second factor."""
    import main
    hdr, fid = world["hdr"], world["fid"]
    _user(client, hdr, "insider@example.com", fid)
    c, r = _login("insider@example.com"); uh = {"X-CSRF-Token": r.json()["csrf_token"]}
    ukey = SoftKey(prf=False)
    opts = c.post("/api/auth/webauthn/register/options", json={"name": "insider key"}, headers=uh).json()
    assert c.post("/api/auth/webauthn/register/finish", json={"name": "insider key", "credential": ukey.register(opts), "master_password": PW}, headers=uh).status_code == 200
    # the owner turns on the second factor with their own key
    okey = SoftKey(prf=False)
    opts = client.post("/api/auth/webauthn/register/options", json={"name": "owner key"}, headers=hdr).json()
    assert client.post("/api/auth/webauthn/register/finish", json={"name": "owner key", "credential": okey.register(opts), "master_password": MASTER}, headers=hdr).status_code == 200
    assert client.post("/api/auth/webauthn/second-factor", json={"enabled": True}, headers=hdr).json()["second_factor"] is True
    try:
        with TestClient(main.app, base_url=ORIGIN) as anon:
            netutil.clear_fails("testclient")
            # the insider asks for a challenge naming themselves and signs it with their own key
            o = anon.post("/api/auth/webauthn/options", params={"purpose": "second_factor", "email": "insider@example.com"}).json()
            r = anon.post("/api/auth/unlock", json={"master_password": MASTER, "webauthn": ukey.assertion(o)})
            assert r.status_code == 401 and not anon.cookies.get("vault_session"), r.text
            # the owner's own key still works
            netutil.clear_fails("testclient")
            o = anon.post("/api/auth/webauthn/options", params={"purpose": "second_factor"}).json()
            assert anon.post("/api/auth/unlock", json={"master_password": MASTER, "webauthn": okey.assertion(o)}).status_code == 200
    finally:
        netutil.clear_fails("testclient")
        hdr = unlock_with_key(client, okey)
        assert client.post("/api/auth/webauthn/second-factor", json={"enabled": False, "password": MASTER}, headers=hdr).status_code == 200
        for cr in client.get("/api/auth/webauthn/credentials").json()["credentials"]:
            client.delete(f"/api/auth/webauthn/credentials/{cr['id']}", headers=hdr)


def unlock_with_key(client, key):
    o = client.post("/api/auth/webauthn/options", params={"purpose": "second_factor"}).json()
    r = client.post("/api/auth/unlock", json={"master_password": MASTER, "webauthn": key.assertion(o)})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


# ─── the rest of the 05.10.2026 findings ─────────────────────────────────────

def test_canary_answers_generically_even_with_a_policy_and_with_the_watch_off(client, world, monkeypatch):
    """B5: a canary with allowed_cidrs answered 403 'access policy' (= 'this token is real') before tripping; with
    VAULT_WATCH=0 it was a working token. Now: generic 401 in both cases, and the use is audited."""
    hdr, fid = unlock(client), world["fid"]
    tok = client.post("/api/tokens", json={"name": "canary-policy", "folder_id": fid, "canary": True, "allowed_cidrs": "10.9.9.0/24"}, headers=hdr).json()["raw_token"]
    r = client.get("/api/v1/m/secret/review-secret", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401 and r.json()["detail"] == "invalid service token", r.text
    monkeypatch.setattr(settings.SETTINGS, "watch_enabled", False)
    tok2 = client.post("/api/tokens", json={"name": "canary-nowatch", "folder_id": fid, "canary": True}, headers=hdr).json()["raw_token"]
    r = client.get("/api/v1/m/secret/review-secret", headers={"Authorization": f"Bearer {tok2}"})
    assert r.status_code == 401 and "crown-jewels" not in r.text, "with the watch off a canary used to read secrets"


def test_flags_cannot_be_lifted_by_a_writer_and_managers_cannot_issue_machine_access_to_flagged_folders(client, world):
    """A6/B2/C1/C3: a writer PATCHed require_approval / machine_only off and read the value; a manager issued a token or
    an enrolment code for the folder and read flagged values through the machine API; an http rotation sent a flagged
    value out. Now each is refused for non-owners, and the owner needs the master password to lift a flag."""
    hdr, fid = unlock(client), world["fid"]
    flagged = client.post("/api/folders", json={"name": "review-flagged"}, headers=hdr).json()["id"]
    sid = client.post("/api/secrets", json={"folder_id": flagged, "name": "two-person", "value": "needs-two", "require_approval": True}, headers=hdr).json()["id"]
    mid = client.post("/api/secrets", json={"folder_id": flagged, "name": "machines", "value": "robots-only", "machine_only": True}, headers=hdr).json()["id"]
    _user(client, hdr, "writer-0510@example.com", flagged, role="writer")
    _user(client, hdr, "manager-0510@example.com", flagged, role="manager")
    w, r = _login("writer-0510@example.com"); wh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert w.patch(f"/api/secrets/{sid}", json={"require_approval": False}, headers=wh).status_code == 403
    assert w.patch(f"/api/secrets/{mid}", json={"machine_only": False}, headers=wh).status_code == 403
    assert "needs-two" not in w.get(f"/api/secrets/{sid}").text and "robots-only" not in w.get(f"/api/secrets/{mid}").text
    m, r = _login("manager-0510@example.com"); mh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert m.post("/api/tokens", json={"name": "mgr-backdoor", "folder_id": flagged}, headers=mh).status_code == 403
    assert m.post("/api/enrollments", json={"folder_id": flagged, "name_prefix": "x"}, headers=mh).status_code == 403
    rr = m.put(f"/api/secrets/{mid}/rotation", json={"target": "http", "config": {"url": "https://example.com/hook"}}, headers=mh)
    assert rr.status_code == 403, rr.text
    # the owner: master password needed to lift; with it, the flag goes and the change is audited as such
    netutil.clear_fails("testclient")
    hdr = world["hdr"] = unlock(client)
    assert client.patch(f"/api/secrets/{sid}", json={"require_approval": False, "master_password": "nope nope nope"}, headers=hdr).status_code == 401
    netutil.clear_fails("testclient")
    assert client.patch(f"/api/secrets/{sid}", json={"require_approval": False, "master_password": MASTER}, headers=hdr).status_code == 200
    acts = [a["action"] for a in client.get("/api/audit", params={"limit": 40}, headers=hdr).json()]
    assert "secret:approval_off" in acts and "secret:flag_clear_fail" in acts


def test_share_link_stops_when_the_secret_becomes_flagged_and_spent_links_keep_no_key(client, world):
    """B6/C7/C5: a link made before the secret was flagged kept serving the value; spent/revoked links kept a copy of the
    whole folder key in the database."""
    import db
    hdr, fid = world["hdr"] = unlock(client), world["fid"]
    sid = client.post("/api/secrets", json={"folder_id": fid, "name": "later-flagged", "value": "was-shareable"}, headers=hdr).json()["id"]
    link = client.post("/api/share", json={"secret_id": sid, "max_uses": 5, "ttl_minutes": 60}, headers=hdr).json()
    token = link["url"].rsplit("/", 1)[-1]
    assert client.patch(f"/api/secrets/{sid}", json={"machine_only": True}, headers=hdr).status_code == 200
    r = client.get(f"/api/share/{token}")
    assert r.status_code == 410 and "was-shareable" not in r.text
    with db.get_session() as s:
        assert s.query(db.ShareLink).filter_by(id=link["id"]).one().folder_key_enc == b""
    # a one-use link: after its use the key copy is gone
    sid2 = client.post("/api/secrets", json={"folder_id": fid, "name": "one-use", "value": "once"}, headers=hdr).json()["id"]
    l2 = client.post("/api/share", json={"secret_id": sid2, "max_uses": 1, "ttl_minutes": 60}, headers=hdr).json()
    assert client.get(f"/api/share/{l2['url'].rsplit('/', 1)[-1]}").json()["value"] == "once"
    with db.get_session() as s:
        assert s.query(db.ShareLink).filter_by(id=l2["id"]).one().folder_key_enc == b""


def test_in_session_secret_checks_are_rate_limited_and_password_change_closes_other_sessions(client, world):
    """A3/A4: TOTP-disable / password-change inside a session had no lockout (a stolen session could guess 6 digits);
    a user's password change left their other (possibly stolen) sessions alive."""
    hdr, fid = world["hdr"] = unlock(client), world["fid"]
    _user(client, hdr, "pwchange@example.com", fid)
    a, r = _login("pwchange@example.com"); ah = {"X-CSRF-Token": r.json()["csrf_token"]}
    b, r = _login("pwchange@example.com"); bh = {"X-CSRF-Token": r.json()["csrf_token"]}     # the "stolen" session
    for _ in range(5):
        assert b.post("/api/me/password", json={"current_password": "guess guess guess", "new_password": "whatever whatever 1"}, headers=bh).status_code == 400
    assert b.post("/api/me/password", json={"current_password": PW, "new_password": "new review password 2026!"}, headers=bh).status_code == 429
    netutil.clear_fails("testclient")
    r = a.post("/api/me/password", json={"current_password": PW, "new_password": "new review password 2026!"}, headers=ah)
    assert r.status_code == 200 and r.json()["other_sessions_closed"] >= 1, r.text
    assert b.get("/api/me").status_code == 401, "the other session is closed"
    assert a.get("/api/me").status_code == 200, "the session that changed the password stays"


def test_totp_code_is_accepted_once(client, world):
    """A9: an intercepted TOTP code was reusable within its ~90 s window."""
    import main
    import pyotp
    hdr = world["hdr"] = unlock(client)
    assert main._totp_accept("test:replay", "JBSWY3DPEHPK3PXP", pyotp.TOTP("JBSWY3DPEHPK3PXP").now()) is True
    assert main._totp_accept("test:replay", "JBSWY3DPEHPK3PXP", pyotp.TOTP("JBSWY3DPEHPK3PXP").now()) is False
    assert main._totp_accept("test:other", "JBSWY3DPEHPK3PXP", "12345x") is False


def test_managers_cannot_appoint_or_demote_managers(client, world):
    """A12: peer managers could demote or remove each other (or make new managers)."""
    hdr, fid = world["hdr"] = unlock(client), world["fid"]
    m1 = _user(client, hdr, "m1-0510@example.com", fid, role="manager")
    m2 = _user(client, hdr, "m2-0510@example.com", fid, role="manager")
    rd = _user(client, hdr, "rd-0510@example.com", fid)
    c, r = _login("m1-0510@example.com"); h = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert c.put(f"/api/users/{m2}/grants", json={"folder_id": fid, "role": "reader"}, headers=h).status_code == 403
    assert c.delete(f"/api/users/{m2}/grants/{fid}", headers=h).status_code == 403
    assert c.put(f"/api/users/{rd}/grants", json={"folder_id": fid, "role": "manager"}, headers=h).status_code == 403
    assert c.put(f"/api/users/{rd}/grants", json={"folder_id": fid, "role": "writer"}, headers=h).status_code == 200


def test_ui_and_api_headers_outbound_without_redirects_and_100_64(client, world):
    """D8/B4/C6: API answers carry no-store; outbound calls refuse redirects; 100.64/10 and IPv4-mapped loopback are
    not 'public' for the SSRF guard."""
    import netutil as n
    r = client.get("/api/health")
    assert r.headers.get("cache-control") == "no-store"
    assert n.address_is_public("100.64.0.1") is False and n.address_is_public("::ffff:127.0.0.1") is False
    assert n.address_is_public("169.254.169.254") is False and n.address_is_public("10.1.2.3") is False
    import http.server
    import threading
    import urllib.error
    import urllib.request

    class R(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302); self.send_header("Location", "http://169.254.169.254/latest/meta-data/"); self.end_headers()
        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError, match="redirect .* refused"):
            n.urlopen_noredirect(urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/", data=b"{}", method="POST"), timeout=5)
    finally:
        srv.shutdown()


def test_rotation_through_an_admin_credential_is_owner_only_and_the_account_is_bound(client, world):
    """C2: a manager could point a postgres/ldap/ssh rotation at any account (postgres, cn=admin, root) through the
    administrator DSN; a writer could retarget it later by changing the secret's login. Now admin-credential rotations
    are configured by the owner, and the account is frozen into the configuration."""
    import crypto
    import db
    import rotation as rot
    hdr, fid = world["hdr"] = unlock(client), world["fid"]
    dsn = client.post("/api/secrets", json={"folder_id": fid, "name": "pg-admin-dsn", "value": "postgresql://postgres:x@db:5432/app", "machine_only": True}, headers=hdr).json()["id"]
    app_sid = client.post("/api/secrets", json={"folder_id": fid, "name": "app-db-pw", "value": "v1", "login": "app_user"}, headers=hdr).json()["id"]
    _user(client, hdr, "rot-mgr-0510@example.com", fid, role="manager")
    m, r = _login("rot-mgr-0510@example.com"); mh = {"X-CSRF-Token": r.json()["csrf_token"]}
    assert m.put(f"/api/secrets/{app_sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": dsn, "role": "postgres"}}, headers=mh).status_code == 403
    hdr = world["hdr"] = unlock(client)
    r = client.put(f"/api/secrets/{app_sid}/rotation", json={"target": "postgres", "config": {"dsn_secret_id": dsn}}, headers=hdr)
    assert r.status_code == 200, r.text
    assert client.get(f"/api/secrets/{app_sid}/rotation", headers=hdr).json()["config"]["role"] == "app_user", "the login is bound at setup"
    # changing the login afterwards does not retarget the rotation
    assert client.patch(f"/api/secrets/{app_sid}", json={"login": "postgres"}, headers=hdr).status_code == 200
    assert client.get(f"/api/secrets/{app_sid}/rotation", headers=hdr).json()["config"]["role"] == "app_user"


def test_deactivating_a_person_revokes_the_machine_access_they_issued(client, world):
    """A9: a manager issued a service token and an enrollment code, then was deactivated — both kept working, so
    the person's access outlived them through the machines. Now deactivation revokes what they issued; tokens the
    owner issued on the same folder stay alive."""
    hdr = world["hdr"] = unlock(client)
    fid = client.post("/api/folders", json={"name": "review-0510-deact"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "deact-secret", "value": "still-mine"}, headers=hdr)
    uid = _user(client, hdr, "leaver-0510@example.com", fid, role="manager")
    c, r = _login("leaver-0510@example.com"); h = {"X-CSRF-Token": r.json()["csrf_token"]}
    t = c.post("/api/tokens", json={"name": "leaver-token-0510", "folder_id": fid}, headers=h)
    assert t.status_code == 200, t.text
    tok = t.json()["raw_token"]
    e = c.post("/api/enrollments", json={"folder_id": fid, "name_prefix": "leaver"}, headers=h)
    assert e.status_code == 200, e.text
    own = client.post("/api/tokens", json={"name": "owner-token-0510", "folder_id": fid}, headers=hdr).json()["raw_token"]
    read = lambda raw: client.get("/api/v1/m/secret/deact-secret", headers={"Authorization": f"Bearer {raw}"})
    assert read(tok).status_code == 200, "precondition: the manager's token works"
    assert client.delete(f"/api/users/{uid}", headers=hdr).status_code == 200
    assert read(tok).status_code == 401, "the leaver's token must die with the account"
    assert read(own).status_code == 200 and read(own).json()["value"] == "still-mine", "the owner's token is not touched"
    import db
    with db.get_session() as s:
        en = s.query(db.Enrollment).filter_by(created_by="leaver-0510@example.com").one()
        assert en.revoked and en.folder_key_enc == b"", "the enrollment is revoked and keeps no folder key"


def test_webhooks_and_the_approver_notification_need_https_to_public_hosts(client, world, monkeypatch):
    """Found by ops/checks/dast.py: a webhook to http://<public host> was accepted, so event metadata crossed the
    internet in clear text (rotation receivers already required https). Plain http stays allowed only together with
    VAULT_WEBHOOK_ALLOW_PRIVATE=1 (an internal receiver) or in dev."""
    import main
    hdr = world["hdr"] = unlock(client)
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", False)
    monkeypatch.setattr(settings.SETTINGS, "dev", False)
    import api_sharing
    import webhooks
    for m in (webhooks, api_sharing):        # 0.41.7: the callers live in these modules since main.py was split
        monkeypatch.setattr(m, "_webhook_target_allowed", lambda url: True)        # no DNS in the test: every host counts as public
    r = client.post("/api/webhooks", json={"name": "plain-0510", "url": "http://hooks.example.com/in"}, headers=hdr)
    assert r.status_code == 422 and "https" in r.text, r.text
    r = client.post("/api/webhooks", json={"name": "tls-0510", "url": "https://hooks.example.com/in"}, headers=hdr)
    assert r.status_code == 200, r.text
    monkeypatch.setattr(settings.SETTINGS, "approval_notify_url", "http://hooks.example.com/approve")
    sent = []
    monkeypatch.setattr(netutil, "urlopen_noredirect", lambda req, timeout=8: sent.append(req.full_url), raising=False)
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda req, timeout=8: sent.append(req.full_url))
    assert main._notify_approver("t", "https://vault/approve/x", "s", "r", "1.2.3.4") is False and sent == [], "no clear-text approver link"
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", True)                 # an internal receiver: http allowed
    r = client.post("/api/webhooks", json={"name": "internal-0510", "url": "http://hooks.internal/in"}, headers=hdr)
    assert r.status_code == 200, r.text
    for w in client.get("/api/webhooks", headers=hdr).json():          # these receivers do not exist: do not slow later tests
        if w["name"].endswith("-0510"):
            client.delete(f"/api/webhooks/{w['id']}", headers=hdr)
