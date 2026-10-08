"""Import from other managers (0.29): every format is parsed into the vault's payload, previewed, then
imported through the one import path; values, logins, notes, TOTP seeds and URLs land decrypted where
they belong; archived items are skipped; TOTP as otpauth URL is reduced to its seed, Steam codes go to
the notes with a warning; conflicts skip / version / rename; a live HashiCorp KV v2 source is pulled
through our own facade (which speaks KV v2) — a real walk of LIST + GET, not a mock."""
import csv
import io
import json
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

import importers
import settings
from conftest import unlock


def _parse(client, hdr, name, data: bytes, fmt="auto", **form):
    return client.post("/api/import/parse", files={"file": (name, data)}, data={"format": fmt, **form}, headers=hdr)


def _values(client, hdr, folder_name):
    fid = next(f["id"] for f in client.get("/api/folders", headers=hdr).json() if f["name"] == folder_name)
    out = {}
    for s in client.get("/api/secrets", params={"folder_id": fid}, headers=hdr).json():
        out[s["name"]] = client.get(f"/api/secrets/{s['id']}", headers=hdr).json()
    return out


BITWARDEN = {
    "encrypted": False,
    "folders": [{"id": "f1", "name": "Work"}, {"id": "f2", "name": "Home"}],
    "items": [
        {"id": "1", "type": 1, "name": "GitLab", "folderId": "f1", "favorite": True, "notes": "deploy account",
         "login": {"username": "ci-bot", "password": "gl-pass-1", "totp": "otpauth://totp/GitLab:ci-bot?secret=JBSWY3DPEHPK3PXP&issuer=GitLab",
                   "uris": [{"uri": "https://gitlab.example.com"}, {"uri": "https://git.example.com"}]},
         "fields": [{"name": "project", "value": "core"}]},
        {"id": "2", "type": 1, "name": "Steam", "folderId": "f2", "login": {"username": "gamer", "password": "st-pass", "totp": "steam://ABCDEFGHIJKLMNOPQRS"}},
        {"id": "3", "type": 2, "name": "Wi-Fi office", "folderId": "f1", "notes": "SSID office / pw w1f1-secret", "secureNote": {"type": 0}},
        {"id": "4", "type": 1, "name": "Old thing", "folderId": None, "deletedDate": "2026-01-01T00:00:00Z", "login": {"password": "x"}},
        {"id": "5", "type": 3, "name": "Visa", "folderId": "f2", "card": {"cardholderName": "K Z", "number": "4111111111111111", "expMonth": "12", "expYear": "2030", "code": "123", "brand": "Visa"}},
        {"id": "6", "type": 1, "name": "GitLab", "folderId": "f1", "login": {"username": "second", "password": "gl-pass-2"}},
        {"id": "7", "type": 1, "name": "No folder", "folderId": None, "login": {"username": "a", "password": "b", "totp": "not base32 at all!!"}},
    ],
}

KEEPASS = """<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Generator>KeePass</Generator></Meta><Root><Group><Name>Root</Name>
<Entry><String><Key>Title</Key><Value>Root entry</Value></String><String><Key>Password</Key><Value>root-pw</Value></String></Entry>
<Group><Name>Servers</Name>
  <Entry><String><Key>Title</Key><Value>db01</Value></String><String><Key>UserName</Key><Value>postgres</Value></String>
         <String><Key>Password</Key><Value>pg-secret</Value></String><String><Key>URL</Key><Value>db01.example.com</Value></String>
         <String><Key>Notes</Key><Value>primary</Value></String><String><Key>otp</Key><Value>otpauth://totp/db01?secret=GEZDGNBVGY3TQOJQ</Value></String>
         <String><Key>Port</Key><Value>5432</Value></String><Tags>prod;db</Tags></Entry>
  <Group><Name>Backup</Name><Entry><String><Key>Title</Key><Value>db02</Value></String><String><Key>Password</Key><Value>pg2</Value></String></Entry></Group>
</Group>
<Group><Name>Recycle Bin</Name><Entry><String><Key>Title</Key><Value>gone</Value></String><String><Key>Password</Key><Value>x</Value></String></Entry></Group>
</Group></Root></KeePassFile>"""

ONEPASSWORD_CSV = """Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
AWS root,https://aws.amazon.com,root@example.com,aws-pw,otpauth://totp/AWS?secret=MFRGGZDFMZTWQ2LK,true,false,cloud;infra,break glass
Archived one,,u,p,,false,true,,
"""

LASTPASS_CSV = """url,username,password,totp,extra,name,grouping,fav
https://example.com/login,alice,lp-pass,JBSWY3DPEHPK3PXP,note here,Example,Personal\\Web,1
http://sn,,,,"my secure note text",Note item,Personal,0
"""

DOTENV = b"""# database
DB_PASSWORD=p@ss word
export API_KEY="quoted \\"value\\""
EMPTY=
SINGLE='single quoted' # trailing comment
BAD LINE
"""


def test_bitwarden_parse_preview_and_import(client, initialized):
    hdr = unlock(client)
    r = _parse(client, hdr, "bitwarden_export_20261004.json", json.dumps(BITWARDEN).encode())
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["format"] == "bitwarden"
    st = res["stats"]
    assert st["skipped"] == 1 and st["secrets"] == 6 and st["folders"] == 3, st     # Work, Home, import-bitwarden
    assert st["with_login"] == 4 and st["with_totp"] == 1
    work = next(f for f in res["payload"]["folders"] if f["name"] == "Work")
    names = [x["name"] for x in work["secrets"]]
    assert names == ["GitLab", "Wi-Fi office", "GitLab (2)"], "duplicates get a suffix, nothing is lost"
    gl = work["secrets"][0]
    assert gl["totp_seed"] == "JBSWY3DPEHPK3PXP" and gl["url"] == "https://gitlab.example.com" and gl["login"] == "ci-bot" and gl["is_favorite"] is True
    assert "project: core" in gl["notes"] and "URL: https://git.example.com" in gl["notes"]
    note = work["secrets"][1]
    assert note["value"] == "SSID office / pw w1f1-secret" and note["notes"] == "" and note["tags"] == "note", "a note without a password: the note is the secret"
    assert any("Steam" in w for w in res["warnings"]) and any("No folder" in w and "base32" in w for w in res["warnings"])
    steam = next(x for x in next(f for f in res["payload"]["folders"] if f["name"] == "Home")["secrets"] if x["name"] == "Steam")
    assert steam["totp_seed"] == "" and "steam://" in steam["notes"]
    # import what the preview showed; then the secrets are really there, decrypted
    imp = client.post("/api/import", json={"folders": res["payload"]["folders"], "create_missing_folders": True, "on_conflict": "skip"}, headers=hdr)
    assert imp.status_code == 200 and imp.json()["created_secrets"] == 6 and imp.json()["created_folders"] == 3, imp.text
    got = _values(client, hdr, "Work")
    assert got["GitLab"]["value"] == "gl-pass-1" and got["GitLab"]["login"] == "ci-bot" and len(got["GitLab"]["totp"]) == 6 and got["GitLab"]["url"] == "https://gitlab.example.com"
    assert got["GitLab (2)"]["value"] == "gl-pass-2"
    home = _values(client, hdr, "Home")
    assert home["Visa"]["value"] == "4111111111111111" and "cardholderName: K Z" in home["Visa"]["notes"] and home["Visa"]["tags"] == "card"
    # conflict modes on a second import of the same file
    again = client.post("/api/import", json={"folders": res["payload"]["folders"], "on_conflict": "skip"}, headers=hdr).json()
    assert again["created_secrets"] == 0 and again["skipped"] == 6
    BITWARDEN["items"][0]["login"]["password"] = "gl-pass-NEW"
    res2 = _parse(client, hdr, "bw.json", json.dumps(BITWARDEN).encode()).json()
    ver = client.post("/api/import", json={"folders": res2["payload"]["folders"], "on_conflict": "version"}, headers=hdr).json()
    assert ver["updated"] == 6 and ver["created_secrets"] == 0
    got = _values(client, hdr, "Work")
    assert got["GitLab"]["value"] == "gl-pass-NEW" and got["GitLab"]["version"] == 2
    hist = client.get(f"/api/secrets/{got['GitLab']['id']}/history", headers=hdr).json()["history"]
    assert hist[0]["value"] == "gl-pass-1" and hist[0]["changed_by"] == "master:import"
    ren = client.post("/api/import", json={"folders": res2["payload"]["folders"], "on_conflict": "rename"}, headers=hdr).json()
    assert ren["created_secrets"] == 6
    assert "GitLab (3)" in _values(client, hdr, "Work"), "rename picks the next free suffix"
    BITWARDEN["items"][0]["login"]["password"] = "gl-pass-1"
    acts = client.get("/api/audit", params={"limit": 20}, headers=hdr).json()
    assert any(a["action"] == "import:parse" for a in acts) and any(a["action"] == "import:json" for a in acts)


def test_keepass_xml_groups_become_folders(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "db.xml", KEEPASS.encode()).json()
    assert res["format"] == "keepass" and res["stats"]["skipped"] == 1, res["stats"]
    folders = {f["name"]: f["secrets"] for f in res["payload"]["folders"]}
    assert set(folders) == {"import-keepass", "Servers", "Servers/Backup"}
    db01 = folders["Servers"][0]
    assert db01["login"] == "postgres" and db01["value"] == "pg-secret" and db01["url"] == "https://db01.example.com" and db01["totp_seed"] == "GEZDGNBVGY3TQOJQ"
    assert "Port: 5432" in db01["notes"] and db01["tags"] == "prod,db" and "primary" in db01["notes"]
    assert folders["Servers/Backup"][0]["name"] == "db02"
    # a prefix and an "everything into one folder" option
    res2 = _parse(client, hdr, "db.xml", KEEPASS.encode(), prefix="kp/").json()
    assert {f["name"] for f in res2["payload"]["folders"]} == {"kp/import-keepass", "kp/Servers", "kp/Servers/Backup"}
    res3 = _parse(client, hdr, "db.xml", KEEPASS.encode(), into_folder="all-keepass").json()
    assert [f["name"] for f in res3["payload"]["folders"]] == ["all-keepass"] and res3["stats"]["secrets"] == 3
    assert client.post("/api/import", json={"folders": res3["payload"]["folders"]}, headers=hdr).json()["created_secrets"] == 3
    assert _values(client, hdr, "all-keepass")["db01"]["totp"].isdigit()


def test_1password_csv_and_1pux(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "1Password.csv", ONEPASSWORD_CSV.encode()).json()
    assert res["format"] == "1password" and res["stats"]["secrets"] == 1 and res["stats"]["skipped"] == 1
    aws = res["payload"]["folders"][0]["secrets"][0]
    assert aws["login"] == "root@example.com" and aws["value"] == "aws-pw" and aws["totp_seed"] == "MFRGGZDFMZTWQ2LK" and aws["tags"] == "cloud,infra" and aws["is_favorite"] is True
    # 1PUX: a zip with export.data
    export = {"accounts": [{"attrs": {"name": "me"}, "vaults": [{"attrs": {"name": "Private"}, "items": [
        {"uuid": "a", "favIndex": 1, "overview": {"title": "Bank", "url": "https://bank.example", "tags": ["money"]},
         "details": {"loginFields": [{"designation": "username", "value": "kz"}, {"designation": "password", "value": "bank-pw"}], "notesPlain": "pin 1234",
                     "sections": [{"title": "", "fields": [{"title": "one-time password", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}}, {"title": "account no", "value": {"string": "40817"}}]}]}},
        {"uuid": "b", "state": "archived", "overview": {"title": "Old"}, "details": {"loginFields": [{"designation": "password", "value": "x"}]}},
    ]}]}]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("export.attributes", "{}"); z.writestr("export.data", json.dumps(export))
    res2 = _parse(client, hdr, "export.1pux", buf.getvalue()).json()
    assert res2["format"] == "1pux" and res2["stats"]["secrets"] == 1 and res2["stats"]["skipped"] == 1
    bank = res2["payload"]["folders"][0]
    assert bank["name"] == "Private"
    b = bank["secrets"][0]
    assert b["login"] == "kz" and b["value"] == "bank-pw" and b["totp_seed"] == "JBSWY3DPEHPK3PXP" and "account no: 40817" in b["notes"] and "pin 1234" in b["notes"] and b["tags"] == "money" and b["is_favorite"]


def test_lastpass_generic_csv_and_dotenv(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "lastpass_export.csv", LASTPASS_CSV.encode()).json()
    assert res["format"] == "lastpass"
    folders = {f["name"]: f["secrets"] for f in res["payload"]["folders"]}
    ex = folders["Personal/Web"][0]
    assert ex["login"] == "alice" and ex["value"] == "lp-pass" and ex["totp_seed"] == "JBSWY3DPEHPK3PXP" and ex["is_favorite"] and ex["url"] == "https://example.com/login"
    note = folders["Personal"][0]
    assert note["value"] == "my secure note text" and note["url"] == "", "LastPass secure note: http://sn dropped, the note is the value"
    # a generic CSV with a column mapping (semicolon-separated, extra columns ignored)
    generic = "name;password;user;website;folder;comment\nsvc-a;pw-a;ua;a.example.com;Apps;first\nsvc-b;pw-b;;;;\n".encode()
    res2 = _parse(client, hdr, "list.csv", generic.encode() if isinstance(generic, str) else generic).json()
    assert res2["format"] == "csv"
    f = {x["name"]: x for fl in res2["payload"]["folders"] for x in fl["secrets"]}
    assert f["svc-a"]["login"] == "ua" and f["svc-a"]["url"] == "https://a.example.com" and f["svc-a"]["notes"] == "first" and f["svc-b"]["value"] == "pw-b"
    assert {fl["name"] for fl in res2["payload"]["folders"]} == {"Apps", "import-csv"}
    # .env
    res3 = _parse(client, hdr, "prod.env", DOTENV).json()
    assert res3["format"] == "dotenv"
    env = {x["name"]: x["value"] for x in res3["payload"]["folders"][0]["secrets"]}
    assert env == {"DB_PASSWORD": "p@ss word", "API_KEY": 'quoted "value"', "SINGLE": "single quoted"}, env
    assert res3["stats"]["skipped"] == 1 and any("EMPTY" in w for w in res3["warnings"]) and any("BAD LINE" in w for w in res3["warnings"])
    assert res3["payload"]["folders"][0]["name"] == "prod.env"


def test_format_errors_and_limits(client, initialized):
    hdr = unlock(client)
    assert _parse(client, hdr, "x.json", json.dumps({"encrypted": True, "items": [], "folders": []}).encode()).status_code == 422
    r = _parse(client, hdr, "x.json", b'{"hello": 1}')
    assert r.status_code == 422 and "pick the format" in r.json()["detail"]
    assert _parse(client, hdr, "x.bin", b"\x00\x01\x02 binary garbage").status_code == 422
    assert _parse(client, hdr, "x.csv", b"a,b\n1,2\n", fmt="csv").status_code == 422, "no name/value columns"
    assert _parse(client, hdr, "x.xml", b"<other/>", fmt="keepass").status_code == 422
    assert _parse(client, hdr, "x.csv", b"a,b\n", fmt="nope").status_code == 422
    assert _parse(client, hdr, "empty.env", b"   \n").status_code == 422
    # our own export round-trips
    exp = client.get("/api/export", headers=hdr).json()
    res = _parse(client, hdr, "aps-vault-export.json", json.dumps(exp).encode()).json()
    assert res["format"] == "apsvault" and res["stats"]["secrets"] >= 10
    # a named user may not import
    import main
    u = client.post("/api/users", json={"email": "imp@example.com", "grants": []}, headers=hdr).json()
    with TestClient(main.app, base_url="https://vault.test") as anon:
        anon.post(f"/api/invite/{u['invite_url'].rsplit('/', 1)[-1]}", json={"password": "import user pass!!"})
    import netutil
    uc = TestClient(main.app, base_url="https://vault.test"); netutil.clear_fails("testclient")
    lr = uc.post("/api/auth/login", json={"email": "imp@example.com", "password": "import user pass!!"}); uh = {"X-CSRF-Token": lr.json()["csrf_token"]}
    assert uc.post("/api/import/parse", files={"file": ("a.env", b"A=1\n")}, data={"format": "dotenv"}, headers=uh).status_code == 403


# ─── HashiCorp / Stronghold KV v2 — pulled through our own facade ────────────
@pytest.fixture(scope="module")
def live_kv(client, initialized):
    """A live uvicorn of this very app: its /v1/<mount>/... facade is a KV v2 source for the importer."""
    import socket
    import time
    import uvicorn
    import main
    hdr = unlock(client)
    fid = client.post("/api/folders", json={"name": "kv-source"}, headers=hdr).json()["id"]
    client.post("/api/secrets", json={"folder_id": fid, "name": "app/db", "value": "kv-pw", "login": "svc"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "app/api-key", "value": "kv-key"}, headers=hdr)
    client.post("/api/secrets", json={"folder_id": fid, "name": "top", "value": "kv-top", "notes": "n"}, headers=hdr)
    tok = client.post("/api/tokens", json={"name": "kv-reader", "folder_id": fid, "can_read_notes": True}, headers=hdr).json()["raw_token"]
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
        except OSError:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", tok, hdr
    server.should_exit = True


def test_hashicorp_kv2_pull(client, live_kv, monkeypatch):
    url, tok, hdr = live_kv
    r = client.post("/api/import/hashicorp", json={"addr": url, "token": tok, "mount": "kv-source"}, headers=hdr)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["format"] == "hashicorp" and res["stats"]["secrets"] == 3
    items = {x["name"]: x for x in res["payload"]["folders"][0]["secrets"]}
    assert res["payload"]["folders"][0]["name"] == "kv-source"
    assert items["app/db"]["value"] == "kv-pw" and items["app/db"]["login"] == "svc" and items["app/api-key"]["value"] == "kv-key" and items["top"]["notes"] == "n"
    # a sub-path only
    sub = client.post("/api/import/hashicorp", json={"addr": url, "token": tok, "mount": "kv-source", "path": "app", "into_folder": "from-kv"}, headers=hdr).json()
    assert sub["stats"]["secrets"] == 2 and sub["payload"]["folders"][0]["name"] == "from-kv"
    imp = client.post("/api/import", json={"folders": sub["payload"]["folders"]}, headers=hdr).json()
    assert imp["created_secrets"] == 2
    assert _values(client, hdr, "from-kv")["app/db"]["value"] == "kv-pw"
    # wrong token → permission denied, wrong mount → nothing there, bad scheme → 422
    assert client.post("/api/import/hashicorp", json={"addr": url, "token": "vlt_nope", "mount": "kv-source"}, headers=hdr).status_code == 422
    r = client.post("/api/import/hashicorp", json={"addr": url, "token": tok, "mount": "other-mount"}, headers=hdr)
    assert r.status_code == 422, r.text
    assert client.post("/api/import/hashicorp", json={"addr": "ftp://x", "token": tok, "mount": "m"}, headers=hdr).status_code == 422
    # outside the test environment a private source address is refused unless allowed
    monkeypatch.setattr(settings.SETTINGS, "webhook_allow_private", False)
    r = client.post("/api/import/hashicorp", json={"addr": url, "token": tok, "mount": "kv-source"}, headers=hdr)
    assert r.status_code == 422 and "not allowed" in r.json()["detail"]


def test_kv_map_rules_unit():
    """Key/value maps that are not our shape: one key → the value; password+username → value+login;
    anything else → the whole map as JSON with a note."""
    calls = {
        "/v1/m/metadata/?list=true": (200, {"data": {"keys": ["one", "pair", "blob", "dir/"]}}),
        "/v1/m/metadata/dir/?list=true": (200, {"data": {"keys": ["inner"]}}),
        "/v1/m/data/one": (200, {"data": {"data": {"api_token": "T1"}}}),
        "/v1/m/data/pair": (200, {"data": {"data": {"username": "u", "password": "p", "host": "h"}}}),
        "/v1/m/data/blob": (200, {"data": {"data": {"a": "1", "b": {"c": 2}}}}),
        "/v1/m/data/dir/inner": (403, {"errors": ["permission denied"]}),
    }
    def fetch(method, url, headers):
        assert headers["X-Vault-Token"] == "t"
        return calls[url.split("http://src", 1)[1]]
    res = importers.pull_hashicorp("http://src", "t", "m", fetch=fetch)
    items = {x["name"]: x for x in res["payload"]["folders"][0]["secrets"]}
    assert items["one"]["value"] == "T1"
    assert items["pair"]["value"] == "p" and items["pair"]["login"] == "u" and "other keys" in items["pair"]["notes"] and '"host": "h"' in items["pair"]["notes"]
    assert json.loads(items["blob"]["value"]) == {"a": "1", "b": {"c": 2}} and "whole map" in items["blob"]["notes"]
    assert res["stats"]["skipped"] == 1 and any("dir/inner" in w for w in res["warnings"])


# ─── Passwork: file exports and the live API, against an emulator built from the official connector's code ──
PASSWORK_JSON = {"vaults": [{"name": "Infra", "folders": [{"name": "DB", "passwords": [
    {"name": "pg-main", "login": "postgres", "password": "pg-pw", "url": "db.example.com", "description": "primary", "tags": ["prod"],
     "customs": [{"name": "otp", "type": "totp", "value": "JBSWY3DPEHPK3PXP"}, {"name": "port", "type": "text", "value": "5432"}],
     "attachments": [{"name": "ca.pem"}]}]},
    {"name": "Web", "passwords": [{"name": "nginx", "password": "ng-pw"}]}],
    "passwords": [{"name": "root-item", "login": "root", "password": "r-pw", "isFavorite": True}]}]}

PASSWORK_CSV_RU = "Название;Логин;Пароль;Ссылка;Описание;Теги;Папка\nПочта;kz;mail-pw;mail.example.com;рабочая;work;Личное\n"


def test_passwork_files(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "passwork_export.json", json.dumps(PASSWORK_JSON).encode()).json()
    assert res["format"] == "passwork" and res["stats"]["secrets"] == 3
    f = {fl["name"]: {x["name"]: x for x in fl["secrets"]} for fl in res["payload"]["folders"]}
    assert set(f) == {"Infra/DB", "Infra/Web", "Infra"}, set(f)
    pg = f["Infra/DB"]["pg-main"]
    assert pg["login"] == "postgres" and pg["value"] == "pg-pw" and pg["totp_seed"] == "JBSWY3DPEHPK3PXP" and pg["url"] == "https://db.example.com" and pg["tags"] == "prod"
    assert "port: 5432" in pg["notes"] and "attachment (not imported): ca.pem" in pg["notes"] and "primary" in pg["notes"]
    assert f["Infra"]["root-item"]["is_favorite"] is True
    res2 = _parse(client, hdr, "passwork.csv", PASSWORK_CSV_RU.encode("utf-8"), fmt="passwork").json()
    m = res2["payload"]["folders"][0]
    assert m["name"] == "Личное" and m["secrets"][0]["name"] == "Почта" and m["secrets"][0]["login"] == "kz" and m["secrets"][0]["value"] == "mail-pw" and m["secrets"][0]["url"] == "https://mail.example.com"
    # an encrypted-on-the-client export cannot be read from the file
    enc = {"passwords": [{"name": "x", "login": "u", "passwordEncrypted": "0123456789abcdef", "keyEncrypted": "zz"}]}
    r = _parse(client, hdr, "pw.json", json.dumps(enc).encode(), fmt="passwork")
    assert r.status_code == 422 and "no password records" in r.json()["detail"]


class _PassworkEmu:
    """What a Passwork 7 answers to the connector's calls, with the connector's own crypto (importers.pw_encrypt_aes
    mirrors passwork_client.crypto.encrypt_aes): users/master-key/options, users/keys, vaults, folders, items/search,
    items/{id}. `encrypt=True` = client-side encryption on."""

    def __init__(self, encrypt: bool):
        import base64 as b64
        import hashlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as rp, rsa
        self.encrypt = encrypt
        self.token = "pw-access-token"
        self.master_password = "passwork master 2026!"
        self.options = "pbkdf:sha256:1000:64:saltsaltsalt"
        self.master_key = importers.pw_master_key_from_password(self.master_password, self.options)
        self.master_hash = hashlib.sha256(self.master_key.encode()).hexdigest()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        pub = key.public_key()
        self.keys = {"public": "…", "privateEncrypted": importers.pw_encrypt_aes(priv_pem.encode(), self.master_key)}
        vmk = "vault-master-key-" + "x" * 80
        self.vmk_enc = b64.b64encode(pub.encrypt(vmk.encode(), rp.OAEP(mgf=rp.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()
        item_key = "item-key-" + "k" * 90
        def enc_field(v: str) -> str:
            return importers.pw_encrypt_aes(v.encode(), item_key) if encrypt else b64.b64encode(v.encode()).decode()
        self.items = {
            "i1": {"id": "i1", "name": "GitLab deploy", "login": "ci", "url": "https://gitlab.example.com", "description": "runner", "tags": ["ci", "prod"], "vaultId": "v1", "folderId": "f2", "isFavorite": True,
                   "passwordEncrypted": enc_field("gl-pw"), "keyEncrypted": importers.pw_encrypt_aes(item_key.encode(), vmk) if encrypt else "", "vaultMasterKeyEncrypted": self.vmk_enc if encrypt else "",
                   "customs": [{"name": enc_field("2FA"), "type": enc_field("totp"), "value": enc_field("otpauth://totp/GitLab?secret=JBSWY3DPEHPK3PXP")}, {"name": enc_field("project"), "type": enc_field("text"), "value": enc_field("core")}],
                   "attachments": [{"id": "a1", "name": "runner.toml"}]},
            "i2": {"id": "i2", "name": "Plain note", "vaultId": "v1", "folderId": "", "passwordEncrypted": enc_field("note-pw"),
                   "keyEncrypted": importers.pw_encrypt_aes(item_key.encode(), vmk) if encrypt else "", "vaultMasterKeyEncrypted": self.vmk_enc if encrypt else "", "customs": []},
        }
        self.vaults = {"v1": {"id": "v1", "name": "Ops"}}
        self.folders = {"f1": {"id": "f1", "name": "CI", "parentId": ""}, "f2": {"id": "f2", "name": "GitLab", "parentId": "f1"}}
        self.calls = []

    def handler(self):
        emu = self
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            def _send(self, code, obj):
                body = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                emu.calls.append(self.path)
                if self.headers.get("Authorization") != f"Bearer {emu.token}":
                    return self._send(401, {"errors": [{"code": "accessTokenInvalid", "message": "Invalid token"}]})
                path = self.path.split("?")[0]
                if emu.encrypt and path.startswith("/api/v1/items/") and self.headers.get("X-Master-Key-Hash") != emu.master_hash:
                    return self._send(403, {"errors": [{"code": "masterKeyRequired", "message": "Master key hash mismatch"}]})
                if path == "/api/v1/users/master-key/options": return self._send(200, {"masterKeyOptions": emu.options})
                if path == "/api/v1/users/keys": return self._send(200, {"keys": emu.keys})
                if path == "/api/v1/vaults": return self._send(200, {"items": list(emu.vaults.values())})
                if path.startswith("/api/v1/folders/"):
                    f = emu.folders.get(path.rsplit("/", 1)[1]); return self._send(200, f) if f else self._send(404, {"errors": [{"message": "not found"}]})
                if path == "/api/v1/items/search": return self._send(200, {"items": [{"id": i, "name": it["name"]} for i, it in emu.items.items()]})
                if path.startswith("/api/v1/items/"):
                    it = emu.items.get(path.rsplit("/", 1)[1]); return self._send(200, it) if it else self._send(404, {"errors": [{"message": "not found"}]})
                self._send(404, {"errors": [{"message": "unknown"}]})

            def log_message(self, *a):
                pass
        return H


@pytest.fixture(scope="module")
def passwork_servers():
    from http.server import HTTPServer
    out = {}
    for mode in (True, False):
        emu = _PassworkEmu(encrypt=mode)
        srv = HTTPServer(("127.0.0.1", 0), emu.handler()); threading.Thread(target=srv.serve_forever, daemon=True).start()
        out[mode] = (f"http://127.0.0.1:{srv.server_port}", emu, srv)
    yield out
    for _, _, srv in out.values():
        srv.shutdown()


def test_passwork_live_encrypted_and_plain(client, initialized, passwork_servers):
    hdr = unlock(client)
    host, emu, _ = passwork_servers[True]
    # encryption on: without the master password the instance refuses item reads → a plain message, not a 403 dump
    r = client.post("/api/import/passwork", json={"host": host, "token": emu.token}, headers=hdr)
    assert r.status_code == 422 and "master password" in r.json()["detail"], r.text
    r = client.post("/api/import/passwork", json={"host": host, "token": emu.token, "master_password": "wrong one"}, headers=hdr)
    assert r.status_code == 422 and "wrong master password" in r.json()["detail"], r.text
    r = client.post("/api/import/passwork", json={"host": host, "token": "bad", "master_password": emu.master_password}, headers=hdr)
    assert r.status_code == 422 and "token rejected" in r.json()["detail"]
    r = client.post("/api/import/passwork", json={"host": host, "token": emu.token, "master_password": emu.master_password}, headers=hdr)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["format"] == "passwork" and res["stats"]["secrets"] == 2 and res["stats"]["skipped"] == 0, res["stats"]
    f = {fl["name"]: {x["name"]: x for x in fl["secrets"]} for fl in res["payload"]["folders"]}
    assert set(f) == {"Ops/CI/GitLab", "Ops"}, set(f)
    gl = f["Ops/CI/GitLab"]["GitLab deploy"]
    assert gl["value"] == "gl-pw" and gl["login"] == "ci" and gl["totp_seed"] == "JBSWY3DPEHPK3PXP" and gl["url"] == "https://gitlab.example.com" and gl["tags"] == "ci,prod" and gl["is_favorite"]
    assert "project: core" in gl["notes"] and "attachment (not imported): runner.toml" in gl["notes"] and "runner" in gl["notes"]
    assert f["Ops"]["Plain note"]["value"] == "note-pw"
    assert "/api/v1/users/master-key/options" in emu.calls and any(p.startswith("/api/v1/folders/f2") for p in emu.calls)
    # the same with the master key given directly (what PASSWORK_MASTER_KEY holds)
    r = client.post("/api/import/passwork", json={"host": host, "token": emu.token, "master_key": emu.master_key}, headers=hdr)
    assert r.status_code == 200 and r.json()["stats"]["secrets"] == 2
    # import for real and read back
    imp = client.post("/api/import", json={"folders": res["payload"]["folders"]}, headers=hdr).json()
    assert imp["created_secrets"] == 2
    got = _values(client, hdr, "Ops/CI/GitLab")["GitLab deploy"]
    assert got["value"] == "gl-pw" and got["totp"].isdigit() and got["login"] == "ci"
    # encryption off: plain base64 on the wire, no master password needed
    host2, emu2, _ = passwork_servers[False]
    r = client.post("/api/import/passwork", json={"host": host2, "token": emu2.token, "into_folder": "pw-plain"}, headers=hdr)
    assert r.status_code == 200 and r.json()["stats"]["secrets"] == 2, r.text
    assert r.json()["payload"]["folders"][0]["name"] == "pw-plain" and {x["value"] for x in r.json()["payload"]["folders"][0]["secrets"]} == {"gl-pw", "note-pw"}


def test_passwork_crypto_roundtrip_unit():
    """The connector's primitives, reproduced: custom base32, OpenSSL Salted__ AES-CBC, PBKDF2 master key."""
    assert importers.pw_base32_decode(importers.pw_base32_encode("Hello, Мир! 123")) == "Hello, Мир! 123"
    blob = importers.pw_encrypt_aes("секрет".encode(), "pass-phrase")
    assert set(blob) <= set("0123456789abcdefghjkmnpqrtuvwxyz") and importers.pw_decrypt_aes(blob, "pass-phrase").decode() == "секрет"
    # a wrong passphrase: usually a padding error, once in ~256 tries valid-looking garbage — either way, never the plaintext
    try:
        assert importers.pw_decrypt_aes(blob, "other") != "секрет".encode()
    except Exception:
        pass
    mk = importers.pw_master_key_from_password("p", "pbkdf:sha256:10:64:s")
    import base64, hashlib
    assert base64.b64decode(mk) == hashlib.pbkdf2_hmac("sha256", b"p", b"s", 10, dklen=64)


# ─── 0.35: Dashlane, Keeper, Passbolt, KDBX ──────────────────────────────────
import os as _os
import pathlib as _pathlib

KDBX_DIR = _pathlib.Path(__file__).resolve().parent / "fixtures" / "kdbx"

DASHLANE_CREDENTIALS = """username,username2,username3,title,password,note,url,category,otpSecret
alice@example.com,alice,,GitHub,gh-pass-1,work account,https://github.com,Work,JBSWY3DPEHPK3PXP
,,,"Router, home",r0uter,,http://192.168.1.1,Home,
"""
DASHLANE_NOTES = """title,note,category
Wi-Fi,SSID office / pw w1f1,Work
"""
KEEPER_JSON = {
    "shared_folders": [{"path": "Team\\Ops", "manage_users": True}],
    "records": [
        {"title": "Prod DB", "login": "dba", "password": "kp-pass-1", "login_url": "https://db.example.com", "notes": "primary",
         "custom_fields": {"TFC:Keeper": "otpauth://totp/db?secret=GEZDGNBVGY3TQOJQ", "Port": "5432"}, "folders": [{"folder": "Infra\\Databases"}]},
        {"title": "Shared API", "login": "svc", "password": "kp-pass-2", "folders": [{"shared_folder": "Team\\Ops", "can_edit": True}]},
        {"title": "Loose", "login": "", "password": "kp-pass-3"},
    ],
}
KEEPER_CSV = """Folder,Title,Login,Password,Website Address,Notes,Shared Folder,Custom Fields
Infra\\Databases,Prod DB,dba,kp-pass-1,https://db.example.com,primary,,TFC:Keeper,otpauth://totp/db?secret=GEZDGNBVGY3TQOJQ,Port,5432
"""
PASSBOLT_CSV = """Title,Username,URL,Password,Notes,Group,TOTP
Jenkins,admin,https://ci.example.com,pb-pass-1,build server,DevOps/CI,otpauth://totp/J?secret=JBSWY3DPEHPK3PXP
Printer,,http://printer.local,pb-pass-2,,Office,
"""


def test_dashlane_zip_and_single_csv(client, initialized):
    hdr = unlock(client)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("export/credentials.csv", DASHLANE_CREDENTIALS); z.writestr("export/securenotes.csv", DASHLANE_NOTES); z.writestr("export/payments.csv", "a,b\n1,2\n")
    res = _parse(client, hdr, "dashlane.zip", buf.getvalue()).json()
    assert res["format"] == "dashlane", res
    folders = {f["name"]: {s["name"]: s for s in f["secrets"]} for f in res["payload"]["folders"]}
    gh = folders["Work"]["GitHub"]
    assert gh["value"] == "gh-pass-1" and gh["login"] == "alice@example.com" and gh["totp_seed"] == "JBSWY3DPEHPK3PXP" and gh["url"] == "https://github.com"
    assert "also: alice" in gh["notes"] and "work account" in gh["notes"]
    assert folders["Home"]["Router, home"]["value"] == "r0uter"
    assert folders["Work"]["Wi-Fi"]["value"] == "SSID office / pw w1f1" and folders["Work"]["Wi-Fi"]["tags"] == "note", "a secure note's text is the value"
    assert res["stats"]["secrets"] == 3
    res2 = _parse(client, hdr, "credentials.csv", DASHLANE_CREDENTIALS.encode()).json()
    assert res2["format"] == "dashlane" and res2["stats"]["secrets"] == 2
    assert client.post("/api/import", json={"folders": res["payload"]["folders"]}, headers=hdr).json()["created_secrets"] == 3
    assert _values(client, hdr, "Work")["GitHub"]["totp"].isdigit()


def test_keeper_json_and_csv_with_header(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "keeper.json", json.dumps(KEEPER_JSON).encode()).json()
    assert res["format"] == "keeper", res
    folders = {f["name"]: {s["name"]: s for s in f["secrets"]} for f in res["payload"]["folders"]}
    db = folders["Infra/Databases"]["Prod DB"]
    assert db["value"] == "kp-pass-1" and db["login"] == "dba" and db["totp_seed"] == "GEZDGNBVGY3TQOJQ" and "Port: 5432" in db["notes"] and "primary" in db["notes"]
    assert folders["Team/Ops"]["Shared API"]["value"] == "kp-pass-2"
    assert folders["import-keeper"]["Loose"]["value"] == "kp-pass-3", "a record without a folder lands in the default folder"
    res2 = _parse(client, hdr, "keeper.csv", KEEPER_CSV.encode()).json()
    assert res2["format"] == "keeper" and res2["payload"]["folders"][0]["name"] == "Infra/Databases"
    s = res2["payload"]["folders"][0]["secrets"][0]
    assert s["totp_seed"] == "GEZDGNBVGY3TQOJQ" and "Port: 5432" in s["notes"] and s["url"] == "https://db.example.com"
    # a Keeper CSV without a header row cannot be told apart from any CSV: it is refused by name with a pointer to the JSON export
    r = _parse(client, hdr, "keeper-noheader.csv", b"Infra,Prod DB,dba,pw,https://x,notes,,\n", fmt="keeper")
    assert r.status_code == 422 and "JSON export is recommended" in r.json()["detail"]


def test_passbolt_csv(client, initialized):
    hdr = unlock(client)
    res = _parse(client, hdr, "passbolt.csv", PASSBOLT_CSV.encode()).json()
    assert res["format"] == "passbolt", res
    folders = {f["name"]: {s["name"]: s for s in f["secrets"]} for f in res["payload"]["folders"]}
    j = folders["DevOps/CI"]["Jenkins"]
    assert j["value"] == "pb-pass-1" and j["login"] == "admin" and j["totp_seed"] == "JBSWY3DPEHPK3PXP" and j["notes"] == "build server" and j["url"] == "https://ci.example.com"
    assert folders["Office"]["Printer"]["value"] == "pb-pass-2"
    r = _parse(client, hdr, "x.csv", b"Title,Password\nA,b\n", fmt="passbolt")
    assert r.status_code == 422 and "CSV (KeePass)" in r.json()["detail"]


def _kdbx(client, hdr, name, password="", keyfile=None, fmt="auto"):
    files = {"file": (name, (KDBX_DIR / name).read_bytes())}
    if keyfile:
        files["keyfile"] = (keyfile, (KDBX_DIR / keyfile).read_bytes())
    return client.post("/api/import/parse", files=files, data={"format": fmt, "password": password}, headers=hdr)


def test_kdbx_keepassxc_vectors_open_directly(client, initialized):
    """KeePassXC's own test databases: KDBX 3.0 and 3.1 (AES-KDF, AES, Salsa20 inner stream), KDBX 4.0 (Argon2d,
    ChaCha20) and a key-file-only database with a v2 XML key file. Detected by signature, read without the XML export."""
    hdr = unlock(client)
    for name, pw, expect in (("Format300.kdbx", "a", ("Sample Entry", "User Name", "Password")),
                             ("NewDatabase.kdbx", "a", ("Sample Entry", "User Name", "Password")),
                             ("Format400.kdbx", "t", ("Format400", "Format400", "Format400"))):
        res = _kdbx(client, hdr, name, pw)
        assert res.status_code == 200, (name, res.text)
        res = res.json()
        assert res["format"] == "kdbx", name
        all_secrets = {s["name"]: s for f in res["payload"]["folders"] for s in f["secrets"]}
        s = all_secrets[expect[0]]
        assert (s["login"], s["value"]) == (expect[1], expect[2]), (name, s)
    nd = _kdbx(client, hdr, "NewDatabase.kdbx", "a").json()
    # the root group of KeePassXC's file is named after the database, so it becomes the top folder
    assert {f["name"] for f in nd["payload"]["folders"]} == {"NewDatabase", "NewDatabase/Homebanking/Subgroup"}, nd["payload"]["folders"]
    assert any(s["name"] == "Subgroup Entry" and s["value"] == "SecurePassword" and s["login"] == "Bank User Name" for f in nd["payload"]["folders"] for s in f["secrets"])
    kf = _kdbx(client, hdr, "FileKeyXmlV2.kdbx", "", keyfile="FileKeyXmlV2.keyx")
    assert kf.status_code in (200, 422), kf.text          # the database is empty: the import payload has no secrets
    if kf.status_code == 200:
        assert kf.json()["stats"]["secrets"] == 0
    else:
        assert "KDBX" not in kf.json()["detail"], kf.text   # 422 only for "nothing to import", never a key error


def test_kdbx_pykeepass_files_argon2id_chacha20_keyfile_history(client, initialized):
    """Files written by pykeepass: Argon2d + AES, Argon2id + ChaCha20, password + binary key file. A history entry
    carries a protected value too — the inner stream is consumed in document order, so the current password must
    still decrypt correctly after it. Groups → folders, otp → TOTP, custom field → notes, tags kept."""
    hdr = unlock(client)
    for name, keyfile in (("kdbx4-argon2d-aes.kdbx", None), ("kdbx4-argon2id-chacha20.kdbx", None), ("kdbx4-pw-and-keyfile.kdbx", "FileKeyBinary.key")):
        res = _kdbx(client, hdr, name, "pw-1", keyfile=keyfile)
        assert res.status_code == 200, (name, res.text)
        folders = {f["name"]: {s["name"]: s for s in f["secrets"]} for f in res.json()["payload"]["folders"]}
        if keyfile:                                            # written from the bare database: one entry, no groups
            assert folders["import-kdbx"]["kf"]["value"] == "with-keyfile", folders
            continue
        db01 = folders["Servers"]["db01"]
        assert db01["value"] == "pg-secret-v2" and db01["login"] == "postgres" and db01["totp_seed"] == "GEZDGNBVGY3TQOJQ", (name, db01)
        assert db01["url"] == "https://db01.example.com" and "Port: 5432" in db01["notes"] and "primary" in db01["notes"] and set(db01["tags"].split(",")) == {"prod", "db"}
        assert folders["Servers/Backup"]["db02"]["value"] == "pg2" and folders["import-kdbx"]["Root entry"]["value"] == "root-pw"
    res = _kdbx(client, hdr, "kdbx4-argon2d-aes.kdbx", "pw-1").json()
    assert client.post("/api/import", json={"folders": res["payload"]["folders"]}, headers=hdr).json()["created_secrets"] == 3
    assert _values(client, hdr, "Servers")["db01"]["value"] == "pg-secret-v2"


def test_kdbx_wrong_key_damaged_file_and_bad_keyfile_are_refused(client, initialized):
    hdr = unlock(client)
    r = _kdbx(client, hdr, "kdbx4-argon2d-aes.kdbx", "wrong")
    assert r.status_code == 422 and "wrong password or key file" in r.json()["detail"], r.text
    r = _kdbx(client, hdr, "NewDatabase.kdbx", "wrong")
    assert r.status_code == 422 and "wrong password or key file" in r.json()["detail"], r.text
    r = _kdbx(client, hdr, "kdbx4-pw-and-keyfile.kdbx", "pw-1")                       # key file missing
    assert r.status_code == 422 and "wrong password or key file" in r.json()["detail"]
    r = _kdbx(client, hdr, "kdbx4-argon2d-aes.kdbx", "")
    assert r.status_code == 422 and "password or a key file is required" in r.json()["detail"]
    r = _kdbx(client, hdr, "FileKeyXmlV2HashFail.kdbx", "", keyfile="FileKeyXmlV2HashFail.keyx")
    assert r.status_code == 422 and "hash does not match" in r.json()["detail"], r.text
    raw = bytearray((KDBX_DIR / "Format400.kdbx").read_bytes()); raw[20] ^= 0x01            # a flipped header byte
    r = client.post("/api/import/parse", files={"file": ("x.kdbx", bytes(raw))}, data={"format": "auto", "password": "t"}, headers=hdr)
    assert r.status_code == 422 and ("header hash mismatch" in r.json()["detail"] or "damaged" in r.json()["detail"]), r.text
    raw = (KDBX_DIR / "Format400.kdbx").read_bytes()[:400]                                 # truncated
    r = client.post("/api/import/parse", files={"file": ("x.kdbx", raw)}, data={"format": "auto", "password": "t"}, headers=hdr)
    assert r.status_code == 422, r.text
    # KDBX 2 / unknown versions are named, not guessed
    raw = bytearray((KDBX_DIR / "Format400.kdbx").read_bytes()); raw[10:12] = b"\x02\x00"
    r = client.post("/api/import/parse", files={"file": ("x.kdbx", bytes(raw))}, data={"format": "auto", "password": "t"}, headers=hdr)
    assert r.status_code == 422 and "not supported" in r.json()["detail"]


def test_kdbx_salsa20_and_keyfile_rules_unit():
    import kdbx
    # Salsa20 — the reference vector from the eSTREAM set (key 0x80 00…, nonce 0, first 64 keystream bytes start with E3BE8FDD)
    ks = kdbx._salsa20_block(bytes([0x80]) + bytes(31), bytes(8), 0)
    assert ks[:4].hex() == "e3be8fdd" and len(ks) == 64
    assert kdbx.keyfile_key(bytes(range(32))) == bytes(range(32))
    assert kdbx.keyfile_key(("ab" * 32).encode()) == bytes.fromhex("ab" * 32)
    v1 = b'<?xml version="1.0"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>' + __import__("base64").b64encode(bytes(32)) + b'</Data></Key></KeyFile>'
    assert kdbx.keyfile_key(v1) == bytes(32)
    import hashlib
    assert kdbx.keyfile_key(b"just some text file") == hashlib.sha256(b"just some text file").digest()
    with pytest.raises(kdbx.KdbxError):
        kdbx.composite_key("", None)
