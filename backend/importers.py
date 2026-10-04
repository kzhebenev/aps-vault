"""Import from other secret managers (0.29).

Every source is turned into the vault's own import payload — `{"folders": [{"name", "secrets": [...]}]}`
with secrets of `{name, value, login, notes, totp_seed, url, tags, is_favorite}` — so one preview and one
import path (`POST /api/import`) serve them all. Nothing is stored here: the administrator uploads an
export, sees what would be created, and only then imports.

Sources:
  bitwarden   — Bitwarden / Vaultwarden unencrypted JSON export (folders, items: login / secure note / card / identity)
  keepass     — KeePass 2.x XML export (groups → folders; Title, UserName, Password, URL, Notes, otp)
  1password   — 1Password CSV export (Title, Url, Username, Password, OTPAuth, Favorite, Archived, Tags, Notes)
  1pux        — 1Password 1PUX export (zip with export.data: vaults → items)
  lastpass    — LastPass CSV (url, username, password, totp, extra, name, grouping, fav)
  csv         — any CSV with a header: name/title, value/password/secret, login/username/user, notes, url, tags, totp
  dotenv      — KEY=VALUE files (.env): one secret per key
  apsvault    — this vault's own export JSON
  hashicorp   — a live HashiCorp Vault / Deckhouse Stronghold KV v2 mount (pull over the API)

Mapping rules that are not obvious: a secure note without a password becomes a secret whose *value is the
note* (the note is the secret); a TOTP given as an otpauth:// URL yields its `secret` parameter, a raw
base32 seed is kept, anything else (steam://, unknown) goes to the notes with a warning; names are
de-duplicated inside a folder with " (2)", " (3)" so nothing silently overwrites; archived/trashed items
are skipped and counted.
"""
from __future__ import annotations

import csv
import io
import json
import re
import urllib.parse
import zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 20 * 1024 * 1024
MAX_ITEMS = 20000
FORMATS = ("auto", "bitwarden", "keepass", "1password", "1pux", "lastpass", "csv", "dotenv", "apsvault", "passwork")

_B32 = re.compile(r"^[A-Z2-7]+=*$")


class ImportError_(ValueError):
    pass


# ─── helpers ──────────────────────────────────────────────────────────────────
def totp_seed_from(raw: str) -> tuple[str, str]:
    """(seed, warning). Accepts an otpauth:// URL or a base32 seed; anything else → ('', why)."""
    s = (raw or "").strip()
    if not s:
        return "", ""
    if s.lower().startswith("otpauth://"):
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(s).query)
            sec = (q.get("secret") or [""])[0]
        except Exception:
            sec = ""
        if not sec:
            return "", "otpauth URL without a secret parameter"
        s = sec
    elif s.lower().startswith("steam://"):
        return "", "Steam guard codes are not TOTP — kept in the notes"
    cand = s.replace(" ", "").replace("-", "").upper()
    if _B32.match(cand) and len(cand) >= 8:
        return cand, ""
    return "", "TOTP seed is not base32 — kept in the notes"


def _clean_name(n: str, fallback: str = "unnamed") -> str:
    n = re.sub(r"\s+", " ", (n or "").strip()).strip("/")
    return (n or fallback)[:256]


def _clean_folder(n: str, fallback: str) -> str:
    n = re.sub(r"\s+", " ", (n or "").strip()).strip("/")
    return (n or fallback)[:128]


class _Builder:
    """Collects items per folder, de-duplicates names, counts, keeps warnings."""

    def __init__(self, fmt: str, into_folder: str | None, prefix: str):
        self.fmt, self.into, self.prefix = fmt, (into_folder or "").strip() or None, (prefix or "").strip()
        self.folders: dict[str, list[dict]] = {}
        self.names: dict[str, dict[str, int]] = {}
        self.warnings: list[str] = []
        self.skipped = 0
        self.total = 0

    def folder_name(self, source_folder: str) -> str:
        if self.into:
            return self.into
        base = _clean_folder(source_folder, f"import-{self.fmt}")
        return _clean_folder(f"{self.prefix}{base}", base) if self.prefix else base

    def add(self, source_folder: str, name: str, value: str, *, login: str = "", notes: str = "", totp: str = "",
            url: str = "", tags: str = "", favorite: bool = False, extra_note_lines: list[str] | None = None) -> None:
        if self.total >= MAX_ITEMS:
            raise ImportError_(f"more than {MAX_ITEMS} items — split the export")
        fname = self.folder_name(source_folder)
        name = _clean_name(name)
        seed, warn = totp_seed_from(totp)
        note_parts = [notes.strip()] if notes and notes.strip() else []
        if warn:
            note_parts.append(f"TOTP: {totp.strip()}")
            self.warnings.append(f"{fname}/{name}: {warn}")
        if extra_note_lines:
            note_parts.extend(l for l in extra_note_lines if l)
        notes_out = "\n".join(note_parts)
        if not value:
            if notes_out:
                value, notes_out = notes_out, ""        # a note without a password: the note is the secret
            else:
                self.skipped += 1
                self.warnings.append(f"{fname}/{name}: empty — skipped")
                return
        used = self.names.setdefault(fname, {})
        base, n = name, used.get(name, 0)
        if n:
            name = f"{base} ({n + 1})"
            while name in used:
                n += 1; name = f"{base} ({n + 1})"
        used[base] = n + 1
        used[name] = 1
        url = (url or "").strip()
        if url and not (url.startswith("http://") or url.startswith("https://")):
            if "." in url and " " not in url:
                url = "https://" + url
            else:
                notes_out = (notes_out + f"\nURL: {url}").strip(); url = ""
        self.folders.setdefault(fname, []).append({"name": name, "value": value, "login": (login or "").strip(), "notes": notes_out,
                                                   "totp_seed": seed, "url": url[:512], "tags": (tags or "").strip()[:512], "is_favorite": bool(favorite)})
        self.total += 1

    def payload(self) -> dict:
        return {"folders": [{"name": f, "secrets": items} for f, items in self.folders.items()]}

    def result(self) -> dict:
        return {"format": self.fmt, "payload": self.payload(), "warnings": self.warnings[:200],
                "stats": {"folders": len(self.folders), "secrets": self.total, "skipped": self.skipped,
                          "with_login": sum(1 for it in self.folders.values() for x in it if x["login"]),
                          "with_totp": sum(1 for it in self.folders.values() for x in it if x["totp_seed"]),
                          "with_notes": sum(1 for it in self.folders.values() for x in it if x["notes"])}}


# ─── detection ────────────────────────────────────────────────────────────────
def detect(filename: str, data: bytes) -> str:
    fn = (filename or "").lower()
    head = data[:4096]
    if data[:2] == b"PK":
        return "1pux"
    stripped = head.lstrip()
    if stripped.startswith(b"<"):
        return "keepass"
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        try:
            j = json.loads(data.decode("utf-8-sig"))
        except Exception:
            raise ImportError_("the file looks like JSON but does not parse")
        if isinstance(j, dict) and "items" in j and ("folders" in j or "encrypted" in j):
            return "bitwarden"
        if isinstance(j, dict) and isinstance(j.get("folders"), list) and all(isinstance(f, dict) and "secrets" in f for f in j["folders"]):
            return "apsvault"
        if _looks_like_passwork(j):
            return "passwork"
        raise ImportError_("unknown JSON layout — pick the format by hand")
    text = head.decode("utf-8-sig", "replace")
    first = text.splitlines()[0].strip().lower() if text.strip() else ""
    if fn.endswith(".env") or ".env" in fn or (first and "=" in first and "," not in first and not first.startswith("#") and re.match(r"^(export\s+)?[a-z_][a-z0-9_]*\s*=", first)):
        return "dotenv"
    if first.startswith("url,username,password,totp,extra,name,grouping,fav") or first.startswith("url,username,password,extra,name,grouping,fav"):
        return "lastpass"
    if "title" in first and "username" in first and ("otpauth" in first or "url" in first):
        return "1password"
    if "," in first or ";" in first:
        return "csv"
    if re.search(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", text, re.M):
        return "dotenv"
    raise ImportError_("cannot tell the format — pick it by hand")


# ─── parsers ──────────────────────────────────────────────────────────────────
def _bitwarden(data: bytes, b: _Builder) -> None:
    j = json.loads(data.decode("utf-8-sig"))
    if j.get("encrypted"):
        raise ImportError_("this is an encrypted Bitwarden export — export again with 'json' (unencrypted) and import that file")
    folders = {f.get("id"): f.get("name", "") for f in j.get("folders") or []}
    folders.update({c.get("id"): c.get("name", "") for c in j.get("collections") or []})
    for it in j.get("items") or []:
        if it.get("deletedDate"):
            b.skipped += 1; continue
        name = it.get("name") or "unnamed"
        fld = folders.get(it.get("folderId")) or (folders.get((it.get("collectionIds") or [None])[0]) if it.get("collectionIds") else "") or ""
        notes = it.get("notes") or ""
        extra = [f"{f.get('name')}: {f.get('value')}" for f in (it.get("fields") or []) if f.get("name")]
        t = it.get("type")
        if t == 1 and it.get("login"):
            lg = it["login"]
            uris = [u.get("uri") for u in (lg.get("uris") or []) if u.get("uri")]
            b.add(fld, name, lg.get("password") or "", login=lg.get("username") or "", notes=notes, totp=lg.get("totp") or "",
                  url=uris[0] if uris else "", favorite=bool(it.get("favorite")), extra_note_lines=extra + [f"URL: {u}" for u in uris[1:]])
        elif t == 3 and it.get("card"):
            c = it["card"]
            value = c.get("number") or ""
            extra2 = [f"{k}: {c.get(k)}" for k in ("cardholderName", "brand", "expMonth", "expYear", "code") if c.get(k)]
            b.add(fld, name, value, notes=notes, favorite=bool(it.get("favorite")), extra_note_lines=extra2 + extra, tags="card")
        elif t == 4 and it.get("identity"):
            idn = it["identity"]
            lines = [f"{k}: {v}" for k, v in idn.items() if v]
            b.add(fld, name, "", notes=notes, favorite=bool(it.get("favorite")), extra_note_lines=lines + extra, tags="identity")
        else:   # 2 = secure note, or anything else
            b.add(fld, name, "", notes=notes, favorite=bool(it.get("favorite")), extra_note_lines=extra, tags="note" if t == 2 else "")


def _keepass(data: bytes, b: _Builder) -> None:
    try:
        root = ET.fromstring(data.decode("utf-8-sig"))
    except ET.ParseError as e:
        raise ImportError_(f"not a KeePass XML export: {e}")
    if root.tag != "KeePassFile":
        raise ImportError_("not a KeePass XML export (root element is not KeePassFile)")

    def strings(entry):
        out = {}
        for st in entry.findall("String"):
            k = st.findtext("Key") or ""; v = st.findtext("Value") or ""
            out[k] = v
        return out

    def walk(group, path):
        gname = group.findtext("Name") or ""
        here = path + ([gname] if gname and gname != "Root" and gname != "Database" else [])
        if gname == "Recycle Bin":
            b.skipped += len(group.findall(".//Entry")); return
        for e in group.findall("Entry"):
            s = strings(e)
            totp = s.get("otp") or s.get("TimeOtp-Secret-Base32") or s.get("TOTP Seed") or ""
            known = {"Title", "UserName", "Password", "URL", "Notes", "otp", "TimeOtp-Secret-Base32", "TOTP Seed", "TimeOtp-Length", "TimeOtp-Period", "TimeOtp-Algorithm", "TOTP Settings"}
            extra = [f"{k}: {v}" for k, v in s.items() if k not in known and v]
            tags = (e.findtext("Tags") or "").replace(";", ",")
            b.add("/".join(here), s.get("Title") or "unnamed", s.get("Password") or "", login=s.get("UserName") or "", notes=s.get("Notes") or "",
                  totp=totp, url=s.get("URL") or "", tags=tags, extra_note_lines=extra)
        for g in group.findall("Group"):
            walk(g, here)

    rootgroup = root.find("Root/Group")
    if rootgroup is None:
        raise ImportError_("KeePass XML without Root/Group")
    walk(rootgroup, [])


def _csv_rows(data: bytes) -> tuple[list[str], list[list[str]]]:
    text = data.decode("utf-8-sig", "replace")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    rows = [r for r in rows if any(c.strip() for c in r)]
    if not rows:
        raise ImportError_("empty CSV")
    header = [h.strip().lower().lstrip("﻿") for h in rows[0]]
    return header, rows[1:]


def _col(header: list[str], *names: str) -> int:
    for n in names:
        if n in header:
            return header.index(n)
    return -1


def _onepassword_csv(data: bytes, b: _Builder) -> None:
    header, rows = _csv_rows(data)
    ci = {k: _col(header, k) for k in ("title", "url", "username", "password", "otpauth", "favorite", "archived", "tags", "notes")}
    if ci["title"] < 0 or ci["password"] < 0:
        raise ImportError_("not a 1Password CSV (needs Title and Password columns)")
    g = lambda r, k: r[ci[k]].strip() if ci[k] >= 0 and ci[k] < len(r) else ""
    for r in rows:
        if g(r, "archived").lower() in ("true", "1", "yes"):
            b.skipped += 1; continue
        b.add("1Password", g(r, "title") or "unnamed", g(r, "password"), login=g(r, "username"), notes=g(r, "notes"), totp=g(r, "otpauth"),
              url=g(r, "url"), tags=g(r, "tags").replace(";", ","), favorite=g(r, "favorite").lower() in ("true", "1", "yes"))


def _onepassword_1pux(data: bytes, b: _Builder) -> None:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        raw = z.read("export.data")
    except (zipfile.BadZipFile, KeyError):
        raise ImportError_("not a 1PUX export (zip with export.data)")
    j = json.loads(raw.decode("utf-8"))
    for acc in j.get("accounts") or []:
        for v in acc.get("vaults") or []:
            vname = (v.get("attrs") or {}).get("name") or "1Password"
            for it in v.get("items") or []:
                if it.get("state") == "archived" or it.get("trashed"):
                    b.skipped += 1; continue
                ov = it.get("overview") or {}; det = it.get("details") or {}
                login = password = totp = ""
                for f in det.get("loginFields") or []:
                    d = (f.get("designation") or "").lower()
                    if d == "username": login = f.get("value") or ""
                    elif d == "password": password = f.get("value") or ""
                extra = []
                for sec in det.get("sections") or []:
                    for f in sec.get("fields") or []:
                        val = f.get("value") or {}
                        if "totp" in val:
                            totp = totp or val["totp"]
                        elif "concealed" in val and not password and (f.get("title") or "").lower() in ("password", "пароль"):
                            password = val["concealed"]
                        else:
                            vv = next(iter(val.values()), None) if isinstance(val, dict) and val else None
                            if vv and isinstance(vv, (str, int)) and f.get("title"):
                                extra.append(f"{f.get('title')}: {vv}")
                if not password and det.get("password"):
                    password = det["password"]
                urls = [u.get("url") for u in (ov.get("urls") or []) if u.get("url")] or ([ov["url"]] if ov.get("url") else [])
                b.add(vname, ov.get("title") or "unnamed", password, login=login, notes=det.get("notesPlain") or "", totp=totp,
                      url=urls[0] if urls else "", tags=",".join(ov.get("tags") or []), favorite=bool(it.get("favIndex")),
                      extra_note_lines=extra + [f"URL: {u}" for u in urls[1:]])


def _lastpass(data: bytes, b: _Builder) -> None:
    header, rows = _csv_rows(data)
    ci = {k: _col(header, k) for k in ("url", "username", "password", "totp", "extra", "name", "grouping", "fav")}
    if ci["name"] < 0 or ci["password"] < 0:
        raise ImportError_("not a LastPass CSV (needs name and password columns)")
    g = lambda r, k: r[ci[k]].strip() if ci[k] >= 0 and ci[k] < len(r) else ""
    for r in rows:
        url = g(r, "url")
        if url == "http://sn":
            url = ""           # LastPass marks secure notes with this pseudo-URL
        b.add(g(r, "grouping").replace("\\", "/"), g(r, "name") or "unnamed", g(r, "password"), login=g(r, "username"), notes=g(r, "extra"),
              totp=g(r, "totp"), url=url, favorite=g(r, "fav") == "1")


def _generic_csv(data: bytes, b: _Builder) -> None:
    header, rows = _csv_rows(data)
    name_i = _col(header, "name", "title", "secret_name", "key", "название", "имя", "наименование")
    val_i = _col(header, "value", "password", "secret", "pass", "пароль", "значение")
    if name_i < 0 or val_i < 0:
        raise ImportError_("CSV needs a name/title column and a value/password column (or Название / Пароль)")
    login_i = _col(header, "login", "username", "user", "email", "логин", "пользователь")
    notes_i = _col(header, "notes", "note", "comment", "extra", "description", "описание", "заметки", "комментарий")
    url_i = _col(header, "url", "uri", "website", "link", "ссылка", "сайт", "адрес")
    tags_i = _col(header, "tags", "tag", "labels", "теги", "метки")
    totp_i = _col(header, "totp", "totp_seed", "otp", "otpauth", "2fa")
    folder_i = _col(header, "folder", "group", "grouping", "category", "vault", "path", "папка", "раздел", "сейф", "путь")
    g = lambda r, i: r[i].strip() if 0 <= i < len(r) else ""
    for r in rows:
        b.add(g(r, folder_i), g(r, name_i) or "unnamed", g(r, val_i), login=g(r, login_i), notes=g(r, notes_i), totp=g(r, totp_i), url=g(r, url_i), tags=g(r, tags_i))


_DOTENV = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*?)\s*$""")


def _dotenv(data: bytes, b: _Builder, filename: str = "") -> None:
    text = data.decode("utf-8-sig", "replace")
    fld = (filename or ".env").rsplit("/", 1)[-1] or ".env"
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _DOTENV.match(line)
        if not m:
            b.warnings.append(f"line skipped: {line.strip()[:60]}")
            continue
        key, val = m.group(1), m.group(2)
        if val[:1] in ("\"", "'"):
            q = val[0]
            i, out = 1, []
            while i < len(val) and val[i] != q:
                if q == '"' and val[i] == "\\" and i + 1 < len(val):
                    nxt = val[i + 1]
                    out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "$": "$"}.get(nxt, "\\" + nxt)); i += 2; continue
                out.append(val[i]); i += 1
            val = "".join(out)                 # whatever follows the closing quote (a comment) is ignored
        else:
            val = val.split(" #", 1)[0].rstrip()
        b.add(fld, key, val)


def _apsvault(data: bytes, b: _Builder) -> None:
    j = json.loads(data.decode("utf-8-sig"))
    for f in j.get("folders") or []:
        for sd in f.get("secrets") or []:
            if sd.get("value") is None:
                b.skipped += 1; b.warnings.append(f"{f.get('name')}/{sd.get('name')}: machine-only secret exported without its value — skipped"); continue
            b.add(f.get("name") or "", sd.get("name") or "unnamed", sd.get("value") or "", login=sd.get("login") or "", notes=sd.get("notes") or "",
                  totp=sd.get("totp_seed") or "", url=sd.get("url") or "", tags=sd.get("tags") or "", favorite=bool(sd.get("is_favorite")))


def _looks_like_passwork(j) -> bool:
    """Passwork's JSON exports vary by version; the common trait is objects with a `password` (or
    `passwordEncrypted`) key under `passwords`/`items`, grouped by `vaults`/`folders`."""
    found = []

    def walk(o, depth=0):
        if depth > 8 or len(found) > 2:
            return
        if isinstance(o, dict):
            if ("password" in o or "passwordEncrypted" in o) and ("name" in o or "login" in o):
                found.append(o)
            for v in o.values():
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:50]:
                walk(v, depth + 1)
    walk(j)
    return bool(found)


def _passwork_file(data: bytes, b: _Builder) -> None:
    """Passwork export: JSON (vaults → folders → passwords, any nesting) or CSV (English or Russian headers)."""
    stripped = data.lstrip()
    if not (stripped.startswith(b"{") or stripped.startswith(b"[")):
        return _generic_csv(data, b)
    j = json.loads(data.decode("utf-8-sig"))
    if not _looks_like_passwork(j):
        raise ImportError_("not a Passwork JSON export (no password records found)")
    n = [0]

    def item_from(o: dict, path: list[str]):
        pw = o.get("password")
        if pw is None and o.get("passwordEncrypted"):
            try:
                pw = __import__("base64").b64decode(o["passwordEncrypted"]).decode("utf-8")     # encryption off → plain base64
            except Exception:
                b.warnings.append(f"{o.get('name')}: passwordEncrypted is client-side encrypted — export with the password shown, or use the live import with the master password")
                return
        totp, extra = "", []
        for c in o.get("customs") or o.get("custom") or []:
            if not isinstance(c, dict):
                continue
            if (c.get("type") or "").lower() == "totp":
                totp = totp or (c.get("value") or "")
            elif c.get("name"):
                extra.append(f"{c['name']}: {c.get('value', '')}")
        for a in o.get("attachments") or []:
            if isinstance(a, dict) and a.get("name"):
                extra.append(f"attachment (not imported): {a['name']}")
        tags = o.get("tags") or []
        b.add("/".join(path), o.get("name") or o.get("title") or "unnamed", pw or "", login=o.get("login") or o.get("username") or "",
              notes=o.get("description") or o.get("notes") or "", totp=totp, url=o.get("url") or "", tags=",".join(tags) if isinstance(tags, list) else str(tags),
              favorite=bool(o.get("isFavorite") or o.get("favorite")), extra_note_lines=extra)
        n[0] += 1

    def walk(o, path: list[str], depth=0):
        if depth > 12:
            return
        if isinstance(o, dict):
            if ("password" in o or "passwordEncrypted" in o) and ("name" in o or "login" in o):
                item_from(o, path); return
            name = o.get("name") if isinstance(o.get("name"), str) else None
            here = path + ([name] if name and any(k in o for k in ("folders", "items", "passwords", "children", "vaults")) else [])
            for v in o.values():
                walk(v, here, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, path, depth + 1)
    walk(j, [])
    if not n[0]:
        raise ImportError_("no password records found in the Passwork JSON")


PARSERS = {"bitwarden": _bitwarden, "keepass": _keepass, "1password": _onepassword_csv, "1pux": _onepassword_1pux,
           "lastpass": _lastpass, "csv": _generic_csv, "dotenv": _dotenv, "apsvault": _apsvault, "passwork": _passwork_file}


def parse(fmt: str, filename: str, data: bytes, *, into_folder: str | None = None, prefix: str = "") -> dict:
    if len(data) > MAX_BYTES:
        raise ImportError_(f"file larger than {MAX_BYTES // (1024 * 1024)} MB")
    if not data.strip():
        raise ImportError_("empty file")
    if fmt not in FORMATS:
        raise ImportError_(f"format must be one of {', '.join(FORMATS)}")
    if fmt == "auto":
        fmt = detect(filename, data)
    b = _Builder(fmt, into_folder, prefix)
    try:
        if fmt == "dotenv":
            _dotenv(data, b, filename)
        else:
            PARSERS[fmt](data, b)
    except ImportError_:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ImportError_(f"the file is not a valid {fmt} export: {str(e)[:80]}")
    return b.result()


# ─── HashiCorp Vault / Stronghold KV v2 ───────────────────────────────────────
def pull_hashicorp(addr: str, token: str, mount: str, path: str = "", *, into_folder: str | None = None, timeout: float = 10.0,
                   fetch=None, max_items: int = MAX_ITEMS) -> dict:
    """Walk a KV v2 mount (LIST metadata, GET data) and build the payload. `fetch(method, url, headers)` is
    injectable for tests; by default urllib. The token is used for the calls and forgotten."""
    import urllib.request
    import urllib.error
    addr = addr.rstrip("/")
    mount = mount.strip("/")
    if not mount:
        raise ImportError_("mount is required (the KV v2 engine path, e.g. secret)")

    def _fetch(method, url, headers):
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:     # nosemgrep: dynamic-urllib-use — administrator's import source, SSRF-checked by the caller
                return r.status, json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, body
        except urllib.error.URLError as e:
            raise ImportError_(f"cannot reach {addr}: {e.reason}")

    fetch = fetch or _fetch
    hdr = {"X-Vault-Token": token, "Accept": "application/json"}
    b = _Builder("hashicorp", into_folder, "")
    seen = 0

    def walk(prefix: str):
        nonlocal seen
        st, body = fetch("GET", f"{addr}/v1/{mount}/metadata/{prefix}?list=true", hdr)
        if st == 403:
            raise ImportError_("permission denied: the token cannot list this path (needs list on <mount>/metadata/*)")
        if st == 404:
            if not prefix:
                raise ImportError_(f"nothing at {mount}/ — wrong mount or empty engine")
            return
        if st != 200:
            raise ImportError_(f"LIST {mount}/metadata/{prefix} → HTTP {st}: {(body.get('errors') or [''])[0]}")
        for key in (body.get("data") or {}).get("keys") or []:
            if key.endswith("/"):
                walk(prefix + key)
                continue
            p = prefix + key
            st2, data = fetch("GET", f"{addr}/v1/{mount}/data/{p}", hdr)
            if st2 != 200:
                b.warnings.append(f"{p}: HTTP {st2} on read — skipped"); b.skipped += 1; continue
            d = (data.get("data") or {}).get("data") or {}
            seen += 1
            if seen > max_items:
                raise ImportError_(f"more than {max_items} secrets — import in parts (path=)")
            low = {k.lower(): (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)) for k, v in d.items()}
            value = low.get("value") or low.get("password") or low.get("secret") or low.get("token") or low.get("key") or ""
            login = low.get("login") or low.get("username") or low.get("user") or ""
            notes = low.get("notes") or ""
            totp = low.get("totp") or low.get("totp_seed") or ""
            url = low.get("url") or ""
            tags = low.get("tags") or ""
            known = {"value", "password", "secret", "token", "key", "login", "username", "user", "notes", "totp", "totp_seed", "url", "tags"}
            rest = {k: v for k, v in d.items() if k.lower() not in known}
            extra = []
            if len(d) == 1 and not value:
                value = next(iter(low.values()))
                rest = {}
            if rest:
                if not value:
                    value = json.dumps(d, ensure_ascii=False, sort_keys=True)
                    extra.append("imported key/value map — the whole map is the value")
                else:
                    extra.append("other keys: " + json.dumps(rest, ensure_ascii=False, sort_keys=True))
            b.add(mount, p, value, login=login, notes=notes, totp=totp, url=url, tags=tags, extra_note_lines=extra)

    walk(path.strip("/") + "/" if path.strip("/") else "")
    return b.result()


# ─── Passwork (API v1, Passwork 7+) ───────────────────────────────────────────
# The wire format follows the official connector (github.com/passwork-europe/passwork-python):
# Authorization: Bearer <access token>; with client-side encryption on, X-Master-Key-Hash = sha256(master key).
# decrypt_aes = custom-base32(base64("Salted__" ‖ salt8 ‖ AES-256-CBC(EVP_BytesToKey(MD5), PKCS7))).
# Chain: master key (PBKDF2-HMAC-SHA256 of the master password with the server's options, or given) →
# user RSA private key (AES) → vault master key (RSA OAEP-SHA256 / PKCS1v15) → item key (AES) → password (AES).
_PW_ALPHABET = "0123456789abcdefghjkmnpqrtuvwxyz"
_PW_LOOKUP = {c: i for i, c in enumerate(_PW_ALPHABET)}
_PW_LOOKUP.update({"o": 0, "i": 1, "l": 1, "s": 5})


def pw_base32_decode(text: str) -> str:
    buf = bits = 0
    out = bytearray()
    for ch in text:
        v = _PW_LOOKUP.get(ch.lower())
        if v is None:
            continue
        buf = (buf << 5) | v; bits += 5
        while bits >= 8:
            out.append((buf >> (bits - 8)) & 0xFF); bits -= 8; buf &= (1 << bits) - 1
    return out.decode("utf-8")


def pw_base32_encode(text: str) -> str:
    buf = bits = 0
    out = []
    for byte in text.encode("utf-8"):
        buf = (buf << 8) | byte; bits += 8
        while bits >= 5:
            out.append(_PW_ALPHABET[(buf >> (bits - 5)) & 31]); bits -= 5; buf &= (1 << bits) - 1
    if bits:
        out.append(_PW_ALPHABET[(buf << (5 - bits)) & 31])
    return "".join(out)


def _evp_bytes_to_key(password: str, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    import hashlib
    dt = d = b""
    while len(dt) < key_len + iv_len:
        d = hashlib.md5(d + password.encode() + salt).digest()
        dt += d
    return dt[:key_len], dt[key_len:key_len + iv_len]


def pw_decrypt_aes(encrypted_b32: str, passphrase: str) -> bytes:
    import base64 as _b64
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    raw = _b64.b64decode(pw_base32_decode(encrypted_b32))
    if raw[:8] != b"Salted__":
        raise ValueError("not an OpenSSL Salted__ blob")
    key, iv = _evp_bytes_to_key(passphrase, raw[8:16], 32, 16)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(raw[16:]) + dec.finalize()
    un = padding.PKCS7(128).unpadder()
    return un.update(padded) + un.finalize()


def pw_encrypt_aes(message: bytes, passphrase: str) -> str:
    """The connector's encrypt_aes — used by the test emulator to produce what a real Passwork sends."""
    import base64 as _b64
    import os as _os
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    salt = _os.urandom(8)
    key, iv = _evp_bytes_to_key(passphrase, salt, 32, 16)
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pad.update(message) + pad.finalize()) + enc.finalize()
    return pw_base32_encode(_b64.b64encode(b"Salted__" + salt + ct).decode())


def _pw_rsa_decrypt(data_b64: str, private_pem: str) -> bytes:
    import base64 as _b64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    blob = _b64.b64decode(data_b64)
    try:
        return key.decrypt(blob, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except Exception:
        return key.decrypt(blob, rsa_padding.PKCS1v15())


def pw_master_key_from_password(master_password: str, options: str) -> str:
    """options = "pbkdf:sha256:<iterations>:<bytes>:<salt>" (GET /api/v1/users/master-key/options)."""
    import base64 as _b64
    import hashlib
    parts = options.split(":")
    digest, iterations, length, salt = parts[1], int(parts[2]), int(parts[3]), parts[4]
    dk = hashlib.pbkdf2_hmac(digest, master_password.encode(), salt.encode(), iterations, dklen=length)
    return _b64.b64encode(dk).decode()


def pull_passwork(host: str, token: str, *, master_password: str = "", master_key: str = "", vault_id: str = "",
                  into_folder: str | None = None, timeout: float = 15.0, fetch=None, max_items: int = MAX_ITEMS) -> dict:
    """Walk a Passwork instance: vaults → items (search) → each item (GET), decrypting on the way when the
    instance uses client-side encryption. Nothing is written back; the token is used and forgotten."""
    import base64 as _b64
    import hashlib
    import urllib.request
    import urllib.error
    host = host.rstrip("/")

    def _fetch(method, path, headers, params=None):
        url = host + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:   # nosemgrep: dynamic-urllib-use — administrator's import source, SSRF-checked by the caller
                body = r.read().decode("utf-8") or "{}"
                return r.status, _unwrap(json.loads(body))
        except urllib.error.HTTPError as e:
            try:
                return e.code, _unwrap(json.loads(e.read().decode("utf-8")))
            except Exception:
                return e.code, {}
        except urllib.error.URLError as e:
            raise ImportError_(f"cannot reach {host}: {e.reason}")

    def _unwrap(d):
        if isinstance(d, dict) and d.get("format") == "base64":
            return json.loads(_b64.b64decode(d.get("content", "")).decode("utf-8"))
        return d

    fetch = fetch or _fetch
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    b = _Builder("passwork", into_folder, "")

    def err(st, body, what):
        msgs = [e.get("message") or e.get("code") or "" for e in (body.get("errors") or [])] if isinstance(body, dict) else []
        if st == 403 and any("master" in m.lower() for m in msgs):
            raise ImportError_("this Passwork instance encrypts on the client — the master password (or master key) is required")
        if st == 401:
            raise ImportError_("token rejected by Passwork (HTTP 401)" + (f": {'; '.join(m for m in msgs if m)}" if msgs else ""))
        raise ImportError_(f"{what} → HTTP {st}" + (f": {'; '.join(m for m in msgs if m)}" if msgs else ""))

    # client-side encryption: derive / take the master key, fetch the user's RSA key
    private_pem = None
    if master_password or master_key:
        mk = master_key
        if not mk:
            st, opts = fetch("GET", "/api/v1/users/master-key/options", hdr)
            if st != 200 or not isinstance(opts, dict) or not opts.get("masterKeyOptions"):
                err(st, opts, "GET /api/v1/users/master-key/options")
            mk = pw_master_key_from_password(master_password, opts["masterKeyOptions"])
        hdr["X-Master-Key-Hash"] = hashlib.sha256(mk.encode()).hexdigest()
        st, keys = fetch("GET", "/api/v1/users/keys", hdr)
        if st != 200 or not isinstance(keys, dict) or not (keys.get("keys") or {}).get("privateEncrypted"):
            err(st, keys, "GET /api/v1/users/keys")
        try:
            private_pem = pw_decrypt_aes(keys["keys"]["privateEncrypted"], mk).decode("utf-8")
        except Exception:
            raise ImportError_("the master password / master key does not decrypt the user's private key — wrong master password?")

    # vault names (best effort) and folders (resolved lazily, cached)
    st, vaults = fetch("GET", "/api/v1/vaults", hdr)
    if st == 401 or st == 403:
        err(st, vaults, "GET /api/v1/vaults (token rejected)")
    vault_names: dict[str, str] = {}
    if st == 200:
        lst = vaults.get("items") if isinstance(vaults, dict) else vaults
        for v in lst or []:
            if isinstance(v, dict) and v.get("id"):
                vault_names[v["id"]] = v.get("name") or v["id"]
    folder_cache: dict[str, str] = {}

    def folder_path(fid: str, depth=0) -> str:
        if not fid or depth > 20:
            return ""
        if fid in folder_cache:
            return folder_cache[fid]
        st2, f = fetch("GET", f"/api/v1/folders/{fid}", hdr)
        if st2 != 200 or not isinstance(f, dict):
            folder_cache[fid] = ""; return ""
        parent = folder_path(f.get("parentId") or "", depth + 1)
        name = f.get("name") or ""
        folder_cache[fid] = f"{parent}/{name}".strip("/") if parent else name
        return folder_cache[fid]

    # items: search (all, or one vault), then each item in full
    params = {"vaultIds[]": [vault_id]} if vault_id else None
    st, found = fetch("GET", "/api/v1/items/search", hdr, params)
    if st != 200:
        err(st, found, "GET /api/v1/items/search")
    items = found.get("items") if isinstance(found, dict) else found
    items = [i for i in (items or []) if isinstance(i, dict) and i.get("id")]
    if len(items) > max_items:
        raise ImportError_(f"more than {max_items} items — import vault by vault")
    for brief in items:
        st, it = fetch("GET", f"/api/v1/items/{brief['id']}", hdr)
        if st == 403 and isinstance(it, dict) and any("master" in (e.get("message") or e.get("code") or "").lower() for e in (it.get("errors") or [])):
            err(st, it, f"GET /api/v1/items/{brief['id']}")
        if st != 200 or not isinstance(it, dict):
            b.skipped += 1; b.warnings.append(f"{brief.get('name') or brief['id']}: HTTP {st} on read — skipped"); continue
        try:
            item_key = ""
            if private_pem and it.get("keyEncrypted"):
                vmk = _pw_rsa_decrypt(it["vaultMasterKeyEncrypted"], private_pem).decode("utf-8")
                item_key = pw_decrypt_aes(it["keyEncrypted"], vmk).decode("utf-8")
            pwd_enc = it.get("passwordEncrypted") or ""
            if not pwd_enc:
                pwd = it.get("password") or ""
            elif item_key:
                pwd = pw_decrypt_aes(pwd_enc, item_key).decode("utf-8")
            else:
                pwd = _b64.b64decode(pwd_enc).decode("utf-8")       # encryption off: plain base64
            totp, extra = "", []
            for c in it.get("customs") or []:
                try:
                    cname = pw_decrypt_aes(c["name"], item_key).decode() if item_key else _b64.b64decode(c["name"]).decode()
                    ctype = pw_decrypt_aes(c["type"], item_key).decode() if item_key else _b64.b64decode(c["type"]).decode()
                    cval = pw_decrypt_aes(c["value"], item_key).decode() if item_key else _b64.b64decode(c["value"]).decode()
                except Exception:
                    extra.append("a custom field could not be decoded"); continue
                if ctype.lower() == "totp":
                    totp = totp or cval
                elif cname:
                    extra.append(f"{cname}: {cval}")
            for a in it.get("attachments") or []:
                if isinstance(a, dict) and a.get("name"):
                    extra.append(f"attachment (not imported): {a['name']}")
        except Exception as e:
            b.skipped += 1
            b.warnings.append(f"{it.get('name') or brief['id']}: cannot decrypt ({e.__class__.__name__}) — " + ("master password needed for this vault" if not private_pem else "key chain mismatch"))
            continue
        vname = vault_names.get(it.get("vaultId") or "", it.get("vaultId") or "Passwork")
        fpath = folder_path(it.get("folderId") or "")
        tags = it.get("tags") or []
        b.add(f"{vname}/{fpath}".strip("/") if fpath else vname, it.get("name") or "unnamed", pwd, login=it.get("login") or "",
              notes=it.get("description") or "", totp=totp, url=it.get("url") or "", tags=",".join(tags) if isinstance(tags, list) else str(tags),
              favorite=bool(it.get("isFavorite")), extra_note_lines=extra)
    return b.result()
