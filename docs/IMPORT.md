# Import from other managers (0.29)

Settings → *Import from another manager*. Pick the source, drop the export file (or enter the
address of a HashiCorp Vault), press **Preview**, read what would be created, press **Import**.
Nothing is written before the preview is confirmed; the file is parsed on the server inside your
session and is not stored.

| source | what to export | how it maps |
|---|---|---|
| **Bitwarden / Vaultwarden** | *Export vault → .json* (unencrypted; the encrypted `.json` is refused with a clear message) | folders and collections → folders; login → value = password, login = username, first URI → URL, other URIs and custom fields → notes, `totp` → TOTP seed; secure note → the note **is** the value; card → number is the value, holder/expiry/CVV in the notes (tag `card`); identity → fields in the notes (tag `identity`); trashed items skipped; favourites kept |
| **KeePass 2.x** | *File → Export → KeePass XML (2.x)* | groups → folders (`Servers/Backup`); Title, UserName, Password, URL, Notes; `otp` / `TimeOtp-Secret-Base32` → TOTP; other string fields → notes; Tags; Recycle Bin skipped. The `.kdbx` itself is not read — export the XML and delete it after the import |
| **1Password** | *Export → CSV* (1Password 8) or *.1pux* | Title, Url, Username, Password, OTPAuth, Favorite, Tags, Notes; archived skipped. 1PUX: vaults → folders, login fields, `totp` section fields, other section fields → notes |
| **LastPass** | *Advanced → Export → CSV* | `grouping` → folder (`Personal/Web`), name, username, password, totp, extra → notes, url (the `http://sn` of secure notes is dropped — the note is the value), fav |
| **Any CSV** | a header row | columns recognised: `name`/`title`, `value`/`password`/`secret`, `login`/`username`/`user`/`email`, `notes`/`comment`/`extra`, `url`/`website`, `tags`, `totp`/`otpauth`, `folder`/`group`/`category`/`vault`; `,` `;` or tab |
| **.env** | the file itself | `KEY=VALUE` → one secret per key, quotes and `export` handled, comments skipped; the folder is the file name |
| **APS Vault** | *Settings → Export JSON* of another instance | one to one |
| **Passwork** (7+) | an export file (JSON or CSV, English or Russian headers), or the live API: host, an *access token* from the Passwork profile and — when the installation encrypts on the client — the **master password** (or the master key) | vaults and folders → folders (`Ops/CI/GitLab`); name, login, password, url, description → notes, tags, favourite; custom field of type `totp` → TOTP, other custom fields → notes; attachments are noted by name, not imported. Over the API the vault **decrypts here** exactly as the official connector does (master password → PBKDF2 → the user's RSA key → the vault's key → the item's key → the password); Passwork never sees the values, and token and master password are not stored. A file whose passwords are client-side encrypted cannot be read — use the API import |
| **HashiCorp Vault / Deckhouse Stronghold** | address, a token with `list` on `<mount>/metadata/*` and `read` on `<mount>/data/*`, the KV v2 mount, optionally a sub-path | the mount → folder, the path → name; `value`/`password`/`secret`/`token`/`key` → value, `username`/`user`/`login` → login, `notes`, `totp`, `url`, `tags`; a map with one key → that key is the value; anything else → the whole map as JSON with a note. The token is used for the calls and forgotten |

**Where it goes.** *Folders as in the source* (optionally under a prefix such as `bw/`) or
*everything into one folder* you name. Items the source leaves without a folder land in
`import-<format>`.

**Names that already exist.** *Skip* (default) — the existing secret stays; *write as a new
version* — the old value goes to the history (`changed_by: master:import`) and the imported one
becomes current; *add with a suffix* — `name (2)`. Duplicates *inside* the import are always
suffixed, so nothing is silently lost.

**TOTP.** An `otpauth://` URL is reduced to its `secret`; a raw base32 seed is kept; Steam Guard
codes and anything that is not base32 are kept in the notes with a warning in the preview.

**Limits.** 20 MB per file, 20 000 items per import (split larger exports; a HashiCorp mount can be
imported path by path). Import is the owner's operation; named users get 403.

**After the import.** Delete the export file — it is the plaintext of your old manager. Rotate what
you can (`docs/ROTATION.md`); the vault's history keeps the imported value as version 1.

## Verified

`backend/tests/test_import.py`: a Bitwarden export with folders, favourites, custom fields, two URIs, a
secure note, a card, a trashed item, a duplicate name and three kinds of TOTP (otpauth, Steam, garbage);
a KeePass XML with nested groups, extra fields, tags and a Recycle Bin; 1Password CSV and a 1PUX zip
with sections; LastPass with a secure note; a semicolon CSV with mapped columns; an `.env` with quotes,
`export`, a comment and a bad line; refusals (encrypted Bitwarden, unknown JSON, binary, CSV without
columns, wrong format, a named user); the three conflict modes with the history checked; and a live
HashiCorp KV v2 pull through this vault's own facade (LIST + GET over HTTP), including permission
denied, a missing mount and the private-address guard. Passwork: JSON and Russian CSV exports, and the live
API against an emulator built from the official connector's code (`passwork-europe/passwork-python`) with
client-side encryption on (right and wrong master password, master key given directly) and off — the
custom base32, the OpenSSL `Salted__` AES-CBC and the PBKDF2 master key are reproduced and unit-tested.
**A real Passwork instance was not available**; the wire format follows the connector, the server's
answers are emulated. The browser check imports a Bitwarden file
from the settings page and opens an imported secret with its login and TOTP.
