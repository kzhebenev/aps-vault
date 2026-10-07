"""Named users with per-folder roles (0.20).

Until 0.19 the vault had one human identity — whoever knows the master password (the
*owner*). Teams need people: a developer who may read one folder, an operator who may write
another, a team lead who issues tokens. This module adds them without touching the owner's
model and without a second copy of any folder key in plaintext:

* every user has a **key pair** (X25519 in the aes suite, GOST R 34.10-2012 in the gost suite);
  the private key is stored wrapped under Argon2id(user password), the public key in clear;
* a **grant** gives one user one role on one folder and carries that folder's key encrypted
  to the user's public key (ephemeral key agreement → KDF → AEAD, the same construction as
  sealed delivery). The owner — who holds the master key and therefore every folder key —
  creates grants; the user opens them with the private key that only their password unwraps;
* **roles** per folder: `reader` (read values, TOTP, history), `writer` (+ create / update /
  delete / rotate / move), `manager` (+ issue and revoke tokens, share links). Everything else
  — users, folders, settings, cells, webhooks, export, audit — stays with the owner;
* a user's **session** carries the private key wrapped under the cookie, exactly as the
  owner's session carries the master key; the request-scoped identity decides how a folder
  key is obtained;
* **invitations**: the owner creates a user and gets a one-time link; the private key is
  wrapped under the invite token until the user sets a password. Re-inviting regenerates the
  key pair and re-creates the grants (the owner can, having the master key); deactivating
  revokes the user's sessions and grants.

Revoking a grant does not rotate the folder key: the user can no longer reach the database,
and the key never left the server unwrapped. Rotating folder keys is a separate operation.
"""
from __future__ import annotations

import base64
import os
import secrets as pysecrets
from datetime import timedelta

import crypto
import db
import suite

ROLES = ("reader", "writer", "manager")
_RANK = {r: i for i, r in enumerate(ROLES)}
_GRANT_INFO = b"aps-vault/user-grant/v1"
INVITE_TTL_SEC = 7 * 24 * 3600


class UserError(Exception):
    pass


def role_at_least(have: str | None, need: str) -> bool:
    return have is not None and _RANK.get(have, -1) >= _RANK[need]


# ── key pairs and asymmetric wrapping (suite-dependent) ──────────────────────
def generate_keypair() -> tuple[bytes, bytes]:
    """(private, public) raw bytes for the active suite."""
    if suite.active() == suite.GOST:
        import gostec
        return gostec.generate_keypair()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    sk = X25519PrivateKey.generate()
    return (sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def wrap_for(public: bytes, data: bytes) -> bytes:
    """Encrypt `data` to a user's public key: ephemeral agreement → suite.kdf → suite AEAD.
    Blob = epk ‖ [ukm] ‖ nonce ‖ ct."""
    if suite.active() == suite.GOST:
        import gost
        import gostec
        peer = gostec.decode_point(public)
        d = gostec.generate_private()
        epk = gostec.encode_point(gostec.public_from_private(d))
        ukm = os.urandom(8)
        if ukm == b"\x00" * 8:
            ukm = b"\x01" + ukm[1:]
        key = gost.kdf_tree_256(gostec.vko(d, peer, ukm), _GRANT_INFO, epk + public, 1)
        ct, nonce = suite.aead_encrypt(key, data, _GRANT_INFO)
        return epk + ukm + nonce + ct
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = esk.exchange(X25519PublicKey.from_public_bytes(public))
    key = suite.kdf(shared, _GRANT_INFO + epk + public)
    ct, nonce = suite.aead_encrypt(key, data, _GRANT_INFO)
    return epk + nonce + ct


def unwrap_for(private: bytes, public: bytes, blob: bytes) -> bytes:
    if suite.active() == suite.GOST:
        import gost
        import gostec
        epk, ukm, nonce, ct = blob[:64], blob[64:72], blob[72:88], blob[88:]
        d = int.from_bytes(private, "big")
        key = gost.kdf_tree_256(gostec.vko(d, gostec.decode_point(epk), ukm), _GRANT_INFO, epk + public, 1)
        return suite.aead_decrypt(key, ct, nonce, _GRANT_INFO)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    epk, nonce, ct = blob[:32], blob[32:44], blob[44:]
    shared = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(epk))
    key = suite.kdf(shared, _GRANT_INFO + epk + public)
    return suite.aead_decrypt(key, ct, nonce, _GRANT_INFO)


# ── SSO cell (0.23): the private key under HKDF(VAULT_SSO_UNLOCK_KEY, user) so an OIDC login can open a user session ──
def _sso_key(user_id: int) -> bytes | None:
    import settings
    k = settings.SETTINGS.sso_unlock_key
    return suite.kdf(k, b"aps-vault/user-sso-cell/v1", str(user_id).encode()) if k else None


def _sso_cell_refresh(u, private: bytes) -> None:
    k = _sso_key(u.id)
    if k:
        u.sso_private_enc, u.sso_private_nonce = crypto.encrypt(k, private)


def sso_open(email: str) -> tuple | None:
    """(user, private key) for an OIDC-verified e-mail when the user has an SSO cell and the server key is set."""
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email=email.strip().lower()).first()
        if not u or not u.is_active or not u.sso_private_enc:
            return None
        k = _sso_key(u.id)
        if not k:
            return None
        try:
            priv = crypto.decrypt(k, u.sso_private_enc, u.sso_private_nonce)
        except Exception:
            return None
        u.last_login = _now(); s.commit(); s.refresh(u); s.expunge(u)
        return u, priv


def exists_active(email: str) -> bool:
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email=email.strip().lower()).first()
        return bool(u and u.is_active)


def role_on(user_id: int, folder_id: int) -> str | None:
    with db.get_session() as s:
        g = s.query(db.FolderGrant).filter_by(user_id=user_id, folder_id=folder_id).first()
        return g.role if g else None


def exists_any(email: str) -> bool:
    """0.37: a user record with this e-mail exists, active or not — such an e-mail is never the owner over SSO."""
    with db.get_session() as s:
        return s.query(db.User).filter_by(email=email.strip().lower()).first() is not None


# ── users ────────────────────────────────────────────────────────────────────
def _now():
    return db.utcnow().replace(tzinfo=None)


def _hash(token: str) -> str:
    return suite.hexdigest(("invite:" + token).encode("utf-8"))


def create(email: str, name: str) -> tuple[db.User, str]:
    """New user with a fresh key pair; returns (row, invite token). The private key is wrapped
    under the invite token until the user sets a password."""
    email = email.strip().lower()
    if not email or "@" not in email:
        raise UserError("a valid e-mail is required")
    with db.get_session() as s:
        if s.query(db.User).filter_by(email=email).first():
            raise UserError("a user with this e-mail already exists")
        priv, pub = generate_keypair()
        invite = pysecrets.token_urlsafe(32)
        salt = pysecrets.token_bytes(32)
        enc, nonce = crypto.encrypt(crypto.derive_key(invite, salt), priv)
        u = db.User(email=email, name=(name or "").strip()[:128], public_key=pub, private_key_enc=enc, private_key_nonce=nonce,
                    pw_salt=salt, has_password=False, is_active=True, invite_hash=_hash(invite),
                    invite_expires=_now() + timedelta(seconds=INVITE_TTL_SEC))
        s.add(u); s.commit(); s.refresh(u); s.expunge(u)
        return u, invite


def reinvite(user_id: int, master_key: bytes) -> str:
    """Password reset: new key pair wrapped under a new invite, every grant re-created from
    the folder keys the owner can open. Live sessions of the user are revoked."""
    import sessions
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        if not u:
            raise UserError("user not found")
        priv, pub = generate_keypair()
        invite = pysecrets.token_urlsafe(32)
        salt = pysecrets.token_bytes(32)
        u.private_key_enc, u.private_key_nonce = crypto.encrypt(crypto.derive_key(invite, salt), priv)
        u.pw_salt, u.public_key, u.has_password = salt, pub, False
        u.invite_hash, u.invite_expires = _hash(invite), _now() + timedelta(seconds=INVITE_TTL_SEC)
        u.sso_private_enc, u.sso_private_nonce, u.webauthn_second_factor = b"", b"", False
        u.totp_secret_enc, u.totp_secret_nonce = b"", b""        # 0.30: the seed was under the old private key
        for g in s.query(db.FolderGrant).filter_by(user_id=user_id).all():
            f = s.get(db.Folder, g.folder_id)
            fk = crypto.decrypt(master_key, f.scope_key_enc, f.scope_key_nonce)
            g.folder_key_blob = wrap_for(pub, fk)
        s.commit()
    sessions.revoke_user(user_id)
    import webauthn_auth
    webauthn_auth.drop_user_credentials(user_id)          # the key pair changed: old PRF cells are dead
    return invite


def invite_info(token: str) -> db.User | None:
    with db.get_session() as s:
        u = s.query(db.User).filter_by(invite_hash=_hash(token)).first()
        if not u or not u.is_active or not u.invite_expires or u.invite_expires < _now():
            return None
        s.expunge(u)
        return u


def accept_invite(token: str, password: str) -> db.User:
    """The user sets a password: the private key moves from the invite wrap to the password wrap."""
    if len(password) < 12:
        raise UserError("password must be at least 12 characters")
    with db.get_session() as s:
        u = s.query(db.User).filter_by(invite_hash=_hash(token)).first()
        if not u or not u.is_active or not u.invite_expires or u.invite_expires < _now():
            raise UserError("invitation is unknown, used or expired")
        priv = crypto.decrypt(crypto.derive_key(token, u.pw_salt), u.private_key_enc, u.private_key_nonce)
        salt = pysecrets.token_bytes(32)
        u.private_key_enc, u.private_key_nonce = crypto.encrypt(crypto.derive_key(password, salt), priv)
        u.pw_salt, u.has_password, u.invite_hash, u.invite_expires = salt, True, "", None
        _sso_cell_refresh(u, priv)
        s.commit(); s.refresh(u); s.expunge(u)
        return u


def authenticate(email: str, password: str) -> tuple[db.User, bytes] | None:
    """(user, private key) when the password unwraps the private key; None otherwise."""
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email=email.strip().lower()).first()
        if not u or not u.is_active or not u.has_password:
            crypto.derive_key(password, b"\x00" * 32)    # 0.37: same Argon2 cost for unknown e-mails — no timing oracle
            return None
        try:
            priv = crypto.decrypt(crypto.derive_key(password, u.pw_salt), u.private_key_enc, u.private_key_nonce)
        except Exception:
            return None
        if not u.sso_private_enc:
            _sso_cell_refresh(u, priv)          # a server SSO key configured after the password was set
        u.last_login = _now(); s.commit(); s.refresh(u); s.expunge(u)
        return u, priv


def change_password(user_id: int, private: bytes, current: str, new: str) -> None:
    if len(new) < 12:
        raise UserError("password must be at least 12 characters")
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        try:
            crypto.decrypt(crypto.derive_key(current, u.pw_salt), u.private_key_enc, u.private_key_nonce)
        except Exception:
            raise UserError("current password is wrong")
        salt = pysecrets.token_bytes(32)
        u.private_key_enc, u.private_key_nonce = crypto.encrypt(crypto.derive_key(new, salt), private)
        u.pw_salt = salt
        _sso_cell_refresh(u, private)
        s.commit()


def set_second_factor(user_id: int, enabled: bool) -> None:
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        u.webauthn_second_factor = enabled
        s.commit()


def second_factor_required(email: str) -> bool:
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email=email.strip().lower()).first()
        return bool(u and u.is_active and u.webauthn_second_factor)


def by_email(email: str):
    with db.get_session() as s:
        u = s.query(db.User).filter_by(email=email.strip().lower()).first()
        if u:
            s.expunge(u)
        return u


def by_id(user_id: int):
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        if u:
            s.expunge(u)
        return u


def deactivate(user_id: int) -> None:
    import sessions
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        if not u:
            raise UserError("user not found")
        u.is_active, u.invite_hash, u.invite_expires = False, "", None
        u.sso_private_enc, u.sso_private_nonce = b"", b""
        s.query(db.FolderGrant).filter_by(user_id=user_id).delete()
        # 0.37: machine access this person handed out goes with them — their tokens and unused enrolment codes
        s.query(db.ServiceToken).filter_by(created_by=u.email, revoked=False).update({"revoked": True}, synchronize_session=False)
        s.query(db.Enrollment).filter_by(created_by=u.email, revoked=False).update(
            {"revoked": True, "folder_key_enc": b"", "folder_key_nonce": b""}, synchronize_session=False)
        s.commit()
    sessions.revoke_user(user_id)
    import webauthn_auth
    webauthn_auth.drop_user_credentials(user_id)


# ── grants ───────────────────────────────────────────────────────────────────
def set_grant(user_id: int, folder_id: int, role: str, master_key: bytes | None = None, folder_key: bytes | None = None) -> None:
    """Wrap the folder key to the user's public key. The owner passes the master key (0.20); a folder
    manager passes the folder key they already hold (0.30) — the result is the same grant row."""
    if role not in ROLES:
        raise UserError(f"role must be one of {', '.join(ROLES)}")
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        f = s.get(db.Folder, folder_id)
        if not u or not u.is_active:
            raise UserError("user not found or deactivated")
        if not f:
            raise UserError("folder not found")
        if folder_key is None:
            if master_key is None:
                raise UserError("no key to wrap the grant with")
            folder_key = crypto.decrypt(master_key, f.scope_key_enc, f.scope_key_nonce)
        fk = folder_key
        g = s.query(db.FolderGrant).filter_by(user_id=user_id, folder_id=folder_id).first()
        if g is None:
            g = db.FolderGrant(user_id=user_id, folder_id=folder_id)
            s.add(g)
        g.role = role
        g.folder_key_blob = wrap_for(bytes(u.public_key), fk)
        s.commit()


def remove_grant(user_id: int, folder_id: int) -> bool:
    with db.get_session() as s:
        n = s.query(db.FolderGrant).filter_by(user_id=user_id, folder_id=folder_id).delete()
        s.commit()
        return n > 0


# ── TOTP second factor (0.30): seed under KDF(private key) — verifiable only after the password opened the key ──
_TOTP_INFO = b"aps-vault/user-totp/v1"


def _totp_key(private: bytes) -> bytes:
    return suite.kdf(private, _TOTP_INFO)


def totp_enabled(user_id: int) -> bool:
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        return bool(u and u.totp_secret_enc)


def totp_set(user_id: int, private: bytes, secret_base32: str) -> None:
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        if u.totp_secret_enc:
            raise UserError("TOTP is already enabled; disable it first")
        u.totp_secret_enc, u.totp_secret_nonce = crypto.encrypt(_totp_key(private), secret_base32.encode("utf-8"))
        s.commit()


def totp_secret(u, private: bytes) -> str | None:
    if not u.totp_secret_enc:
        return None
    try:
        return crypto.decrypt(_totp_key(private), u.totp_secret_enc, u.totp_secret_nonce).decode("utf-8")
    except Exception:
        return None


def totp_clear(user_id: int) -> None:
    with db.get_session() as s:
        u = s.get(db.User, user_id)
        u.totp_secret_enc, u.totp_secret_nonce = b"", b""
        s.commit()


def grants_of(user_id: int) -> dict[int, str]:
    with db.get_session() as s:
        return {g.folder_id: g.role for g in s.query(db.FolderGrant).filter_by(user_id=user_id).all()}


def folder_key(user_id: int, folder_id: int, private: bytes) -> tuple[bytes, str] | None:
    """(folder key, role) for a user on a folder, or None when there is no grant."""
    with db.get_session() as s:
        g = s.query(db.FolderGrant).filter_by(user_id=user_id, folder_id=folder_id).first()
        if not g:
            return None
        u = s.get(db.User, user_id)
        return unwrap_for(private, bytes(u.public_key), bytes(g.folder_key_blob)), g.role


def list_users() -> list[dict]:
    with db.get_session() as s:
        rows = s.query(db.User).order_by(db.User.email).all()
        grants = s.query(db.FolderGrant, db.Folder).join(db.Folder, db.Folder.id == db.FolderGrant.folder_id).all()
        by_user: dict[int, list] = {}
        for g, f in grants:
            by_user.setdefault(g.user_id, []).append({"folder_id": f.id, "folder_name": f.name, "role": g.role})
        return [{"id": u.id, "email": u.email, "name": u.name or "", "is_active": bool(u.is_active),
                 "has_password": bool(u.has_password), "invite_pending": bool(u.invite_hash) and bool(u.invite_expires and u.invite_expires >= _now()),
                 "created_at": u.created_at.isoformat() if u.created_at else "", "last_login": u.last_login.isoformat() if u.last_login else None,
                 "grants": sorted(by_user.get(u.id, []), key=lambda x: x["folder_name"]),
                 "public_key": base64.b64encode(bytes(u.public_key)).decode()} for u in rows]
