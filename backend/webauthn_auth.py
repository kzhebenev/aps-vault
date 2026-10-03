"""WebAuthn (security keys, Touch ID, Android biometrics) for the human unlock — v0.13.

Two modes, decided per credential at registration:

* **PRF unlock** — the authenticator supports the PRF / hmac-secret extension (YubiKey 5,
  Apple passkeys in Safari 18+, Android passkeys): at registration the browser hands us the
  PRF output for a fixed salt, we derive a wrap key with HKDF and store the master key wrapped
  under it next to the credential. Unlock = one touch: the browser presents the assertion and
  the PRF output, we verify the signature, unwrap the master key and open a session. The PRF
  output exists only in the authenticator and in transit over TLS; the database holds
  ciphertext. No master password involved.
* **Second factor** — no PRF: the credential proves possession; the master password is still
  typed. Enabled with the `webauthn_second_factor` switch: password unlock then also needs an
  assertion.

Challenges live in the database (replicas share them); each is single-use and short-lived.
The relying party id is the host of VAULT_PUBLIC_URL; WebAuthn refuses IP addresses, so a
deployment reached by IP cannot use this (localhost works).
"""
from __future__ import annotations

import base64
import json
import secrets as pysecrets
from datetime import timedelta
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

import crypto
import db
import settings

CHALLENGE_TTL_SEC = 180
_PRF_INFO = b"aps-vault/webauthn-prf/master-key-wrap/v1"
PRF_SALT = b"aps-vault-prf-salt-v1" + b"\x00" * 11   # fixed 32-byte eval input; the per-key secret is in the authenticator


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rp() -> tuple[str, str]:
    """(rp_id, origin) from VAULT_PUBLIC_URL."""
    url = settings.SETTINGS.public_url or "http://localhost"
    u = urlparse(url)
    host = u.hostname or "localhost"
    return host, f"{u.scheme}://{u.netloc}"


def _now():
    return db.utcnow().replace(tzinfo=None)


def _store_challenge(kind: str, challenge: bytes, data: dict | None = None) -> None:
    with db.get_session() as s:
        s.query(db.WebauthnChallenge).filter(db.WebauthnChallenge.expires_at < _now()).delete()
        s.add(db.WebauthnChallenge(challenge=b64u(challenge), kind=kind, data=json.dumps(data or {}),
                                   expires_at=_now() + timedelta(seconds=CHALLENGE_TTL_SEC)))
        s.commit()


def _take_challenge(kind: str, client_data_json_b64: str) -> tuple[bytes, dict]:
    """Single use: the challenge inside clientDataJSON must be one we issued and not expired."""
    try:
        cd = json.loads(b64u_dec(client_data_json_b64))
        ch = cd["challenge"]
    except Exception:
        raise ValueError("malformed clientDataJSON")
    with db.get_session() as s:
        row = s.query(db.WebauthnChallenge).filter_by(challenge=ch, kind=kind).first()
        if not row or row.expires_at < _now():
            raise ValueError("unknown or expired challenge")
        data = json.loads(row.data or "{}")
        s.delete(row); s.commit()
    return b64u_dec(ch), data


def prf_wrap_key(prf_output: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_PRF_INFO).derive(prf_output)


# ── registration ─────────────────────────────────────────────────────────────
def registration_options(name: str) -> dict:
    rp_id, _ = rp()
    with db.get_session() as s:
        existing = [PublicKeyCredentialDescriptor(id=bytes(c.credential_id)) for c in s.query(db.WebauthnCredential).all()]
    opts = generate_registration_options(
        rp_id=rp_id, rp_name="APS Vault", user_id=b"aps-vault-admin", user_name="admin", user_display_name="APS Vault administrator",
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                               user_verification=UserVerificationRequirement.PREFERRED),
        exclude_credentials=existing, timeout=120000,
    )
    _store_challenge("register", opts.challenge, {"name": name})
    j = json.loads(options_to_json(opts))
    j["extensions"] = {"prf": {"eval": {"first": b64u(PRF_SALT)}}}   # ask for a PRF output right away
    return j


def registration_finish(credential: dict, name: str, master_key: bytes, prf_output_b64: str | None, transports: list[str] | None) -> dict:
    rp_id, origin = rp()
    challenge, data = _take_challenge("register", credential["response"]["clientDataJSON"])
    v = verify_registration_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                     expected_origin=origin, require_user_verification=False)
    enc, nonce = b"", b""
    prf = bool(prf_output_b64)
    if prf:
        out = b64u_dec(prf_output_b64)
        if len(out) < 32:
            raise ValueError("PRF output too short")
        enc, nonce = crypto.encrypt(prf_wrap_key(out), master_key)
    with db.get_session() as s:
        c = db.WebauthnCredential(name=(name or data.get("name") or "security key")[:64], credential_id=v.credential_id,
                                  public_key=v.credential_public_key, sign_count=v.sign_count,
                                  transports=",".join(transports or []), prf_master_enc=enc, prf_master_nonce=nonce)
        s.add(c); s.commit(); s.refresh(c)
        return {"id": c.id, "name": c.name, "prf": prf}


# ── authentication ───────────────────────────────────────────────────────────
def authentication_options(purpose: str = "unlock") -> dict:
    """`purpose`: unlock (PRF credentials, touch-to-unlock) or second_factor (any credential)."""
    rp_id, _ = rp()
    with db.get_session() as s:
        creds = s.query(db.WebauthnCredential).all()
        if purpose == "unlock":
            creds = [c for c in creds if c.prf_master_enc]
        allow = [PublicKeyCredentialDescriptor(id=bytes(c.credential_id)) for c in creds]
    if not allow:
        raise LookupError("no registered security key for this purpose")
    opts = generate_authentication_options(rp_id=rp_id, allow_credentials=allow, timeout=120000,
                                           user_verification=UserVerificationRequirement.PREFERRED)
    _store_challenge(purpose, opts.challenge)
    j = json.loads(options_to_json(opts))
    if purpose == "unlock":
        j["extensions"] = {"prf": {"eval": {"first": b64u(PRF_SALT)}}}
    return j


def verify_assertion(credential: dict, purpose: str):
    """Returns the credential row after a valid assertion (sign count updated)."""
    rp_id, origin = rp()
    challenge, _ = _take_challenge(purpose, credential["response"]["clientDataJSON"])
    cred_id = b64u_dec(credential["rawId"] if "rawId" in credential else credential["id"])
    with db.get_session() as s:
        c = s.query(db.WebauthnCredential).filter_by(credential_id=cred_id).first()
        if not c:
            raise LookupError("unknown credential")
        v = verify_authentication_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                           expected_origin=origin, credential_public_key=bytes(c.public_key),
                                           credential_current_sign_count=c.sign_count or 0, require_user_verification=False)
        c.sign_count = v.new_sign_count; c.last_used = _now(); s.commit()
        s.refresh(s.merge(c)); s.expunge_all()
        return c


def unlock_master_key(cred, prf_output_b64: str) -> bytes:
    if not cred.prf_master_enc:
        raise LookupError("this security key has no PRF cell — use it as a second factor")
    out = b64u_dec(prf_output_b64 or "")
    if len(out) < 32:
        raise ValueError("PRF output missing")
    return crypto.decrypt(prf_wrap_key(out), bytes(cred.prf_master_enc), bytes(cred.prf_master_nonce))


def rewrap_all(old_master_key: bytes, new_master_key: bytes) -> None:
    """Password change / recovery: the PRF cells wrapped the OLD master key. We cannot re-wrap
    without the PRF output, so cells are re-encrypted by first unwrapping... which also needs
    the output. Therefore they are dropped and the UI asks to re-register keys."""
    with db.get_session() as s:
        for c in s.query(db.WebauthnCredential).all():
            c.prf_master_enc, c.prf_master_nonce = b"", b""
        s.commit()


def list_credentials() -> list[dict]:
    with db.get_session() as s:
        return [{"id": c.id, "name": c.name, "prf": bool(c.prf_master_enc), "transports": c.transports or "",
                 "created_at": c.created_at.isoformat() if c.created_at else "", "last_used": c.last_used.isoformat() if c.last_used else None}
                for c in s.query(db.WebauthnCredential).order_by(db.WebauthnCredential.created_at).all()]
