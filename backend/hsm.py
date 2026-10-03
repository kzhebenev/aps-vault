"""PKCS#11 master-key provider (v0.15): the master key wrapped by an AES key that lives inside
a hardware (or software) token and never leaves it.

With it the administrator unlocks with the token's PIN instead of the master password: the
vault asks the token to decrypt the cell, gets the master key for the request, opens a
session. A database dump is useless without the token even if the PIN is weak — brute force
runs into the token's own attempt counter, not ours.

Mechanism: CKM_AES_CBC_PAD with a random 16-byte IV (python-pkcs11 0.10 cannot pass AES-GCM
parameters — TypeError in its Cython layer — and CBC-PAD is supported by every AES-capable
module). Integrity does not come from the cipher: a tampered or foreign cell yields a wrong
master key, which fails the vault's AES-GCM verifier check before any session is opened.

Tested against SoftHSM2 (the OpenDNSSEC software token, PKCS#11 v2.40). Any module that
implements CKM_AES_CBC_PAD on a stored AES-256 key should work the same way — YubiHSM 2,
Nitrokey HSM, Utimaco, Rutoken HSM; those were not exercised here. Configuration:

    VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so   # the vendor's PKCS#11 library
    VAULT_PKCS11_TOKEN_LABEL=aps-vault                     # which token in the slot list
    VAULT_PKCS11_KEY_LABEL=aps-vault-master-wrap           # AES-256 key, created on first enable
    VAULT_PKCS11_PIN=…                                     # optional: lets the server use the
                                                           # token by itself (auto-unlock for SSO,
                                                           # re-wrap on password change)

The PIN entered at unlock is used for one PKCS#11 session and forgotten.
"""
from __future__ import annotations

import os
import threading

import settings

_lock = threading.Lock()
_lib = None
_lib_path = None
MECH = "CKM_AES_CBC_PAD"


class HsmError(Exception):
    pass


def configured() -> bool:
    return bool(settings.SETTINGS.pkcs11_module)


def _library():
    """Load the module once per process (PKCS#11 C_Initialize must happen once)."""
    global _lib, _lib_path
    import pkcs11
    path = settings.SETTINGS.pkcs11_module
    if not path or not os.path.exists(path):
        raise HsmError(f"PKCS#11 module not found: {path or '(VAULT_PKCS11_MODULE unset)'}")
    with _lock:
        if _lib is None or _lib_path != path:
            try:
                _lib = pkcs11.lib(path); _lib_path = path
            except Exception as e:          # the module itself may refuse to initialise (bad config, no slots)
                raise HsmError(f"PKCS#11 module failed to initialise: {e.__class__.__name__}: {str(e)[:80]}")
    return _lib


def _token():
    import pkcs11
    lib = _library()
    label = settings.SETTINGS.pkcs11_token_label
    try:
        return lib.get_token(token_label=label)
    except pkcs11.exceptions.NoSuchToken:
        raise HsmError(f"token '{label}' not found in {settings.SETTINGS.pkcs11_module}")
    except Exception as e:
        raise HsmError(f"PKCS#11: {e.__class__.__name__}: {str(e)[:80]}")


def _key(session, create: bool):
    import pkcs11
    label = settings.SETTINGS.pkcs11_key_label
    try:
        return session.get_key(label=label, object_class=pkcs11.ObjectClass.SECRET_KEY)
    except pkcs11.exceptions.NoSuchKey:
        if not create:
            raise HsmError(f"wrap key '{label}' not present in the token")
        return session.generate_key(pkcs11.KeyType.AES, 256, label=label, store=True,
                                    template={pkcs11.Attribute.EXTRACTABLE: False, pkcs11.Attribute.SENSITIVE: True,
                                              pkcs11.Attribute.ENCRYPT: True, pkcs11.Attribute.DECRYPT: True})


def _open(pin: str, rw: bool):
    import pkcs11
    try:
        return _token().open(user_pin=pin, rw=rw)
    except pkcs11.exceptions.PinIncorrect:
        raise HsmError("PIN incorrect")
    except pkcs11.exceptions.PinLocked:
        raise HsmError("PIN locked by the token")
    except pkcs11.exceptions.PKCS11Error as e:
        raise HsmError(f"PKCS#11: {e.__class__.__name__}")


def info() -> dict:
    """What the token says about itself (no PIN needed)."""
    t = _token()
    def s(v): return v.decode("utf-8", "replace").strip() if isinstance(v, (bytes, bytearray)) else str(v).strip()
    return {"label": s(t.label), "manufacturer": s(t.manufacturer_id), "model": s(t.model), "serial": s(t.serial)}


def wrap(master_key: bytes, pin: str) -> tuple[bytes, bytes]:
    """Encrypt the master key inside the token; (ciphertext+tag, iv). Creates the wrap key on
    first use (needs a read-write session)."""
    import pkcs11
    with _open(pin, rw=True) as s:
        key = _key(s, create=True)
        iv = s.generate_random(128)
        try:
            ct = key.encrypt(master_key, mechanism=pkcs11.Mechanism.AES_CBC_PAD, mechanism_param=iv)
        except pkcs11.exceptions.PKCS11Error as e:
            raise HsmError(f"token cannot {MECH}: {e.__class__.__name__}")
        return bytes(ct), bytes(iv)


def unwrap(cell: bytes, iv: bytes, pin: str) -> bytes:
    import pkcs11
    with _open(pin, rw=False) as s:
        key = _key(s, create=False)
        try:
            return bytes(key.decrypt(cell, mechanism=pkcs11.Mechanism.AES_CBC_PAD, mechanism_param=bytes(iv)))
        except pkcs11.exceptions.PKCS11Error as e:
            raise HsmError(f"cell does not open with this token/key: {e.__class__.__name__}")
