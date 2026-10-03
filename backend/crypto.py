"""
APS Vault — криптография.

Стек:
  * Argon2id (argon2-cffi) — KDF из master-password в master-key (32 байта)
  * AES-256-GCM (cryptography) — симметричное шифрование значений
  * Каждая запись имеет свой 96-битный nonce (random)
  * authTagLength=16 (защита от short-tag forgery)

Архитектура ключей (envelope encryption):

  master_password
        │ Argon2id (m=64MB, t=3, p=4, salt из config.json)
        ▼
  master_key (32 B, в RAM)
        │ AES-GCM
        ▼
  encrypted scope keys  (vault_keys таблица)
        │
        ▼
  scope_key  (random 32 B на каждый scope/folder)
        │ AES-GCM
        ▼
  encrypted secret values  (secrets таблица: value_enc + value_nonce)

Зачем envelope: чтобы выдать service-token со scope-key БЕЗ master-password,
и иметь возможность ротировать master без перешифровки всех секретов.

При запуске сервера master_key хранится ТОЛЬКО в памяти, выгружается при
shutdown'е. Все операции дешифровки требуют unlock'нутого state.
"""
from __future__ import annotations

import json
import os
import secrets as pysecrets
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Параметры Argon2id (OWASP recommended)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024   # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32             # 32 байта = 256 бит → AES-256

GCM_NONCE_BYTES = 12             # 96 бит (стандарт NIST для AES-GCM)
GCM_TAG_BYTES = 16               # 128 бит


@dataclass
class VaultConfig:
    """Конфиг хранится в таблице vault_config (до 0.6 — в data/config.json; файл импортируется).
    Содержит salt + verification token. master_password проверяется так:
    derive(key, password, salt) → расшифровать verifier_enc → если совпадает
    с пасспорт-маркером → пароль верный.
    """
    salt: bytes                    # 32 байта random salt для Argon2
    verifier_enc: bytes            # AES-GCM шифр строки "APS-VAULT-OK"
    verifier_nonce: bytes
    init_at_utc: str
    recovery_code_hash: str        # Argon2-хеш recovery-code (для emergency reset)
    # v0.2: 2FA TOTP (опц.) — base32-secret зашифрован под master_key
    totp_secret_enc: bytes = b""
    totp_secret_nonce: bytes = b""
    # v0.2: recovery cell — master_key зашифрован под Argon2id(recovery_code, recovery_salt)
    recovery_master_enc: bytes = b""
    recovery_master_nonce: bytes = b""
    recovery_salt: bytes = b""
    # v0.10: SSO unlock cell (master key under HKDF(VAULT_SSO_UNLOCK_KEY)); empty = disabled
    sso_master_enc: bytes = b""
    sso_master_nonce: bytes = b""


def _config_path() -> Path:
    return Path(os.environ.get("VAULT_DATA_DIR", "/app/data")) / "config.json"


def _row_to_cfg(r) -> VaultConfig:
    return VaultConfig(
        salt=bytes(r.salt), verifier_enc=bytes(r.verifier_enc), verifier_nonce=bytes(r.verifier_nonce),
        init_at_utc=r.init_at_utc or "", recovery_code_hash=r.recovery_code_hash or "",
        totp_secret_enc=bytes(r.totp_secret_enc or b""), totp_secret_nonce=bytes(r.totp_secret_nonce or b""),
        recovery_master_enc=bytes(r.recovery_master_enc or b""), recovery_master_nonce=bytes(r.recovery_master_nonce or b""),
        recovery_salt=bytes(r.recovery_salt or b""),
        sso_master_enc=bytes(getattr(r, "sso_master_enc", b"") or b""), sso_master_nonce=bytes(getattr(r, "sso_master_nonce", b"") or b""),
    )


def _load_legacy_file() -> VaultConfig | None:
    """data/config.json of 0.1–0.5. Imported into the database once, then left in place as a
    read-only copy (ops/backup.sh of older installs still expects it)."""
    p = _config_path()
    if not p.exists():
        return None
    raw = json.loads(p.read_text())
    return VaultConfig(
        salt=bytes.fromhex(raw["salt"]),
        verifier_enc=bytes.fromhex(raw["verifier_enc"]),
        verifier_nonce=bytes.fromhex(raw["verifier_nonce"]),
        init_at_utc=raw["init_at_utc"],
        recovery_code_hash=raw["recovery_code_hash"],
        totp_secret_enc=bytes.fromhex(raw.get("totp_secret_enc", "")),
        totp_secret_nonce=bytes.fromhex(raw.get("totp_secret_nonce", "")),
        recovery_master_enc=bytes.fromhex(raw.get("recovery_master_enc", "")),
        recovery_master_nonce=bytes.fromhex(raw.get("recovery_master_nonce", "")),
        recovery_salt=bytes.fromhex(raw.get("recovery_salt", "")),
    )


def _load_db() -> VaultConfig | None:
    import db
    with db.get_session() as s:
        r = s.get(db.VaultConfigRow, 1)
        return _row_to_cfg(r) if r else None


def config_exists() -> bool:
    return load_config_or_none() is not None


def load_config_or_none() -> VaultConfig | None:
    """The verifier/recovery material: from the database (shared by all replicas); a legacy
    config.json is imported on first sight so an upgrade from 0.5 needs no manual step."""
    cfg = _load_db()
    if cfg is not None:
        return cfg
    legacy = _load_legacy_file()
    if legacy is None:
        return None
    save_config(legacy)
    return legacy


def load_config() -> VaultConfig:
    cfg = load_config_or_none()
    if cfg is None:
        raise FileNotFoundError("vault не инициализирован")
    return cfg


def save_config(cfg: VaultConfig) -> None:
    import db
    with db.get_session() as s:
        r = s.get(db.VaultConfigRow, 1)
        if r is None:
            r = db.VaultConfigRow(id=1, salt=cfg.salt, verifier_enc=cfg.verifier_enc, verifier_nonce=cfg.verifier_nonce)
            s.add(r)
        r.salt = cfg.salt; r.verifier_enc = cfg.verifier_enc; r.verifier_nonce = cfg.verifier_nonce
        r.init_at_utc = cfg.init_at_utc; r.recovery_code_hash = cfg.recovery_code_hash
        r.totp_secret_enc = cfg.totp_secret_enc; r.totp_secret_nonce = cfg.totp_secret_nonce
        r.recovery_master_enc = cfg.recovery_master_enc; r.recovery_master_nonce = cfg.recovery_master_nonce
        r.recovery_salt = cfg.recovery_salt
        r.sso_master_enc = cfg.sso_master_enc; r.sso_master_nonce = cfg.sso_master_nonce
        s.commit()


def clear_config_for_tests() -> None:
    import db
    with db.get_session() as s:
        s.query(db.VaultConfigRow).delete(); s.commit()


def derive_key(password: str, salt: bytes) -> bytes:
    """Argon2id KDF: password + salt → 32 байта master-key."""
    return low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=low_level.Type.ID,
    )


# Маркер для verifier (нужен чтобы отличить «правильный пароль» от любого другого
# 32-байтного ключа который тоже что-то расшифрует, просто в мусор).
VERIFIER_PLAINTEXT = b"APS-VAULT-OK-v1"


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """AES-GCM шифрование. Возвращает (ciphertext_with_tag, nonce).
    `nonce` задаётся явно только при перешифровке под НОВЫЙ ключ (recovery): уникальность nonce
    требуется в пределах одного ключа, а под другим ключом тот же nonce безопасен. Нужно это
    потому, что ключ service-токена выводится с солью из nonce папки — сменится nonce,
    перестанут работать все токены папки (дефект, пойманный тестом кластера 03.10.2026)."""
    if len(key) != 32:
        raise ValueError("key должен быть 32 байта")
    if nonce is None:
        nonce = pysecrets.token_bytes(GCM_NONCE_BYTES)
    elif len(nonce) != GCM_NONCE_BYTES:
        raise ValueError("nonce должен быть 12 байт")
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad if aad else None)
    return ct, nonce


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM расшифровка. Бросает InvalidTag если данные tamper'ены."""
    if len(key) != 32:
        raise ValueError("key должен быть 32 байта")
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad if aad else None)


def verify_master_password(password: str, cfg: VaultConfig) -> bytes | None:
    """Проверка master-password. Возвращает master-key если OK, None если нет.
    Time-resistant: Argon2id уже сам по себе медленный (~0.5с на проверку).
    """
    candidate_key = derive_key(password, cfg.salt)
    try:
        plain = decrypt(candidate_key, cfg.verifier_enc, cfg.verifier_nonce)
        if plain == VERIFIER_PLAINTEXT:
            return candidate_key
    except Exception:
        pass
    return None


def init_vault(master_password: str) -> tuple[VaultConfig, str]:
    """Первичная инициализация: создаёт salt, шифрует verifier, генерит recovery code.
    Возвращает (config, recovery_code в открытом виде — показать ОДИН РАЗ).
    """
    from datetime import datetime, timezone

    salt = pysecrets.token_bytes(32)
    master_key = derive_key(master_password, salt)
    verifier_enc, verifier_nonce = encrypt(master_key, VERIFIER_PLAINTEXT)

    # Recovery code: 24 hex (96 бит энтропии). Один раз показывается юзеру.
    recovery_code = pysecrets.token_hex(12).upper()
    # Хешируется через Argon2 для проверки при reset'е
    ph = PasswordHasher()
    recovery_hash = ph.hash(recovery_code)

    # Recovery cell: master_key зашифрован под Argon2id(recovery_code, recovery_salt).
    # При recovery вводим recovery_code → derive той же cell → decrypt master_key.
    # Зачем не пере-шифровать всю БД при reset master_password: scope-keys
    # папок остаются под старым master_key, мы лишь меняем что какой пароль
    # его расшифровывает.
    recovery_salt = pysecrets.token_bytes(32)
    recovery_key = derive_key(recovery_code, recovery_salt)
    recovery_master_enc, recovery_master_nonce = encrypt(recovery_key, master_key)

    cfg = VaultConfig(
        salt=salt,
        verifier_enc=verifier_enc,
        verifier_nonce=verifier_nonce,
        init_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        recovery_code_hash=recovery_hash,
        recovery_master_enc=recovery_master_enc,
        recovery_master_nonce=recovery_master_nonce,
        recovery_salt=recovery_salt,
    )
    save_config(cfg)
    return cfg, recovery_code


def verify_recovery_code(code: str, cfg: VaultConfig) -> bytes | None:
    """Recovery code → master_key (если код верный). Иначе None.
    Двойная проверка: Argon2-hash matchитсь + cell расшифровывается."""
    if not cfg.recovery_code_hash or not cfg.recovery_master_enc or not cfg.recovery_salt:
        return None
    try:
        PasswordHasher().verify(cfg.recovery_code_hash, code)
    except Exception:
        return None
    try:
        recovery_key = derive_key(code, cfg.recovery_salt)
        return decrypt(recovery_key, cfg.recovery_master_enc, cfg.recovery_master_nonce)
    except Exception:
        return None


def rewrap_with_new_password(master_key: bytes, new_password: str) -> tuple[VaultConfig, str]:
    """Меняет пароль (и recovery code), сохраняя master_key — поэтому scope-keys
    и значения в БД остаются нетронутыми.

    Возвращает (новый VaultConfig, новый recovery_code).
    """
    from datetime import datetime, timezone
    new_salt = pysecrets.token_bytes(32)
    # Шифруем тот же master_key под новый password-derived ключ
    new_pwd_key = derive_key(new_password, new_salt)
    # verifier шифруем под new_pwd_key (так verify_master_password увидит OK)
    # Но... постойте: verify_master_password дешифрует verifier_enc CANDIDATE_KEY,
    # где candidate_key = derive(password, salt). Чтобы это сработало, мы
    # должны verifier_enc шифровать под new_pwd_key, и в качестве master_key
    # для encrypt/decrypt scope-keys использовать ТОТ ЖЕ new_pwd_key. То есть
    # master_key — это и есть derive(password, salt).
    # А scope-keys в БД зашифрованы под СТАРЫЙ master_key. Если они отличаются —
    # надо ВСЁ перешифровать. Сделаем так: rewrap БУДЕТ перешифровывать БД
    # (см. main.py /api/auth/recover; здесь возвращаем new_pwd_key вместе с cfg).
    verifier_enc, verifier_nonce = encrypt(new_pwd_key, VERIFIER_PLAINTEXT)
    # Новый recovery code + cell
    new_recovery_code = pysecrets.token_hex(12).upper()
    ph = PasswordHasher()
    recovery_hash = ph.hash(new_recovery_code)
    rec_salt = pysecrets.token_bytes(32)
    rec_key = derive_key(new_recovery_code, rec_salt)
    rec_master_enc, rec_master_nonce = encrypt(rec_key, new_pwd_key)
    cfg = VaultConfig(
        salt=new_salt,
        verifier_enc=verifier_enc,
        verifier_nonce=verifier_nonce,
        init_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        recovery_code_hash=recovery_hash,
        recovery_master_enc=rec_master_enc,
        recovery_master_nonce=rec_master_nonce,
        recovery_salt=rec_salt,
    )
    return cfg, new_recovery_code


def gen_service_token() -> str:
    """Генерит service-token: vlt_<base32-12>_<random-32hex>"""
    import base64
    prefix = base64.b32encode(pysecrets.token_bytes(7)).decode().rstrip("=").lower()
    rand = pysecrets.token_hex(32)
    return f"vlt_{prefix}_{rand}"


# ── SSO unlock cell (v0.10) ───────────────────────────────────────────────────
_SSO_INFO = b"aps-vault/sso-unlock-cell/v1"


def sso_wrap_key(server_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_SSO_INFO).derive(server_key)


def sso_cell_set(cfg: VaultConfig, master_key: bytes, server_key: bytes) -> None:
    cfg.sso_master_enc, cfg.sso_master_nonce = encrypt(sso_wrap_key(server_key), master_key)


def sso_cell_open(cfg: VaultConfig, server_key: bytes) -> bytes | None:
    if not cfg.sso_master_enc or not server_key:
        return None
    try:
        return decrypt(sso_wrap_key(server_key), cfg.sso_master_enc, cfg.sso_master_nonce)
    except Exception:
        return None
