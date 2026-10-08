"""
APS Vault — SQLAlchemy модели + миграции.

Таблицы:
  folders          — папки для группировки (произвольная иерархия)
  secrets          — собственно секреты (encrypted values)
  service_tokens   — машинные токены для интеграций (scope = folder_id)
  audit_log        — кто, когда, что смотрел/менял
  lockdown         — IP-локдаун после N failed unlock attempts
  vault_config     — v0.6: salt/verifier/recovery/2FA (раньше data/config.json) — одна строка,
                     общая для всех реплик кластера
  ui_sessions      — v0.6: сессии интерфейса; мастер-ключ в строке завёрнут под ключ, который
                     есть только у клиента (выводится из cookie) — любая реплика обслужит сессию,
                     а дамп БД без cookie не даёт ничего

Хранилище: VAULT_DATABASE_URL (например postgresql+psycopg://user:pw@host/vault) — кластер;
без него — SQLite в VAULT_DB_PATH (один узел).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, UniqueConstraint,
                        String, Text, create_engine)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker


def _db_path() -> str:
    return os.environ.get("VAULT_DB_PATH",
                          str(Path(os.environ.get("VAULT_DATA_DIR", "/app/data")) / "vault.db"))


def database_url() -> str:
    """Explicit URL wins (cluster: PostgreSQL shared by all replicas); otherwise local SQLite."""
    url = os.environ.get("VAULT_DATABASE_URL", "").strip()
    return url or f"sqlite:///{_db_path()}"


def is_sqlite() -> bool:
    return database_url().startswith("sqlite")


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Folder(Base):
    __tablename__ = "folders"
    __table_args__ = {"sqlite_autoincrement": True}      # 0.30: a deleted folder's id is never handed to a new one
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(String(512), default="")
    # Зашифрованный per-folder scope-key (envelope encryption). Без master-key
    # его не расшифровать. service-token хранит свою копию этого ключа,
    # зашифрованную под токен.
    scope_key_enc = Column(LargeBinary, nullable=False)
    scope_key_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    # 0.24: automation cell — the folder key wrapped under HKDF(VAULT_ROTATION_KEY, folder id), so the
    # scheduler can rotate secrets of this folder without a human session. Written when a scheduled
    # rotation is saved on the folder, dropped with the folder's last rotation. Empty = no cell.
    automation_key_enc = Column(LargeBinary, default=b"")
    automation_key_nonce = Column(LargeBinary, default=b"")


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = {"sqlite_autoincrement": True}      # 0.30: a deleted secret's id is never handed to a new one
    id = Column(Integer, primary_key=True)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False, index=True)
    name = Column(String(256), nullable=False, index=True)
    # AES-GCM шифрованные данные (ciphertext + tag)
    value_enc = Column(LargeBinary, nullable=False)
    value_nonce = Column(LargeBinary, nullable=False)
    # Заметки тоже шифруем (могут содержать чувствительные данные)
    notes_enc = Column(LargeBinary, default=b"")
    notes_nonce = Column(LargeBinary, default=b"")
    # TOTP seed (base32) — шифрованный
    totp_seed_enc = Column(LargeBinary, default=b"")
    totp_seed_nonce = Column(LargeBinary, default=b"")
    # v0.3.2: login (имя пользователя / адрес почты для секрета). Шифруем —
    # login часто содержит email/имя сотрудника = PII. Опциональный, nullable
    # на старых записях остаётся пустым (миграция: ADD COLUMN ... DEFAULT NULL).
    login_enc = Column(LargeBinary, default=b"")
    login_nonce = Column(LargeBinary, default=b"")
    # Теги через запятую (открытый текст — для поиска)
    tags = Column(String(512), default="")
    # URL ассоциированный — открытый текст
    url = Column(String(512), default="")
    created_at = Column(DateTime, default=utcnow)
    # 0.33: no onupdate — reads bump last_accessed / access_count and the auto-update made every read look
    # like an edit (the Terraform provider saw its own import "modify" the secret). Edit paths set it explicitly.
    updated_at = Column(DateTime, default=utcnow)
    last_accessed = Column(DateTime)
    access_count = Column(Integer, default=0)
    # v0.3: favorite (звёздочка)
    is_favorite = Column(Boolean, default=False, index=True)
    # v0.7: rotation deadline — the UI warns before it, the health report lists overdue ones
    expires_at = Column(DateTime, nullable=True, index=True)
    # v0.8: monotonically increasing value version; history rows carry the version they held.
    # Lets the machine API read `?version=N` during a key rotation (old files → old key).
    version = Column(Integer, default=1, nullable=False)
    # v0.9: machine-only — the value is never shown in the UI, history, exports or share links;
    # only service tokens (and the rotate endpoint) touch it. For key material the admin issues
    # but must not see.
    machine_only = Column(Boolean, default=False, nullable=False)
    # v0.12: a person reads the value only after the approver confirms a request (approvals table)
    require_approval = Column(Boolean, default=False, nullable=False)

    folder = relationship("Folder")


class SecretHistory(Base):
    """v0.3: история значений секрета. При update value пишется старая версия сюда.
    Хранится зашифрованной — folder_key того же scope. При удалении секрета — каскад."""
    __tablename__ = "secret_history"
    id = Column(Integer, primary_key=True)
    secret_id = Column(Integer, ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False)
    value_enc = Column(LargeBinary, nullable=False)
    value_nonce = Column(LargeBinary, nullable=False)
    changed_at = Column(DateTime, default=utcnow, index=True)
    changed_by = Column(String(64), default="master")  # master | token:<id>
    version = Column(Integer, nullable=True, index=True)   # v0.8: the version number this value had


class ShareLink(Base):
    """v0.3: одноразовые/TTL ссылки для передачи секрета третьему лицу.
    `token_hash` — sha256 от публичного токена. После открытия инкремент used_count.
    Если max_uses достигнут — ссылка мёртвая."""
    __tablename__ = "share_links"
    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    secret_id = Column(Integer, ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False)
    # Зашифрованный folder_key под производный от raw-токена ключ — чтобы
    # просмотр работал БЕЗ master-key и БЕЗ vault unlock.
    folder_key_enc = Column(LargeBinary, nullable=False)
    folder_key_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    max_uses = Column(Integer, default=1)
    used_count = Column(Integer, default=0)
    revoked = Column(Boolean, default=False, index=True)
    note = Column(String(256), default="")


class NoteShare(Base):
    """v0.14: a one-time link for free text that is not a stored secret (a snippet of config, a
    short message, a code). Encrypted under a key derived from the link token — the database
    alone cannot read it, and after the link dies the text is gone with it."""
    __tablename__ = "note_shares"
    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(128), default="")
    payload_enc = Column(LargeBinary, nullable=False)
    payload_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    max_uses = Column(Integer, default=1)
    used_count = Column(Integer, default=0)
    revoked = Column(Boolean, default=False, index=True)
    note = Column(String(256), default="")


class Webhook(Base):
    """v0.3: webhook'и при событиях. Доставка POST'ом с HMAC-SHA256 подписью.
    События: secret:create | secret:update | secret:delete | token:create | token:revoke"""
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    url = Column(String(512), nullable=False)
    # Что слушать: 'secret:*' | 'secret:update,secret:delete' | '*'
    event_filter = Column(String(256), default="*")
    signing_secret = Column(String(128), default="")   # для HMAC
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=utcnow)
    last_triggered_at = Column(DateTime)
    last_status = Column(String(64), default="")


class ServiceToken(Base):
    __tablename__ = "service_tokens"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    # SHA-256 от raw-токена — для проверки. Сам токен показывается ОДИН РАЗ при создании.
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    # Скоуп: один folder = одна папка секретов доступна
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False)
    # Зашифрованный scope-key под производный от raw-токена ключ.
    # При обращении: derive(token) → decrypt(folder_key_enc) → decrypt(secret_value).
    folder_key_enc = Column(LargeBinary, nullable=False)
    folder_key_nonce = Column(LargeBinary, nullable=False)
    # Доступ: read | read+totp | read+notes
    can_read_value = Column(Boolean, default=True)
    can_read_notes = Column(Boolean, default=False)
    can_read_totp = Column(Boolean, default=False)
    # v0.3.1: запись секретов через machine API (POST /api/v1/m/secret/{name}).
    # По умолчанию ВЫКЛ: write-токен может перезаписать секреты своего scope —
    # расширение полномочий, включается осознанно per-token.
    can_write = Column(Boolean, default=False)
    # v0.5: PAM-style policy — where the token may be used from and when (policy.py)
    allowed_cidrs = Column(String(512), default="")
    allowed_hours = Column(String(256), default="")
    # v0.11: mTLS binding — hex fingerprints (SHA-1 or SHA-256) of client certificates the
    # token may be used with; empty = any. The proxy verifies the cert and passes the print.
    allowed_cert_fingerprints = Column(String(1024), default="")
    # v0.17: sealed delivery — raw X25519 public key (base64) of the client; set = the machine API
    # returns values encrypted to this key only, never plaintext (sealed.py)
    client_public_key = Column(String(128), default="")      # 0.19: a GOST point is 64 bytes → 88 base64 chars
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime)         # None = бессрочно
    last_used = Column(DateTime)
    revoked = Column(Boolean, default=False, index=True)
    # 0.26: the token watch — canary tokens trip on ANY use; on_anomaly says what happens when the
    # watch sees something off (alert | freeze); a frozen token answers 403 until a manager unfreezes it
    canary = Column(Boolean, default=False, nullable=False)
    on_anomaly = Column(String(16), default="alert", nullable=False)
    frozen = Column(Boolean, default=False, nullable=False)
    frozen_reason = Column(String(128), default="")
    created_by = Column(String(256), default="")        # 0.37: who issued it — a deactivated person's tokens are revoked

    folder = relationship("Folder")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow, index=True)
    actor = Column(String(64), default="")   # "master" | "token:<id>" | "unauth"
    action = Column(String(64), nullable=False, index=True)
    # secret:read, secret:create, secret:update, secret:delete,
    # folder:create, token:create, token:revoke, auth:unlock, auth:fail
    target = Column(String(256), default="")
    ip = Column(String(64), default="")
    user_agent = Column(String(256), default="")
    meta = Column(Text, default="")          # JSON


class TotpStep(Base):
    """0.37: the last accepted TOTP time step per subject ("owner" or "user:<id>") — a code is accepted once."""
    __tablename__ = "totp_steps"
    subject = Column(String(64), primary_key=True)
    last_step = Column(Integer, default=0)


class Lockdown(Base):
    __tablename__ = "lockdown"
    ip = Column(String(64), primary_key=True)
    fail_count = Column(Integer, default=0)
    locked_until = Column(DateTime)
    last_fail = Column(DateTime, default=utcnow)


class VaultConfigRow(Base):
    """v0.6: the master-password verifier and recovery material. One row (id=1). Was
    data/config.json until 0.5 — a file is per node; replicas need one shared source.
    Legacy file is imported on first start (crypto.load_config)."""
    __tablename__ = "vault_config"
    id = Column(Integer, primary_key=True, default=1)
    salt = Column(LargeBinary, nullable=False)
    verifier_enc = Column(LargeBinary, nullable=False)
    verifier_nonce = Column(LargeBinary, nullable=False)
    init_at_utc = Column(String(32), default="")
    recovery_code_hash = Column(String(256), default="")
    totp_secret_enc = Column(LargeBinary, default=b"")
    totp_secret_nonce = Column(LargeBinary, default=b"")
    recovery_master_enc = Column(LargeBinary, default=b"")
    recovery_master_nonce = Column(LargeBinary, default=b"")
    recovery_salt = Column(LargeBinary, default=b"")
    # v0.10: SSO unlock cell — master key wrapped under HKDF(VAULT_SSO_UNLOCK_KEY); empty = off
    sso_master_enc = Column(LargeBinary, default=b"")
    sso_master_nonce = Column(LargeBinary, default=b"")
    # v0.12: Argon2 hash of the approver's password (a second person, not the master password)
    approver_hash = Column(String(256), default="")
    # v0.13: password unlock also needs a registered security key (second factor)
    webauthn_second_factor = Column(Boolean, default=False)
    # v0.15: PKCS#11 cell — master key encrypted by an AES key inside a hardware/software token
    hsm_master_enc = Column(LargeBinary, default=b"")
    hsm_master_iv = Column(LargeBinary, default=b"")
    hsm_key_label = Column(String(64), default="")
    # v0.16: cloud KMS cell — master key encrypted by a KMS key; `kms_pin_bound` = decrypt needs the PIN context
    kms_master_enc = Column(LargeBinary, default=b"")
    kms_provider = Column(String(16), default="")
    kms_key_id = Column(String(256), default="")
    kms_pin_bound = Column(Boolean, default=False)
    # v0.18: cipher suite the vault was initialised with — aes | gost (suite.py); ciphertext is not portable between them
    cipher_suite = Column(String(16), default="aes")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class WebauthnCredential(Base):
    """v0.13: a security key / platform authenticator of the administrator. With a PRF cell
    (master key wrapped under HKDF(PRF output)) it unlocks the vault by itself."""
    __tablename__ = "webauthn_credentials"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), default="security key")
    credential_id = Column(LargeBinary, nullable=False, unique=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0)
    transports = Column(String(128), default="")
    prf_master_enc = Column(LargeBinary, default=b"")
    prf_master_nonce = Column(LargeBinary, default=b"")
    # v0.23: NULL = the owner's key (PRF cell holds the master key); set = a named user's key (PRF cell holds their private key)
    user_id = Column(Integer, index=True)
    created_at = Column(DateTime, default=utcnow)
    last_used = Column(DateTime)


class WebauthnChallenge(Base):
    """v0.13: issued challenges, single-use, shared by replicas."""
    __tablename__ = "webauthn_challenges"
    challenge = Column(String(128), primary_key=True)
    kind = Column(String(24), nullable=False)        # register | unlock | second_factor
    data = Column(Text, default="")
    expires_at = Column(DateTime, nullable=False, index=True)


class Approval(Base):
    """v0.12: one request by one session to read one approval-required secret. The approve
    link token is stored hashed; the decision is bound to the requesting session."""
    __tablename__ = "approvals"
    id = Column(Integer, primary_key=True)
    secret_id = Column(Integer, ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_sid_hash = Column(String(64), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    status = Column(String(16), default="pending", index=True)   # pending | approved | denied | expired
    reason = Column(String(512), default="")
    requester_ip = Column(String(64), default="")
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)                # request lifetime
    decided_at = Column(DateTime)
    decided_ip = Column(String(64), default="")
    ticket_until = Column(DateTime)                              # how long the requester may read after approval
    notified = Column(Boolean, default=False)


class User(Base):
    """v0.20: a named person with a key pair. The private key is wrapped under Argon2id(password)
    (or under the invite token until the password is set); grants carry folder keys encrypted to
    the public key (users.py)."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(256), nullable=False, unique=True, index=True)
    name = Column(String(128), default="")
    public_key = Column(LargeBinary, nullable=False)
    private_key_enc = Column(LargeBinary, nullable=False)
    private_key_nonce = Column(LargeBinary, nullable=False)
    pw_salt = Column(LargeBinary, nullable=False)
    has_password = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    invite_hash = Column(String(64), default="", index=True)
    invite_expires = Column(DateTime)
    # v0.23: security keys as a second factor on the user's password; SSO cell = private key under HKDF(server SSO key, user)
    webauthn_second_factor = Column(Boolean, default=False)
    sso_private_enc = Column(LargeBinary, default=b"")
    sso_private_nonce = Column(LargeBinary, default=b"")
    # 0.30: TOTP second factor on the password — the seed is encrypted under a key derived from the user's
    # private key, so it is checkable only after the password unwrapped that key (no server key involved)
    totp_secret_enc = Column(LargeBinary, default=b"")
    totp_secret_nonce = Column(LargeBinary, default=b"")
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)


class FolderGrant(Base):
    """v0.20: user × folder → role, with the folder key sealed to the user's public key."""
    __tablename__ = "folder_grants"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False, index=True)
    role = Column(String(16), nullable=False, default="reader")      # reader | writer | manager
    folder_key_blob = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("user_id", "folder_id", name="uq_grant_user_folder"),)


class Enrollment(Base):
    """v0.21: a one-time (or N-use) code that lets a node enrol itself: it generates a key pair,
    presents the code and its public key, and receives a sealed service token for the folder.
    The folder key is stored under KDF(code) so no human session is needed at enrol time —
    the share-link pattern."""
    __tablename__ = "enrollments"
    id = Column(Integer, primary_key=True)
    code_hash = Column(String(64), nullable=False, unique=True, index=True)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=False)
    name_prefix = Column(String(64), default="node")
    folder_key_enc = Column(LargeBinary, nullable=False)
    folder_key_nonce = Column(LargeBinary, nullable=False)
    options = Column(Text, default="{}")              # token options: can_read_*, expires_days, allowed_cidrs/hours
    max_uses = Column(Integer, default=1)
    used_count = Column(Integer, default=0)
    created_by = Column(String(256), default="master")
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked = Column(Boolean, default=False)


class Rotation(Base):
    """0.24: rotation of a secret inside its target system. One row per secret: what to change
    (`target`: postgres | http), how to reach it (`config_*`: JSON encrypted under the folder key —
    it names the admin-DSN secret or carries the receiver URL and its signing secret), how often
    (`interval_days`, 0 = by hand only) and what happened last. `next_at` doubles as the cluster
    claim: a node takes a due row with one conditional UPDATE, so two replicas never rotate the
    same secret at the same moment."""
    __tablename__ = "rotations"
    id = Column(Integer, primary_key=True)
    secret_id = Column(Integer, ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    target = Column(String(16), nullable=False)                 # postgres | http
    config_enc = Column(LargeBinary, nullable=False)
    config_nonce = Column(LargeBinary, nullable=False)
    generate = Column(String(32), default="alnum:32")            # value spec, see generate_value()
    interval_days = Column(Integer, default=0, nullable=False)   # 0 = manual only
    enabled = Column(Boolean, default=True, nullable=False)
    next_at = Column(DateTime, nullable=True, index=True)        # when the scheduler is to run it; NULL = never
    last_at = Column(DateTime, nullable=True)
    last_status = Column(String(16), default="")                 # "" | ok | err
    last_error = Column(String(256), default="")
    runs = Column(Integer, default=0, nullable=False)
    created_by = Column(String(128), default="master")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class TokenProfile(Base):
    """0.26: what normal looks like for a service token — the networks it comes from (/24, /48),
    the secrets it reads, how often. Updated on every machine-API call; the anomaly rules compare
    the current call with it. One row per token."""
    __tablename__ = "token_profiles"
    token_id = Column(Integer, ForeignKey("service_tokens.id", ondelete="CASCADE"), primary_key=True)
    uses = Column(Integer, default=0, nullable=False)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    last_ip = Column(String(64), default="")
    last_network = Column(String(64), default="")
    networks = Column(Text, default="{}")        # {"203.0.113.0/24": {"n": 120, "first": iso, "last": iso, "trusted": false}}
    secrets = Column(Text, default="{}")         # {"db-password": n}
    window_start = Column(DateTime, nullable=True)   # 10-minute rate window
    window_count = Column(Integer, default=0, nullable=False)
    window_new_secrets = Column(Text, default="[]")  # new secret names first read inside the window


class TokenAlert(Base):
    """0.26: one anomaly the watch raised on a token, with what was done about it."""
    __tablename__ = "token_alerts"
    id = Column(Integer, primary_key=True)
    token_id = Column(Integer, ForeignKey("service_tokens.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(32), nullable=False)    # new_network | parallel_networks | rate_spike | enumeration | canary
    detail = Column(Text, default="")            # JSON
    ip = Column(String(64), default="")
    network = Column(String(64), default="")
    created_at = Column(DateTime, default=utcnow, index=True)
    count = Column(Integer, default=1, nullable=False)   # repeats folded into the same alert within an hour
    last_at = Column(DateTime, default=utcnow)
    action = Column(String(16), default="alert")  # alert | freeze
    acknowledged = Column(Boolean, default=False, nullable=False, index=True)


class AgentKey(Base):
    """0.41.8: machine access for AI sessions and automation that acts as the owner without the master password.
    The key carries the master key wrapped under the suite's token KDF of the raw key (like a service token carries
    its folder key); the database holds only that ciphertext and the look-up hash. What a session opened by it may
    call is an allow-list in authz.py (_AGENT_PATHS) — folders, secrets, tokens, users and grants, audit; never the
    master password, recovery, cells, backups, webhooks, export, updates or other agent keys."""
    __tablename__ = "agent_keys"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    salt = Column(LargeBinary, nullable=False)
    master_key_enc = Column(LargeBinary, nullable=False)
    master_key_nonce = Column(LargeBinary, nullable=False)
    allowed_cidrs = Column(String(512), default="")
    expires_at = Column(DateTime)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String(256), default="")
    last_used_at = Column(DateTime)
    last_ip = Column(String(64), default="")


class UiSession(Base):
    """v0.6: UI sessions shared by all replicas. `sid_hash` = sha256(cookie value); the master
    key is AES-GCM-wrapped under HKDF(cookie value) — only the client's cookie unwraps it."""
    __tablename__ = "ui_sessions"
    sid_hash = Column(String(64), primary_key=True)
    master_key_enc = Column(LargeBinary, nullable=False)
    master_key_nonce = Column(LargeBinary, nullable=False)
    csrf = Column(String(128), nullable=False)
    oidc_user = Column(String(256), default="")
    # v0.20: a user's session wraps that user's private key instead of the master key
    user_id = Column(Integer, index=True)
    agent_key_id = Column(Integer, index=True)       # 0.41.8: opened by an agent key (authz checks it on every request)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, default=utcnow)
    ip = Column(String(64), default="")


class UpdateState(Base):
    """0.38: the last look at the release channel, shared by all replicas (one row, id=1). `releases` is the parsed
    list as JSON [{version, date, notes, url}] — the channel is asked at most every few hours, not per page view."""
    __tablename__ = "update_state"
    id = Column(Integer, primary_key=True, default=1)
    checked_at = Column(DateTime)
    releases = Column(Text, default="[]")
    error = Column(String(512), default="")


class UpdateAgent(Base):
    """0.38: an update agent (agent/updater.py) that polled recently. The agent pulls jobs; the vault never calls it."""
    __tablename__ = "update_agents"
    agent_id = Column(String(64), primary_key=True)
    last_seen = Column(DateTime, default=utcnow)
    mode = Column(String(16), default="")              # images (docker compose with release images)
    agent_version = Column(String(32), default="")
    current_version = Column(String(32), default="")   # what the installation runs according to the agent
    verify = Column(String(16), default="")            # cosign | off
    host = Column(String(128), default="")


class UpdateJob(Base):
    """0.38: "update the installation to version X", requested by the owner, carried out by an agent.
    requested → running → done | failed; a requested job can be cancelled."""
    __tablename__ = "update_jobs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_version = Column(String(32), nullable=False)
    from_version = Column(String(32), default="")
    state = Column(String(16), default="requested", index=True)
    step = Column(String(64), default="")
    requested_by = Column(String(256), default="")
    requested_at = Column(DateTime, default=utcnow)
    picked_at = Column(DateTime)
    finished_at = Column(DateTime)
    agent_id = Column(String(64), default="")
    log = Column(Text, default="")


class BackupState(Base):
    """0.39: encrypted backups to S3 — the owner's settings and the scheduler's memory (one row, id=1). Only the
    recipient's PUBLIC key is here; the S3 credentials live in the environment."""
    __tablename__ = "backup_state"
    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, default=False)
    mode = Column(String(16), default="change")              # change | hourly | daily
    include_env = Column(Boolean, default=True)              # 0.40: the VAULT_* / OIDC_* environment goes into the backup too
    recipient_pk = Column(Text, default="")
    recipient_fp = Column(String(32), default="")
    recipient_kind = Column(String(16), default="")
    recipient_set_at = Column(DateTime)
    state_hash = Column(String(64), default="")
    last_ok_at = Column(DateTime)
    last_full_at = Column(DateTime)
    last_error = Column(String(512), default="")
    lease_until = Column(DateTime)
    lease_node = Column(String(64), default="")


class BackupRun(Base):
    """0.39: one upload attempt (the page shows the last ones; S3 List permission is not needed for it)."""
    __tablename__ = "backup_runs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)
    state = Column(String(16), default="running")            # running | ok | failed
    reason = Column(String(16), default="")                  # change | hourly | daily | manual
    object_key = Column(String(512), default="")
    size = Column(Integer, default=0)
    sha256 = Column(String(64), default="")
    error = Column(String(512), default="")
    node = Column(String(64), default="")


# --- engine + session helpers ---
_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        url = database_url()
        if url.startswith("sqlite"):
            Path(_db_path()).parent.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(url, echo=False, future=True,
                                    connect_args={"check_same_thread": False})
        else:
            # pool_pre_ping: a replica must survive a PostgreSQL failover without a restart
            _engine = create_engine(url, echo=False, future=True, pool_pre_ping=True,
                                    pool_size=5, max_overflow=10)
        _create_schema(_engine)
        if url.startswith("sqlite"):
            # 0.37: the database holds names, tags, URLs, e-mails and audit in clear (values are encrypted) — owner only
            import os as _os
            for suffix in ("", "-wal", "-shm", "-journal"):
                p = str(_db_path()) + suffix
                if _os.path.exists(p):
                    try:
                        _os.chmod(p, 0o600)
                    except OSError:
                        pass
    return _engine


def _create_schema(engine) -> None:
    """create_all + migrations, tolerant to replicas starting at the same moment: `checkfirst`
    looks and then creates, and two nodes can both see an empty database and race on CREATE.
    The loser gets "already exists" — we retry, the second look finds the tables."""
    import time
    from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError
    last = None
    for attempt in range(8):
        try:
            Base.metadata.create_all(engine)
            _idempotent_migrations(engine)
            return
        except (OperationalError, ProgrammingError, DBAPIError) as e:
            last = e
            time.sleep(0.25 * (attempt + 1))
    raise last


def reset_engine() -> None:
    """Tests: forget the engine so the next call reads the environment again."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None


def ping() -> bool:
    """True when the database answers — readiness of this replica."""
    from sqlalchemy import text
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _idempotent_migrations(engine) -> None:
    """Идемпотентные ALTER'ы для существующих таблиц. SQLAlchemy `create_all`
    создаёт только отсутствующие таблицы; новые колонки нужно добавлять
    отдельно (ALTER TABLE)."""
    from sqlalchemy import text, inspect
    insp = inspect(engine)
    pg = engine.dialect.name == "postgresql"
    FALSE = "false" if pg else "0"
    TRUE = "true" if pg else "1"
    BLOB = "BYTEA" if pg else "BLOB"
    with engine.begin() as conn:
        # 0.41.8: sessions opened by an agent key
        if "ui_sessions" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("ui_sessions")}
            if "agent_key_id" not in cols:
                conn.execute(text("ALTER TABLE ui_sessions ADD COLUMN agent_key_id INTEGER"))
        # v0.3: is_favorite на secrets
        if "secrets" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("secrets")}
            if "is_favorite" not in cols:
                conn.execute(text(f"ALTER TABLE secrets ADD COLUMN is_favorite BOOLEAN DEFAULT {FALSE}"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_secrets_is_favorite ON secrets (is_favorite)"))
        # v0.3.1: can_write на service_tokens (запись через machine API)
        if "service_tokens" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("service_tokens")}
            if "can_write" not in cols:
                conn.execute(text(f"ALTER TABLE service_tokens ADD COLUMN can_write BOOLEAN DEFAULT {FALSE}"))
            if "allowed_cidrs" not in cols:
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN allowed_cidrs VARCHAR(512) DEFAULT ''"))
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN allowed_hours VARCHAR(256) DEFAULT ''"))
            if "allowed_cert_fingerprints" not in cols:
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN allowed_cert_fingerprints VARCHAR(1024) DEFAULT ''"))
            if "client_public_key" not in cols:
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN client_public_key VARCHAR(2048) DEFAULT ''"))
            elif pg:
                # 0.19: GOST public keys need 88 characters; 0.27: the X25519+ML-KEM-768 hybrid key needs 1624.
                # SQLite ignores VARCHAR lengths, PostgreSQL enforces them.
                conn.execute(text("ALTER TABLE service_tokens ALTER COLUMN client_public_key TYPE VARCHAR(2048)"))
        # v0.3.2: login_enc/login_nonce на secrets — отдельное поле для логина
        # (отделяем от notes/value, чтобы UI и CLI отдавали логин структурно).
        # Шифруем т.к. login часто = email/имя сотрудника (PII).
        if "secrets" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("secrets")}
            if "login_enc" not in cols:
                conn.execute(text(f"ALTER TABLE secrets ADD COLUMN login_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE secrets ADD COLUMN login_nonce {BLOB}"))
            # v0.7: expires_at (rotation deadline)
            if "expires_at" not in cols:
                conn.execute(text("ALTER TABLE secrets ADD COLUMN expires_at TIMESTAMP"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_secrets_expires_at ON secrets (expires_at)"))
            # v0.8: value versions
            if "version" not in cols:
                conn.execute(text("ALTER TABLE secrets ADD COLUMN version INTEGER NOT NULL DEFAULT 1"))
            if "machine_only" not in cols:
                conn.execute(text(f"ALTER TABLE secrets ADD COLUMN machine_only BOOLEAN NOT NULL DEFAULT {FALSE}"))
            if "require_approval" not in cols:
                conn.execute(text(f"ALTER TABLE secrets ADD COLUMN require_approval BOOLEAN NOT NULL DEFAULT {FALSE}"))
        if "vault_config" in insp.get_table_names():
            vcols = {c["name"] for c in insp.get_columns("vault_config")}
            if "sso_master_enc" not in vcols:
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN sso_master_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN sso_master_nonce {BLOB}"))
            if "approver_hash" not in vcols:
                conn.execute(text("ALTER TABLE vault_config ADD COLUMN approver_hash VARCHAR(256) DEFAULT ''"))
            if "webauthn_second_factor" not in vcols:
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN webauthn_second_factor BOOLEAN DEFAULT {FALSE}"))
            if "hsm_master_enc" not in vcols:
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN hsm_master_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN hsm_master_iv {BLOB}"))
                conn.execute(text("ALTER TABLE vault_config ADD COLUMN hsm_key_label VARCHAR(64) DEFAULT ''"))
            if "kms_master_enc" not in vcols:
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN kms_master_enc {BLOB}"))
                conn.execute(text("ALTER TABLE vault_config ADD COLUMN kms_provider VARCHAR(16) DEFAULT ''"))
                conn.execute(text("ALTER TABLE vault_config ADD COLUMN kms_key_id VARCHAR(256) DEFAULT ''"))
                conn.execute(text(f"ALTER TABLE vault_config ADD COLUMN kms_pin_bound BOOLEAN DEFAULT {FALSE}"))
            if "cipher_suite" not in vcols:
                conn.execute(text("ALTER TABLE vault_config ADD COLUMN cipher_suite VARCHAR(16) DEFAULT 'aes'"))
        if "ui_sessions" in insp.get_table_names():
            scols = {c["name"] for c in insp.get_columns("ui_sessions")}
            if "user_id" not in scols:
                conn.execute(text("ALTER TABLE ui_sessions ADD COLUMN user_id INTEGER"))
        if "webauthn_credentials" in insp.get_table_names():
            wcols = {c["name"] for c in insp.get_columns("webauthn_credentials")}
            if "user_id" not in wcols:
                conn.execute(text("ALTER TABLE webauthn_credentials ADD COLUMN user_id INTEGER"))
        if "users" in insp.get_table_names():
            ucols = {c["name"] for c in insp.get_columns("users")}
            if "webauthn_second_factor" not in ucols:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN webauthn_second_factor BOOLEAN DEFAULT {FALSE}"))
                conn.execute(text(f"ALTER TABLE users ADD COLUMN sso_private_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE users ADD COLUMN sso_private_nonce {BLOB}"))
            if "totp_secret_enc" not in ucols:                          # 0.30
                conn.execute(text(f"ALTER TABLE users ADD COLUMN totp_secret_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE users ADD COLUMN totp_secret_nonce {BLOB}"))
        if "folders" in insp.get_table_names():
            fcols = {c["name"] for c in insp.get_columns("folders")}
            if "automation_key_enc" not in fcols:                       # 0.24
                conn.execute(text(f"ALTER TABLE folders ADD COLUMN automation_key_enc {BLOB}"))
                conn.execute(text(f"ALTER TABLE folders ADD COLUMN automation_key_nonce {BLOB}"))
        if "service_tokens" in insp.get_table_names():
            tcols = {c["name"] for c in insp.get_columns("service_tokens")}
            if "canary" not in tcols:                                   # 0.26
                conn.execute(text(f"ALTER TABLE service_tokens ADD COLUMN canary BOOLEAN NOT NULL DEFAULT {FALSE}"))
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN on_anomaly VARCHAR(16) NOT NULL DEFAULT 'alert'"))
                conn.execute(text(f"ALTER TABLE service_tokens ADD COLUMN frozen BOOLEAN NOT NULL DEFAULT {FALSE}"))
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN frozen_reason VARCHAR(128) DEFAULT ''"))
            if "created_by" not in tcols:                               # 0.37
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN created_by VARCHAR(256) DEFAULT ''"))
        if "backup_state" in insp.get_table_names():
            bcols = {c["name"] for c in insp.get_columns("backup_state")}
            if "include_env" not in bcols:                              # 0.40
                conn.execute(text(f"ALTER TABLE backup_state ADD COLUMN include_env BOOLEAN DEFAULT {TRUE}"))
        if "secret_history" in insp.get_table_names():
            hcols = {c["name"] for c in insp.get_columns("secret_history")}
            if "version" not in hcols:
                conn.execute(text("ALTER TABLE secret_history ADD COLUMN version INTEGER"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_secret_history_version ON secret_history (version)"))
    _backfill_versions(engine)


def _backfill_versions(engine) -> None:
    """Number existing history rows 1..k by time and set the secret's version to k+1 — once,
    for rows created before 0.8 (version IS NULL). Idempotent: nothing to do on a fresh DB."""
    from sqlalchemy.orm import Session
    with Session(engine) as s:
        pending = s.query(SecretHistory.secret_id).filter(SecretHistory.version.is_(None)).distinct().all()
        for (sid,) in pending:
            rows = s.query(SecretHistory).filter_by(secret_id=sid).order_by(SecretHistory.changed_at.asc(), SecretHistory.id.asc()).all()
            for i, r in enumerate(rows, start=1):
                r.version = i
            sec = s.get(Secret, sid)
            if sec is not None and (sec.version or 1) <= len(rows):
                sec.version = len(rows) + 1
        s.commit()


def get_session():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory()
