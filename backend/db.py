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

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary,
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
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(String(512), default="")
    # Зашифрованный per-folder scope-key (envelope encryption). Без master-key
    # его не расшифровать. service-token хранит свою копию этого ключа,
    # зашифрованную под токен.
    scope_key_enc = Column(LargeBinary, nullable=False)
    scope_key_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class Secret(Base):
    __tablename__ = "secrets"
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
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
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
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime)         # None = бессрочно
    last_used = Column(DateTime)
    revoked = Column(Boolean, default=False, index=True)

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
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


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


class UiSession(Base):
    """v0.6: UI sessions shared by all replicas. `sid_hash` = sha256(cookie value); the master
    key is AES-GCM-wrapped under HKDF(cookie value) — only the client's cookie unwraps it."""
    __tablename__ = "ui_sessions"
    sid_hash = Column(String(64), primary_key=True)
    master_key_enc = Column(LargeBinary, nullable=False)
    master_key_nonce = Column(LargeBinary, nullable=False)
    csrf = Column(String(128), nullable=False)
    oidc_user = Column(String(256), default="")
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, default=utcnow)
    ip = Column(String(64), default="")


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
    BLOB = "BYTEA" if pg else "BLOB"
    with engine.begin() as conn:
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
