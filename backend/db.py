"""
APS Vault — SQLAlchemy модели + миграции.

Таблицы:
  folders          — папки для группировки (произвольная иерархия)
  secrets          — собственно секреты (encrypted values)
  service_tokens   — машинные токены для интеграций (scope = folder_id)
  audit_log        — кто, когда, что смотрел/менял
  lockdown         — IP-локдаун после N failed unlock attempts
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


# --- engine + session helpers ---
_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        path = _db_path()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{path}", echo=False, future=True,
                                connect_args={"check_same_thread": False})
        Base.metadata.create_all(_engine)
        _idempotent_migrations(_engine)
    return _engine


def _idempotent_migrations(engine) -> None:
    """Идемпотентные ALTER'ы для существующих таблиц. SQLAlchemy `create_all`
    создаёт только отсутствующие таблицы; новые колонки нужно добавлять
    отдельно (ALTER TABLE)."""
    from sqlalchemy import text, inspect
    insp = inspect(engine)
    with engine.begin() as conn:
        # v0.3: is_favorite на secrets
        if "secrets" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("secrets")}
            if "is_favorite" not in cols:
                conn.execute(text("ALTER TABLE secrets ADD COLUMN is_favorite BOOLEAN DEFAULT 0"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_secrets_is_favorite ON secrets (is_favorite)"))
        # v0.3.1: can_write на service_tokens (запись через machine API)
        if "service_tokens" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("service_tokens")}
            if "can_write" not in cols:
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN can_write BOOLEAN DEFAULT 0"))
            if "allowed_cidrs" not in cols:
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN allowed_cidrs VARCHAR(512) DEFAULT ''"))
                conn.execute(text("ALTER TABLE service_tokens ADD COLUMN allowed_hours VARCHAR(256) DEFAULT ''"))
        # v0.3.2: login_enc/login_nonce на secrets — отдельное поле для логина
        # (отделяем от notes/value, чтобы UI и CLI отдавали логин структурно).
        # Шифруем т.к. login часто = email/имя сотрудника (PII).
        if "secrets" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("secrets")}
            if "login_enc" not in cols:
                conn.execute(text("ALTER TABLE secrets ADD COLUMN login_enc BLOB"))
                conn.execute(text("ALTER TABLE secrets ADD COLUMN login_nonce BLOB"))


def get_session():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory()
