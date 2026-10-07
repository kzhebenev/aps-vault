#!/usr/bin/env python3
# MCP server for APS Vault.
# Stdio-транспорт. Агент получает доступ к секретам в scope своего токена
# без HTTP-обвязки и без необходимости спрашивать у пользователя.
#
# Конфиг через env:
#   VAULT_URL    — https://vault.example.com (required)
#   VAULT_TOKEN  — service-token vlt_..., scoped на ОДНУ папку
# Fallback: /etc/vault.conf, ~/.vault-token (как в /usr/local/bin/vault CLI).
#
# Источник правды по API — /aps/vault/backend/sdk_api.py.

from __future__ import annotations

import os
from urllib.parse import quote
from pathlib import Path
from typing import Any

# FastMCP/pydantic-settings читает .env из cwd при импорте — у непривилегированных
# юзеров может не быть прав на чужой .env. Прыгаем в свою директорию ДО импорта.
os.chdir(Path(__file__).resolve().parent)

import httpx
from mcp.server.fastmcp import FastMCP


def _load_config() -> tuple[str, str]:
    url = os.environ.get("VAULT_URL", "").strip()
    token = os.environ.get("VAULT_TOKEN", "").strip()
    # Fallback на стандартные конфиги vault CLI.
    if not token:
        for f in ("/etc/vault.conf", str(Path.home() / ".vault-token")):
            p = Path(f)
            if not p.is_file():
                continue
            try:
                for line in p.read_text().splitlines():
                    k, _, v = line.partition("=")
                    v = v.strip().strip('"').strip("'")
                    if k.strip() == "VAULT_TOKEN" and not token:
                        token = v
                    elif k.strip() == "VAULT_URL" and not url:
                        url = v
                if token:
                    break
            except PermissionError:
                continue
    if not url:
        raise RuntimeError("VAULT_URL is not set (e.g. https://vault.example.com)")
    if not token or not token.startswith("vlt_"):
        raise RuntimeError(
            "VAULT_TOKEN не задан или невалиден (нужен vlt_*). "
            "Запросите service-token у админа APS Vault, scope = нужная папка."
        )
    return url.rstrip("/"), token


BASE_URL, TOKEN = _load_config()
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

mcp = FastMCP("aps-vault")


async def _http(method: str, path: str, **kwargs: Any) -> Any:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.request(method, f"{BASE_URL}{path}", headers=HEADERS, **kwargs)
        if r.status_code == 401:
            raise RuntimeError(
                "Vault: 401 Unauthorized — токен невалиден, отозван или истёк. "
                "Запросите новый у админа."
            )
        if r.status_code == 403:
            raise RuntimeError(
                "Vault: 403 Forbidden — у токена нет нужного флага "
                "(can_write/can_read_notes/can_read_totp) или запрос вне scope."
            )
        if r.status_code == 404:
            raise FileNotFoundError(
                f"Vault: 404 — секрет/ресурс не найден. Проверьте имя; "
                f"токен scope'ed на одну папку — секрет вне неё не виден."
            )
        r.raise_for_status()
        return r.json()


@mcp.tool()
async def health() -> dict[str, Any]:
    """Статус Vault + scope текущего токена.

    Используй ПЕРВЫМ делом если не уверен, на какую папку у тебя доступ
    и что разрешено (can_read_notes / can_read_totp).

    Returns:
        {status, token_name, scope_folder, can_read_notes, can_read_totp, server_time_utc}
    """
    return await _http("GET", "/api/v1/m/health")


@mcp.tool()
async def list_secrets() -> list[dict[str, Any]]:
    """Список секретов в scope-папке (без значений).

    Каждая запись содержит name, tags, url, флаги has_notes/has_totp,
    updated_at. Получить значение → vault_get(name).
    """
    return await _http("GET", "/api/v1/m/secrets")


@mcp.tool()
async def get(name: str, include_notes: bool = False, include_totp: bool = False, version: int | None = None) -> dict[str, Any]:
    """Получить расшифрованный секрет по имени из scope-папки.

    Поля:
      - value — основное значение (пароль/токен/ключ).
      - version / current_version — номер версии значения (0.8); version=N запрашивает старую.
      - login — связанный логин/email (если задан в записи).
      - notes — заметки (только если у токена can_read_notes И include_notes=True).
      - totp — текущий 6-значный код (если can_read_totp И include_totp=True).

    Не печатай value в логи/чат без необходимости — секрет.
    Не передавай value сторонним сервисам без явной нужды.

    Args:
        name: Имя секрета (без слешей, без расширения).
        include_notes: Запросить заметки (нужен can_read_notes).
        include_totp: Запросить TOTP-код (нужен can_read_totp).
        version: Номер старой версии (например, предыдущий ключ при ротации); None — текущая.

    Returns:
        {name, value, login?, notes?, totp?, version, current_version, updated_at}
        Поля notes/totp придут только если флаги токена это разрешают.
    """
    if "/" in name or ".." in name:
        raise ValueError(f"имя секрета не должно содержать '/' или '..': {name!r}")
    data = await _http("GET", f"/api/v1/m/secret/{quote(name, safe='')}" + (f"?version={int(version)}" if version else ""))
    if "sealed" in data:
        # 0.17: токен привязан к ключу клиента — у MCP-сервера приватного ключа нет; для агента
        # выпускают обычный токен, запечатанные предназначены сервисам с клиентской библиотекой
        raise ValueError("этот токен отдаёт значения запечатанными (sealed delivery) — MCP-серверу нужен обычный токен без client_public_key")
    # Фильтруем поля по запросу клиента (бэкенд отдаёт всё что разрешено токеном).
    out = {"name": data.get("name"), "value": data.get("value"), "updated_at": data.get("updated_at"),
           "version": data.get("version"), "current_version": data.get("current_version")}
    if "login" in data:
        out["login"] = data["login"]
    if include_notes and "notes" in data:
        out["notes"] = data["notes"]
    if include_totp and "totp" in data:
        out["totp"] = data["totp"]
    return out


def _write_allowed() -> bool:
    """0.37: writing is off unless the operator turns it on — an LLM steered by text it reads (a web page, a secret's
    url or tags) must not be able to overwrite a production secret just because the token happens to have can_write."""
    return os.environ.get("APS_MCP_ALLOW_WRITE", "").strip() in ("1", "true", "yes")


@mcp.tool()
async def put(name: str, value: str, notes: str | None = None) -> dict[str, Any]:
    """DESTRUCTIVE. Upsert секрет в scope-папке. Требует can_write у токена И APS_MCP_ALLOW_WRITE=1 у сервера.

    Если can_write отключён (по умолчанию выкл у большинства токенов) —
    вернёт 403. Запиши тогда секрет руками через UI vault
    или попроси у админа write-токен.

    Существующее значение уезжает в history (как в human API).

    Args:
        name: Имя секрета.
        value: Новое значение.
        notes: Опциональные заметки (пишутся только если есть can_write).
    """
    if not _write_allowed():
        raise ValueError("запись выключена: оператор MCP-сервера должен явно задать APS_MCP_ALLOW_WRITE=1 (destructive: перезаписывает секрет)")
    if "/" in name or ".." in name:
        raise ValueError(f"имя секрета не должно содержать '/' или '..': {name!r}")
    body: dict[str, Any] = {"value": value}
    if notes is not None:
        body["notes"] = notes
    return await _http("POST", f"/api/v1/m/secret/{quote(name, safe='')}", json=body)


if __name__ == "__main__":
    mcp.run()
