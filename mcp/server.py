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
        r = await client.request(method, f"{BASE_URL}{path}", headers={**HEADERS, **kwargs.pop("headers", {})}, **kwargs)
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
    if not _get_allowed():
        raise PermissionError("get выключен оператором (APS_MCP_DISABLE_GET=1): секреты этого агента не попадают в его "
                              "контекст — используй use(name, url, headers={...{{secret}}...})")
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


# ── use (0.41.6): the agent acts with a secret it never sees ─────────────────────────────────────────────────────────
# `get` puts the value into the model's context, and from there into whatever processes that context. `use` keeps it
# here: the agent describes an HTTPS request with placeholders, this server fetches the secret, substitutes it, sends
# the request and returns the response with every form of the value cut out. What stops a prompt-injected agent from
# simply sending the secret to its own server: the request may go only to the host written in the secret's own `url`
# field (the same binding a browser's autofill uses) or to a host the operator listed in APS_MCP_USE_HOSTS; no
# redirects are followed; the placeholder cannot be in the host part. `get` stays as it was; APS_MCP_DISABLE_GET=1
# turns it off for agents that should only ever `use`.
PLACEHOLDERS = ("{{secret}}", "{{login}}", "{{basic}}")
USE_MAX_BODY = 20000


def _use_hosts() -> list[str]:
    return [h.strip().lower() for h in os.environ.get("APS_MCP_USE_HOSTS", "").split(",") if h.strip()]


def _host_allowed(host: str, secret_url: str) -> tuple[bool, bool]:
    """(allowed, by_operator). The secret's own url binds it to one host; the operator's list adds hosts
    (exact `api.example.com` or `*.example.com`)."""
    from urllib.parse import urlsplit
    host = host.lower().rstrip(".")
    own = (urlsplit(secret_url).hostname or "").lower().rstrip(".") if secret_url else ""
    if own and host == own:
        return True, False
    for h in _use_hosts():
        if h == host or (h.startswith("*.") and host.endswith(h[1:])):
            return True, True
    return False, False


def _forms(value: str) -> list[str]:
    """Every form in which a response could echo the value back: as is, URL-encoded, base64 (alone and in Basic)."""
    import base64
    from urllib.parse import quote as q, quote_plus
    import json
    enc = {q(value, safe=""), quote_plus(value), base64.b64encode(value.encode()).decode(),
           json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}   # echoed inside a JSON string
    out = {value} | {f for f in enc if len(f) >= 4}          # the value itself always, however short
    return sorted((f for f in out if f), key=len, reverse=True)


REDACT_GRAM = 8


def _redact(text: str, secrets: list[str]) -> tuple[str, int]:
    """Cut out every stretch of `text` that repeats at least REDACT_GRAM consecutive characters of any form of the
    secret (the whole value when it is shorter). A list of exact encodings is not enough: a server echoes a value
    partly percent-encoded (`…z=1%22q`) or escaped twice inside JSON, and the exact forms no longer match — but long
    runs of the original characters are still there. Linear: n-grams of the forms in a set, one pass over the text."""
    grams: dict[int, set[str]] = {}
    for f in secrets:
        if f:
            k = min(REDACT_GRAM, len(f))
            grams.setdefault(k, set()).update(f[i:i + k] for i in range(len(f) - k + 1))
    hit = bytearray(len(text))
    for k, gs in grams.items():
        for i in range(len(text) - k + 1):
            if text[i:i + k] in gs:
                hit[i:i + k] = b"\x01" * k
    out, n, i = [], 0, 0
    while i < len(text):
        if hit[i]:
            j = i
            while j < len(text) and hit[j]:
                j += 1
            out.append("[REDACTED]"); n += 1; i = j
        else:
            out.append(text[i]); i += 1
    return "".join(out), n


def _get_allowed() -> bool:
    return os.environ.get("APS_MCP_DISABLE_GET", "").strip() not in ("1", "true", "yes")


@mcp.tool()
async def use(name: str, url: str, method: str = "GET", headers: dict[str, str] | None = None,
              body: str | dict[str, Any] | list[Any] | None = None) -> dict[str, Any]:
    """Сделать HTTPS-запрос С секретом, не получая сам секрет. Предпочтительнее get для обращения к API.

    В url (только путь/query), headers и body (строка или JSON-объект) подставь плейсхолдер — сервер заменит его сам:
      {{secret}} — значение, {{login}} — логин записи, {{basic}} — base64("login:value") для Basic-авторизации.
    Пример: use("github-token", "https://api.github.com/user", headers={"Authorization": "Bearer {{secret}}"}).

    Куда можно: только на хост из поля url самой записи секрета (или из списка оператора APS_MCP_USE_HOSTS),
    только https (http — лишь для хостов оператора), редиректы не выполняются (вернутся status 3xx и location).
    Ответ возвращается с вырезанным секретом во всех формах ([REDACTED]); тело — первые 20 000 символов.

    Returns:
        {status, headers: {content-type, location?}, body, truncated, redacted, host}
    """
    from urllib.parse import urlsplit
    if "/" in name or ".." in name:
        raise ValueError(f"имя секрета не должно содержать '/' или '..': {name!r}")
    json_body = body if isinstance(body, (dict, list)) else None   # MCP hosts turn a JSON-looking string into an object
    if json_body is not None:
        import json
        body = json.dumps(body, ensure_ascii=False)                   # for the placeholder check below only
        headers = {"Content-Type": "application/json", **(headers or {})}
    method = method.upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
        raise ValueError(f"метод {method} не поддерживается")
    parts = urlsplit(url)
    if any(p in (parts.netloc or "") for p in ("{{", "}}")):
        raise ValueError("плейсхолдер не может стоять в имени хоста — секрет не выбирает, куда уйти")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"нужен абсолютный адрес: {url!r}")
    texts = [url, body or "", *(headers or {}).keys(), *(headers or {}).values()]
    if not any(p in t for t in texts for p in PLACEHOLDERS):
        raise ValueError("в запросе нет плейсхолдера {{secret}} / {{login}} / {{basic}} — для запроса без секрета use не нужен")
    if any(p in k for k in (headers or {}) for p in PLACEHOLDERS):
        raise ValueError("плейсхолдер допустим в значении заголовка, не в имени")
    listing = await _http("GET", "/api/v1/m/secrets")
    rec = next((r for r in listing if r.get("name") == name), None)
    if rec is None:
        raise FileNotFoundError(f"Vault: секрета {name!r} нет в папке токена")
    allowed, by_operator = _host_allowed(host, rec.get("url") or "")
    if not allowed:
        own = urlsplit(rec.get("url") or "").hostname
        raise PermissionError(
            f"секрет {name!r} нельзя отправить на {host}: " +
            (f"он привязан к {own} (поле url записи)" if own else "у записи нет url, а хоста нет в APS_MCP_USE_HOSTS") +
            ". Если это законная цель — добавьте её в url записи или в APS_MCP_USE_HOSTS оператора.")
    if parts.scheme != "https" and not (parts.scheme == "http" and by_operator):
        raise PermissionError("только https (http — лишь для хостов из APS_MCP_USE_HOSTS)")

    data = await _http("GET", f"/api/v1/m/secret/{quote(name, safe='')}",
                       headers={"User-Agent": f"aps-vault-mcp/use host={host}"})     # the vault's audit shows where it went
    if "sealed" in data:
        raise ValueError("этот токен отдаёт значения запечатанными (sealed delivery) — MCP-серверу нужен обычный токен без client_public_key")
    import base64
    value, login = data.get("value") or "", data.get("login") or ""
    basic = base64.b64encode(f"{login}:{value}".encode()).decode()
    sub = lambda t: t.replace("{{secret}}", value).replace("{{login}}", login).replace("{{basic}}", basic)
    path_q = parts._replace(scheme="", netloc="").geturl()
    real_url = f"{parts.scheme}://{parts.netloc}{sub(path_q)}"
    hdrs = {k: sub(v) for k, v in (headers or {}).items()}
    hdrs.setdefault("User-Agent", "aps-vault-mcp/use")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False) as client:
            if json_body is not None:                # substitute inside the strings, then serialise: a quote in the secret stays escaped
                deep = lambda o: {k: deep(v) for k, v in o.items()} if isinstance(o, dict) else [deep(v) for v in o] if isinstance(o, list) else sub(o) if isinstance(o, str) else o
                content = json.dumps(deep(json_body), ensure_ascii=False).encode()
            else:
                content = sub(body).encode() if body is not None else None
            r = await client.request(method, real_url, headers=hdrs, content=content)
    except httpx.HTTPError as e:
        msg, _ = _redact(str(e), _forms(value) + ([basic] if login else []))
        raise RuntimeError(f"запрос к {host} не удался: {type(e).__name__}: {msg}") from None
    forms = _forms(value) + ([basic] if login else [])
    text = r.text if method != "HEAD" else ""
    truncated = len(text) > USE_MAX_BODY
    text, n = _redact(text[:USE_MAX_BODY], forms)
    out_headers = {}
    for h in ("content-type", "location"):
        if h in r.headers:
            out_headers[h], k = _redact(r.headers[h], forms)
            n += k
    return {"status": r.status_code, "headers": out_headers, "body": text, "truncated": truncated,
            "redacted": n, "host": host}


if __name__ == "__main__":
    mcp.run()
