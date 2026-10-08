"""Outgoing webhooks: configuration, delivery and the event emitter the other modules call.

Split out of main.py in 0.41.7 (code moved verbatim; tests/test_route_table.py holds the contract)."""
from __future__ import annotations

import json
import secrets as pysecrets
from datetime import datetime, timezone

from fastapi import (Depends, HTTPException, Request)
from pydantic import BaseModel, Field

import db
import metrics
import netutil
import settings as cfgmod
from pydantic import field_validator

from app_core import _check_url, _client_ip, app, audit  # noqa: F401
from authz import require_unlocked  # noqa: F401
from fastapi import APIRouter

router = APIRouter()

# ─── Endpoints: webhooks (v0.3) ──────────────────────────────────────────────
class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=512)
    event_filter: str = "*"
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = _check_url(v)
        if not _outbound_scheme_ok(v):
            raise ValueError("webhook must be https:// (http:// only with VAULT_WEBHOOK_ALLOW_PRIVATE=1 or VAULT_DEV)")
        if not _webhook_target_allowed(v):
            raise ValueError("webhook target resolves to a private or loopback address "
                             "(set VAULT_WEBHOOK_ALLOW_PRIVATE=1 to allow)")
        return v


def _outbound_scheme_ok(url: str) -> bool:
    """0.37: a call that leaves the vault (webhook, approver notification) goes over https. Plain http only where
    private networks are allowed anyway (VAULT_WEBHOOK_ALLOW_PRIVATE=1) or in dev — otherwise event metadata and the
    approver's link would cross the internet in clear text."""
    if url.startswith("https://"):
        return True
    return url.startswith("http://") and (cfgmod.SETTINGS.webhook_allow_private or cfgmod.SETTINGS.dev)


def _webhook_target_allowed(url: str) -> bool:
    """SSRF guard: a webhook is admin-configured, but the vault should still not become a
    way to poke at the metadata service or internal hosts. Private/loopback/link-local
    targets are refused unless explicitly allowed."""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    if cfgmod.SETTINGS.webhook_allow_private:
        return True
    # 0.37: "globally routable" instead of a list of exclusions — 100.64/10 (carrier-grade NAT, cloud-internal) and
    # IPv4-mapped IPv6 used to pass; redirects are refused by netutil.urlopen_noredirect at call time
    return netutil.address_is_public(urlparse(url).hostname or "")


def _emit(event: str, data: dict) -> None:
    """Fire webhooks for an event without blocking the request. Payload carries names and
    ids only — never values."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # a worker thread (the rotation scheduler): hand the delivery to the main loop
        if _MAIN_LOOP is not None and not _MAIN_LOOP.is_closed():
            asyncio.run_coroutine_threadsafe(_fire_webhook(event, data), _MAIN_LOOP)
        return
    loop.create_task(_fire_webhook(event, data))


@router.get("/api/webhooks")
async def list_webhooks(_: str = Depends(require_unlocked)):
    with db.get_session() as s:
        rows = s.query(db.Webhook).order_by(db.Webhook.name).all()
        return [{
            "id": w.id, "name": w.name, "url": w.url,
            "event_filter": w.event_filter, "enabled": w.enabled,
            "created_at": w.created_at.isoformat() if w.created_at else "",
            "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
            "last_status": w.last_status,
        } for w in rows]


@router.post("/api/webhooks")
async def create_webhook(req: WebhookCreate, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        signing = pysecrets.token_hex(16)
        w = db.Webhook(name=req.name, url=req.url, event_filter=req.event_filter,
                       enabled=req.enabled, signing_secret=signing)
        s.add(w); s.commit(); s.refresh(w)
        audit("webhook:create", target=req.name, ip=_client_ip(request))
        return {"id": w.id, "signing_secret": signing,
                "note": "Save the signing_secret — the receiver uses it to verify the HMAC"}


@router.delete("/api/webhooks/{wid}")
async def delete_webhook(wid: int, request: Request, _: str = Depends(require_unlocked)):
    with db.get_session() as s:
        w = s.get(db.Webhook, wid)
        if not w:
            raise HTTPException(404, "not found")
        s.delete(w); s.commit()
        audit("webhook:delete", target=w.name, ip=_client_ip(request))
        return {"ok": True}


async def _fire_webhook(event: str, data: dict) -> None:
    """Best-effort delivery: HMAC-SHA256 подпись в X-Vault-Signature."""
    import hmac, hashlib, asyncio
    import urllib.request
    with db.get_session() as s:
        hooks = [w for w in s.query(db.Webhook).filter_by(enabled=True).all()
                 if _event_matches(w.event_filter, event)]
        if not hooks: return
        payload = json.dumps({"event": event, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "data": data}, ensure_ascii=False).encode()
        for w in hooks:
            # Re-checked at delivery time too: DNS may have changed since the hook was created.
            if not _outbound_scheme_ok(w.url) or not _webhook_target_allowed(w.url):
                w.last_status = "err: url not allowed"
                w.last_triggered_at = db.utcnow()
                continue
            sig = hmac.new(w.signing_secret.encode(), payload, hashlib.sha256).hexdigest()
            try:
                req = urllib.request.Request(
                    w.url, data=payload, method="POST",
                    headers={"Content-Type": "application/json",
                             "X-Vault-Event": event,
                             "X-Vault-Signature": f"sha256={sig}"})
                await asyncio.get_event_loop().run_in_executor(None, _deliver_webhook, req)
                w.last_status = "ok"
                metrics.record_webhook("ok")
            except Exception as e:
                w.last_status = f"err: {str(e)[:60]}"
                metrics.record_webhook("error")
            w.last_triggered_at = db.utcnow()
        s.commit()


def _deliver_webhook(req) -> bytes:
    """Отправка webhook'а через urlopen. Вынесено в отдельную функцию чтобы
    nosemgrep-аннотация была локальной. URL валидирован вызывающим
    (http/https only); SSRF-риски выше по стеку (admin-only UI)."""
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    return netutil.urlopen_noredirect(req, timeout=5).read()


def _event_matches(filter_pat: str, event: str) -> bool:
    if filter_pat in ("*", ""): return True
    for p in filter_pat.split(","):
        p = p.strip()
        if p == event: return True
        if p.endswith(":*") and event.startswith(p[:-1]): return True
    return False


_MAIN_LOOP = None
