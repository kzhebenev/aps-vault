"""
APS Vault — the FastAPI application, assembled.

Until 0.41.6 everything was in this file (4 200 lines). 0.41.7 split it by responsibility; the code moved verbatim and
tests/test_route_table.py holds the routes, their dependency trees, the middleware and the order of overlapping paths
to what they were before. Where things are:

  app_core.py      the app object, CORS, security headers, CSRF, the audit log, request helpers, crypto helpers, models
  authz.py         every permission check: unlocked session, roles per folder, owner-only, attempt limits, TOTP replay
  api_auth.py      /api/health, /api/init, unlock/lock, HSM and KMS master key, WebAuthn, 2FA, recovery
  api_users.py     named users and their roles, their TOTP, folder-key rotation
  api_secrets.py   folders, secrets, favourites, history, stats, export/import, import from other managers
  api_rotation.py  rotation in target systems and its scheduler
  api_tokens.py    service tokens, token watch, node enrolment
  api_sharing.py   read approvals, one-time share links
  api_ops.py       audit log, backups to S3, updates, metrics
  webhooks.py      outgoing webhooks and the event emitter
  sdk_api.py       the machine API (/api/v1/m/…) and the HashiCorp-compatible facade (/v1/…)
  version.py       VERSION
"""
from __future__ import annotations

import os
import urllib  # noqa: F401  (tests patch main.urllib.request — kept importable)

from fastapi import Request
from fastapi.responses import JSONResponse

import crypto
import db
import sessions
import settings as cfgmod
import suite as _suite_mod
import netutil

import api_auth
import api_ops
import api_rotation
import api_secrets
import api_sharing
import api_tokens
import api_users
import webhooks
import app_core
import authz
from app_core import NODE, app, logger
from authz import _wipe_spent_keys
from api_ops import _backup_loop
from api_rotation import _rotation_loop
from version import VERSION

# the same order the routes had in the single file — FastAPI takes the first matching path
for _m in (api_auth, api_users, api_secrets, api_rotation, api_tokens, api_ops, api_sharing, webhooks):
    app.include_router(_m.router)

# Until 0.41.6 all of these lived in this module, and code reaches them as main.X — sdk_api through
# __import__("main") (archive_value, _emit, _notify_event), backup and updates for VERSION, the tests for a few more.
# The whole old namespace stays readable here (tests/test_route_table.py checks every name of 0.41.6). Reading only:
# patching main.X no longer changes what the modules call — patch the module that defines X.
from typing import Any  # noqa: E402,F401  (imported by the old main; nothing uses them now)
from fastapi import Body  # noqa: E402,F401
from state import set_current_master_key  # noqa: E402,F401
for _mod in (app_core, authz, api_auth, api_users, api_secrets, api_rotation, api_tokens, api_ops, api_sharing, webhooks):
    for _k, _v in vars(_mod).items():
        if not _k.startswith("__") and _k != "router" and _k not in globals():
            globals()[_k] = _v


# ─── Machine API (M4) ────────────────────────────────────────────────────────
# Подключаем после определения всего — отдельный router.
try:
    import sdk_api
    app.include_router(sdk_api.build_router())
    app.include_router(sdk_api.build_kv_router())

    @app.exception_handler(sdk_api.KVError)
    async def _kv_error(request: Request, exc: sdk_api.KVError):
        return JSONResponse({"errors": exc.errors}, status_code=exc.status)
except Exception as e:
    logger.warning("sdk_api router not loaded: %s", e)


@app.on_event("startup")
async def _startup():
    import asyncio
    webhooks._MAIN_LOOP = asyncio.get_running_loop()      # 0.41.7: the emitter lives in webhooks.py and reads it there
    db.get_engine()  # создаст таблицы
    crypto.load_config_or_none()        # activates the stored cipher suite before any request
    # 0.37: say loudly what weakens this instance (the review found these were silent)
    if not os.environ.get("VAULT_TRUSTED_PROXIES"):
        logger.warning("VAULT_TRUSTED_PROXIES is not set: every private address (10/8, 172.16/12, 192.168/16) may set "
                       "X-Forwarded-For — a neighbour container/pod that reaches the backend directly can choose its source "
                       "address for token CIDR policies and the attempt limit. Set it to your proxy's address (docs/DEPLOYMENT.md).")
    for _h in cfgmod.SETTINGS.trusted_proxy_hosts:      # 0.41: proxies given by name — say what they resolve to now
        _a = sorted(str(x) for x in netutil._resolve(_h))
        (logger.info if _a else logger.warning)("trusted proxy %s → %s", _h, ", ".join(_a) or "does not resolve yet (retried every 10 s; untrusted until then)")
    if os.environ.get("VAULT_MASTER_PASSWORD") and not cfgmod.SETTINGS.dev:
        logger.warning("VAULT_MASTER_PASSWORD is set outside VAULT_DEV: the master password sits in the environment — use the "
                       "SSO cell, the HSM or the KMS instead (docs/DEPLOYMENT.md)")
    with db.get_session() as s:
        _wipe_spent_keys(s)                 # 0.37: folder-key copies of spent / expired links and codes
    purged = sessions.purge_expired()
    if cfgmod.SETTINGS.rotation_tick_sec > 0:
        asyncio.create_task(_rotation_loop())     # 0.24: scheduled rotations (a no-op without VAULT_ROTATION_KEY)
    if cfgmod.SETTINGS.backup_tick_sec > 0:
        asyncio.create_task(_backup_loop())       # 0.39: encrypted backups to S3 (a no-op until enabled in Settings)
    logger.info("aps-vault v%s started on %s; db=%s initialized=%s cipher=%s sessions_active=%d (purged %d expired)",
                VERSION, NODE, "sqlite" if db.is_sqlite() else "postgresql", crypto.config_exists(), _suite_mod.active(),
                sessions.active_count(), purged)
    if _suite_mod.experimental():
        logger.warning(_suite_mod.experimental_warning())    # 0.41.4: said once, at every start


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8086)
