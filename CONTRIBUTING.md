# Contributing

Thanks for looking. The project is intentionally small; please keep it that way.

## Ground rules

- **No new runtime dependencies without a reason** written in the PR. The whole point is that
  the code can be audited in an evening.
- **Cryptography changes** need a note in `docs/ARCHITECTURE.md` and a test that proves the
  old data still decrypts (or an explicit migration).
- **Never log secrets.** Not values, not tokens, not `id_token`s. Log exception *types*, not
  messages that may carry payloads (see `oidc.py` for the pattern).
- **Frontend:** build DOM with `el()` and `textContent`. `innerHTML` with data is a bug.
- **Every endpoint that changes state is audited.** If you add one, add the `audit()` call.

## Development

```bash
# backend
cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
VAULT_DATA_DIR=/tmp/vault-dev uvicorn main:app --reload --port 8086

# frontend: static files — open http://localhost:8087 via docker compose, or point nginx at frontend/
```

Tests: `cd backend && pytest` (test suite is being added for 0.4 — see the release checklist;
PRs with tests are very welcome).

## Pull requests

One topic per PR, a sentence on *why* in the description, and a line in `CHANGELOG.md` under
*Unreleased*. Versions follow `MAJOR.MINOR.PATCH`; bump `VERSION` and `backend/version.py:VERSION`
together (they must match — CI checks it).

## Security issues

See [SECURITY.md](SECURITY.md). Please do not file them as public issues.
