#!/bin/bash
# Backend tests in a throwaway container (no local venv needed).
#   ./run_tests.sh            — pytest on SQLite (single node + the two-node cluster test on a shared file)
#   ./run_tests.sh pg         — the same suite against a throwaway PostgreSQL 16 (what a cluster runs on)
#   ./run_tests.sh audit      — pip-audit of runtime dependencies
set -e
cd "$(dirname "$0")"
IMG=python:3.11-slim
# SoftHSM2 inside the test container: a PKCS#11 token for the HSM tests (test_hsm.py). Installed
# from Debian, token initialised in /tmp; the tests see it through VAULT_PKCS11_MODULE. Without
# it the HSM tests are skipped with "НЕ НАСТРОЕНО".
SOFTHSM_PREP='(apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y softhsm2 >/dev/null 2>&1) && mkdir -p /tmp/softhsm && printf "directories.tokendir = /tmp/softhsm\nobjectstore.backend = file\n" > /tmp/softhsm2.conf && export SOFTHSM2_CONF=/tmp/softhsm2.conf && softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678 >/dev/null && export VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so VAULT_PKCS11_TOKEN_LABEL=aps-vault TEST_PKCS11_PIN=1234;'

case "${1:-}" in
  audit)
    docker run --rm -v "$PWD:/repo:ro" -w /repo/backend $IMG bash -c \
      "pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && pip-audit -r requirements.txt" ;;
  pg)
    NET=aps-vault-test-$$; PG=aps-vault-test-pg-$$
    cleanup() { docker rm -f "$PG" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=vault -e POSTGRES_PASSWORD=vault -e POSTGRES_DB=vault \
      postgres:16-alpine >/dev/null
    for i in $(seq 1 30); do docker exec "$PG" pg_isready -U vault -q && break; sleep 1; done
    URL="postgresql+psycopg://vault:vault@$PG:5432/vault"
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 \
      -e VAULT_DATABASE_URL="$URL" -e TEST_DATABASE_URL="$URL" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider tests/" ;;
  *)
    docker run --rm -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider tests/" ;;
esac
