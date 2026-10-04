#!/bin/bash
# Backend tests in a throwaway container (no local venv needed).
#   ./run_tests.sh            — pytest on SQLite (single node + the two-node cluster test on a shared file)
#   ./run_tests.sh pg         — the same suite against a throwaway PostgreSQL 16 (what a cluster runs on)
#   ./run_tests.sh gost       — the same suite with VAULT_CIPHER=gost (Kuznyechik-MGM / Streebog / KDF_TREE)
# Every mode ends with tests/compat_fixture_check.py: a 0.17.1 database must still open.
#   ./run_tests.sh audit      — pip-audit of runtime dependencies
#   PYTEST_ARGS=tests/test_rotation.py ./run_tests.sh   — a subset (any mode)
set -e
cd "$(dirname "$0")"
IMG=python:3.11-slim
# SoftHSM2 inside the test container: a PKCS#11 token for the HSM tests (test_hsm.py). Installed
# from Debian, token initialised in /tmp; the tests see it through VAULT_PKCS11_MODULE. Without
# it the HSM tests are skipped with "НЕ НАСТРОЕНО".
SOFTHSM_PREP='(apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y softhsm2 >/dev/null 2>&1) && mkdir -p /tmp/softhsm && printf "directories.tokendir = /tmp/softhsm\nobjectstore.backend = file\n" > /tmp/softhsm2.conf && export SOFTHSM2_CONF=/tmp/softhsm2.conf && softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678 >/dev/null && export VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so VAULT_PKCS11_TOKEN_LABEL=aps-vault TEST_PKCS11_PIN=1234;'

# LocalStack (community image, AWS KMS only) as the cloud-KMS emulator for test_kms.py: same wire
# protocol as AWS (SigV4, EncryptionContext). Without it the KMS tests are skipped with "НЕ НАСТРОЕНО".
KMS_IMG=localstack/localstack:3.8.1
NET=aps-vault-test-$$; PG=aps-vault-test-pg-$$; LS=aps-vault-test-kms-$$
cleanup() { docker rm -f "$PG" "$LS" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
KMS_ENV=()
PG_TARGET_ENV=()
# PostgreSQL as a rotation *target* (test_rotation.py: ALTER ROLE + login with the new password).
# Without it the postgres-target tests are skipped with "НЕ НАСТРОЕНО". The pg mode uses the same server as the store.
start_pg() {
  docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=vault -e POSTGRES_PASSWORD=vault -e POSTGRES_DB=vault postgres:16-alpine >/dev/null
  for i in $(seq 1 30); do docker exec "$PG" pg_isready -U vault -q && break; sleep 1; done
  PG_TARGET_ENV=(-e "TEST_ROTATION_PG_DSN=postgresql://vault:vault@$PG:5432/vault")
}
start_kms() {
  docker run -d --name "$LS" --network "$NET" -e SERVICES=kms -e EAGER_SERVICE_LOADING=1 $KMS_IMG >/dev/null || return 0
  for i in $(seq 1 60); do
    KEY=$(docker exec "$LS" awslocal kms create-key --query KeyMetadata.KeyId --output text 2>/dev/null) && [ -n "$KEY" ] && break
    sleep 2; KEY=
  done
  if [ -n "$KEY" ]; then
    KMS_ENV=(-e VAULT_KMS_PROVIDER=aws -e VAULT_KMS_KEY_ID="$KEY" -e VAULT_KMS_REGION=us-east-1 -e "VAULT_KMS_ENDPOINT=http://$LS:4566/" -e VAULT_KMS_AWS_ACCESS_KEY=test -e VAULT_KMS_AWS_SECRET_KEY=test)
  else
    echo "KMS emulator did not come up — test_kms.py will be skipped (НЕ НАСТРОЕНО)" >&2
  fi
}

case "${1:-}" in
  audit)
    docker run --rm -v "$PWD:/repo:ro" -w /repo/backend $IMG bash -c \
      "pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && pip-audit -r requirements.txt" ;;
  pg)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    URL="postgresql+psycopg://vault:vault@$PG:5432/vault"
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" \
      -e VAULT_DATABASE_URL="$URL" -e TEST_DATABASE_URL="$URL" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
  gost)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 -e VAULT_CIPHER=gost "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
  *)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
esac
