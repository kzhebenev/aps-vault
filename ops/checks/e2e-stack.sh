#!/bin/bash
# Throwaway APS Vault stack for the browser end-to-end check: fresh SQLite in a temp dir, dev
# mode off (init token required, as in production), UI on 127.0.0.1:${E2E_PORT:-8189}.
#   ops/checks/e2e-stack.sh up      → prints the URL when /api/health answers
#   ops/checks/e2e-stack.sh down
set -euo pipefail
cd "$(dirname "$0")/../.."
PROJECT=aps-vault-e2e
PORT="${E2E_PORT:-8189}"
DATA="${E2E_DATA:-/tmp/aps-vault-e2e-data}"
case "${1:-up}" in
  up)
    mkdir -p "$DATA"; chown 10001:10001 "$DATA" 2>/dev/null || sudo -n chown 10001:10001 "$DATA" 2>/dev/null || chmod 777 "$DATA"   # the backend runs as uid 10001
    export VAULT_PORT="$PORT" VAULT_BIND=127.0.0.1 VAULT_INIT_TOKEN=e2e-init-token VAULT_PUBLIC_URL="http://127.0.0.1:$PORT" \
           VAULT_ALLOWED_ORIGINS="http://127.0.0.1:$PORT" VAULT_METRICS_TOKEN=e2e-metrics VAULT_DEV=0
    # the KMS emulator first: the backend reads VAULT_KMS_KEY_ID at start, so the key must exist before it
    printf 'VAULT_DEV=0\n' > /tmp/aps-vault-e2e.env
    docker compose -p "$PROJECT" -f docker-compose.yml -f ops/checks/e2e-compose.override.yml --env-file /tmp/aps-vault-e2e.env up -d localstack >/dev/null
    KMS_KEY=
    for i in $(seq 1 60); do
      KMS_KEY=$(docker compose -p "$PROJECT" -f docker-compose.yml -f ops/checks/e2e-compose.override.yml --env-file /tmp/aps-vault-e2e.env exec -T localstack awslocal kms create-key --query KeyMetadata.KeyId --output text 2>/dev/null) && [ -n "$KMS_KEY" ] && break
      sleep 2; KMS_KEY=
    done
    [ -n "$KMS_KEY" ] || echo "KMS emulator did not come up — KMS steps will fail" >&2
    cat > /tmp/aps-vault-e2e.env <<EOF
VAULT_INIT_TOKEN=e2e-init-token
VAULT_KMS_PROVIDER=aws
VAULT_KMS_KEY_ID=$KMS_KEY
VAULT_KMS_REGION=us-east-1
VAULT_KMS_ENDPOINT=http://localstack:4566/
VAULT_KMS_AWS_ACCESS_KEY=test
VAULT_KMS_AWS_SECRET_KEY=test
VAULT_PUBLIC_URL=http://localhost:$PORT
VAULT_ALLOWED_ORIGINS=http://localhost:$PORT http://127.0.0.1:$PORT
VAULT_METRICS_TOKEN=e2e-metrics
VAULT_WEBHOOK_ALLOW_PRIVATE=1
VAULT_DEV=0
VAULT_SECURITY_LOG=
VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
VAULT_PKCS11_TOKEN_LABEL=aps-vault
EOF
    docker compose -p "$PROJECT" -f docker-compose.yml -f ops/checks/e2e-compose.override.yml --env-file /tmp/aps-vault-e2e.env up -d --build >/dev/null
    for i in $(seq 1 60); do
      if H=$(curl -fs "http://127.0.0.1:$PORT/api/health" 2>/dev/null); then
        echo "$H" | grep -q '"initialized":true' && echo "warning: the e2e vault is already initialised — run 'down' first for a fresh browser check" >&2
        # a SoftHSM2 token for the HSM steps of the browser check (PIN 1234)
        docker compose -p "$PROJECT" exec -T backend sh -c 'mkdir -p /app/data/softhsm && softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678' >/dev/null 2>&1 || echo "softhsm init failed" >&2
        echo "http://localhost:$PORT"; exit 0
      fi
      sleep 1
    done
    echo "e2e stack did not come up" >&2; docker compose -p "$PROJECT" logs --tail=30 >&2; exit 1 ;;
  down)
    docker compose -p "$PROJECT" -f docker-compose.yml -f ops/checks/e2e-compose.override.yml --env-file /tmp/aps-vault-e2e.env down -v >/dev/null 2>&1 || true
    rm -rf "$DATA" 2>/dev/null || sudo -n rm -rf "$DATA" 2>/dev/null || docker run --rm -v "$DATA:/d" alpine sh -c 'rm -rf /d/* /d/.[!.]*' >/dev/null 2>&1   # files belong to uid 10001
    rm -rf "$DATA" 2>/dev/null || true ;;
esac
