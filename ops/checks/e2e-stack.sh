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
    mkdir -p "$DATA"; chown 10001:10001 "$DATA" 2>/dev/null || true
    export VAULT_PORT="$PORT" VAULT_BIND=127.0.0.1 VAULT_INIT_TOKEN=e2e-init-token VAULT_PUBLIC_URL="http://127.0.0.1:$PORT" \
           VAULT_ALLOWED_ORIGINS="http://127.0.0.1:$PORT" VAULT_METRICS_TOKEN=e2e-metrics VAULT_DEV=0
    cat > /tmp/aps-vault-e2e.env <<EOF
VAULT_INIT_TOKEN=e2e-init-token
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
      if curl -fs "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
        # a SoftHSM2 token for the HSM steps of the browser check (PIN 1234)
        docker compose -p "$PROJECT" exec -T backend sh -c 'mkdir -p /app/data/softhsm && softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678' >/dev/null 2>&1 || echo "softhsm init failed" >&2
        echo "http://localhost:$PORT"; exit 0
      fi
      sleep 1
    done
    echo "e2e stack did not come up" >&2; docker compose -p "$PROJECT" logs --tail=30 >&2; exit 1 ;;
  down)
    docker compose -p "$PROJECT" -f docker-compose.yml -f ops/checks/e2e-compose.override.yml --env-file /tmp/aps-vault-e2e.env down -v >/dev/null 2>&1 || true
    rm -rf "$DATA" ;;
esac
