#!/bin/bash
# Smoke: UI answers, API health through the frontend proxy, containers up.
#   VAULT_URL=https://vault.example.com ./smoke_test.sh   (default: http://127.0.0.1:${VAULT_PORT:-8087})
set -e
[ -f "$(dirname "$0")/.env" ] && set -a && . "$(dirname "$0")/.env" && set +a
URL="${VAULT_URL:-http://${VAULT_BIND:-127.0.0.1}:${VAULT_PORT:-8087}}"
echo "--- SMOKE: APS Vault @ $URL ---"
FE=$(curl -s -o /dev/null -w "%{http_code}" "$URL/")
[ "$FE" = "200" ] && echo "UI: OK" || { echo "UI FAIL ($FE)"; exit 1; }
H=$(curl -s "$URL/api/health")
echo "$H" | grep -q '"status":"ok"' && echo "API health: OK — $H" || { echo "API FAIL: $H"; exit 1; }
for c in $(docker ps --format "{{.Names}}" | grep -E "vault.*(backend|frontend)"); do
  docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true && echo "$c: running" || echo "$c: not found (ok if deployed differently)"
done
echo "--- DONE ---"
