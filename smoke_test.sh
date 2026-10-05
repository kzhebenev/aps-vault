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
# the deployed version must be the one in this tree — a stale image is a failure, not a note
V=$(cat "$(dirname "$0")/VERSION" 2>/dev/null); AV=$(echo "$H" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
[ -z "$V" ] || [ "$AV" = "$V" ] && echo "version: $AV" || { echo "VERSION FAIL: API says $AV, tree says $V"; exit 1; }
# the cluster stand (deploy/cluster), when it runs on this host: its frontend must answer and be current
if docker ps --format "{{.Names}}" 2>/dev/null | grep -q '^aps-vault-cluster-frontend'; then
  CU="http://127.0.0.1:${CLUSTER_PORT:-8188}"
  CF=$(curl -s -m 8 -o /dev/null -w "%{http_code}" "$CU/"); CH=$(curl -s -m 8 "$CU/api/health")
  CV=$(echo "$CH" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
  [ "$CF" = "200" ] && echo "$CH" | grep -q '"status":"ok"' && { [ -z "$V" ] || [ "$CV" = "$V" ]; } \
    && echo "cluster @ $CU: OK — $CV" || { echo "CLUSTER FAIL: UI $CF, health: $CH"; exit 1; }
fi
for c in $(docker ps --format "{{.Names}}" | grep -E "vault.*(backend|frontend)"); do
  docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true && echo "$c: running" || echo "$c: not found (ok if deployed differently)"
done
echo "--- DONE ---"
