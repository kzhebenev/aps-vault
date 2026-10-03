#!/bin/bash
# Push the vault's own lock-outs into fail2ban so a brute-forcer is cut off at the firewall,
# not only at the application. Run from cron every minute on the fail2ban host.
#
#   VAULT_URL=https://vault.example.com VAULT_METRICS_TOKEN=… ops/fail2ban/sync-bans.sh
#
# GET /api/security/lockdowns returns the addresses currently over the failed-attempt budget;
# each is banned in the aps-vault jail (banip is idempotent — already banned is a no-op).
set -euo pipefail
: "${VAULT_URL:?set VAULT_URL}"; : "${VAULT_METRICS_TOKEN:?set VAULT_METRICS_TOKEN}"
JAIL="${JAIL:-aps-vault}"
ips=$(curl -fsS --max-time 10 -H "Authorization: Bearer $VAULT_METRICS_TOKEN" "$VAULT_URL/api/security/lockdowns" \
      | python3 -c 'import sys,json; [print(r["ip"]) for r in json.load(sys.stdin)["locked"]]')
n=0
for ip in $ips; do
  [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]] || continue       # never pass anything but an address to fail2ban-client
  fail2ban-client set "$JAIL" banip "$ip" >/dev/null 2>&1 && n=$((n+1)) || true
done
echo "sync-bans: $n address(es) pushed to jail $JAIL"
