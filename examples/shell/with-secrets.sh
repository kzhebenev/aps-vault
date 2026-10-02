#!/bin/bash
# Export secrets from APS Vault as environment variables, then exec the program.
# No code changes in the program: it keeps reading ${DB_PASSWORD} etc.
#
#   with-secrets.sh <secret>:<ENV_VAR> [<secret>:<ENV_VAR> ...] -- <command> [args]
#   VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_…  (or VAULT_TOKEN_FILE=/etc/app/vault.token)
#
# Fails closed: a missing secret or an unreachable vault stops the start.
set -euo pipefail
: "${VAULT_URL:?set VAULT_URL}"
if [ -z "${VAULT_TOKEN:-}" ] && [ -n "${VAULT_TOKEN_FILE:-}" ]; then VAULT_TOKEN=$(<"$VAULT_TOKEN_FILE"); fi
: "${VAULT_TOKEN:?set VAULT_TOKEN or VAULT_TOKEN_FILE}"
[[ "$VAULT_TOKEN" == vlt_* ]] || { echo "with-secrets: VAULT_TOKEN must be a service token (vlt_…)" >&2; exit 2; }

pairs=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do pairs+=("$1"); shift; done
[ "${1:-}" = "--" ] && shift || { echo "usage: $0 secret:ENV ... -- command" >&2; exit 2; }
[ $# -gt 0 ] || { echo "with-secrets: no command given" >&2; exit 2; }

for p in "${pairs[@]}"; do
  name=${p%%:*}; var=${p#*:}
  [[ "$var" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "with-secrets: bad variable name '$var'" >&2; exit 2; }
  # retries only on transient failures (timeouts, 429, 5xx) — a 404 is final; value extracted
  # with python to avoid shell quoting traps
  value=$(curl -fsS --retry 3 --retry-delay 1 --max-time 5 \
            -H "Authorization: Bearer $VAULT_TOKEN" \
            "$VAULT_URL/api/v1/m/secret/$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$name")" \
          | python3 -c 'import sys,json; sys.stdout.write(json.load(sys.stdin)["value"])' 2>/dev/null) \
    || { echo "with-secrets: cannot read '$name' from vault" >&2; exit 1; }
  export "$var=$value"
done
unset VAULT_TOKEN   # the program does not need the token itself
exec "$@"
