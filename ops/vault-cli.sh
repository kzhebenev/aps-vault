#!/bin/bash
# vault — CLI wrapper for APS Vault.
# Использует service-token (VAULT_TOKEN из env или ~/.vault-token).
#
# Usage:
#   vault get <name>           # значение секрета (в текущем scope токена)
#   vault put <name> [value]   # создать/обновить секрет (нужен can_write; без value — stdin)
#   vault list                 # список секретов в scope
#   vault health               # статус + scope текущего токена
#   vault get-all              # все секреты в формате KEY=VALUE (для eval $(...))
#
# Конфиг:
#   VAULT_TOKEN env-var (vlt_*)  — либо файл ~/.vault-token / /etc/vault.conf
#   VAULT_URL    (required, e.g. https://vault.example.com)

set -euo pipefail

# Загружаем токен из конфигов если не задан в env
if [ -z "${VAULT_TOKEN:-}" ]; then
    for f in /etc/vault.conf ~/.vault-token; do
        if [ -f "$f" ]; then
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || true
            [ -n "${VAULT_TOKEN:-}" ] && break
        fi
    done
fi

VAULT_URL="${VAULT_URL:-}"
[ -z "$VAULT_URL" ] && { echo "vault: set VAULT_URL (https://vault.example.com) in env or /etc/vault.conf" >&2; exit 2; }

if [ -z "${VAULT_TOKEN:-}" ] || [[ ! "$VAULT_TOKEN" =~ ^vlt_ ]]; then
    echo "vault: задай VAULT_TOKEN (vlt_*) в env, /etc/vault.conf или ~/.vault-token" >&2
    exit 2
fi

CMD="${1:-help}"
shift || true

api() {
    local path="$1"
    curl -fsS -H "Authorization: Bearer $VAULT_TOKEN" "$VAULT_URL$path"
}

case "$CMD" in
    health)
        api "/api/v1/m/health" | python3 -m json.tool
        ;;
    list|ls)
        api "/api/v1/m/secrets" | python3 -c "
import sys, json
for s in json.load(sys.stdin):
    flags = ('T' if s['has_totp'] else '-') + ('N' if s['has_notes'] else '-')
    print(f'  [{flags}] {s[\"name\"]:30s} {s.get(\"tags\",\"\")}')"
        ;;
    put)
        # vault put <name> [value]   (без value — читает из stdin, удобно для пайпов)
        # Требует can_write на токене (v0.3.1)
        NAME="${1:?usage: vault put <name> [value]}"
        VALUE="${2:-}"
        if [ -z "$VALUE" ]; then VALUE=$(cat); fi
        BODY=$(VAL="$VALUE" python3 -c 'import json,os; print(json.dumps({"value": os.environ["VAL"]}))')
        curl -fsS -X POST -H "Authorization: Bearer $VAULT_TOKEN" -H "Content-Type: application/json"              -d "$BODY" "$VAULT_URL/api/v1/m/secret/$NAME" | python3 -m json.tool
        ;;
    get)
        NAME="${1:?usage: vault get <name>}"
        api "/api/v1/m/secret/$NAME" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['value'])"
        ;;
    get-all|export)
        api "/api/v1/m/secrets" | python3 -c "
import sys, json, urllib.request, os, re, shlex
secrets = json.load(sys.stdin)
tok = os.environ.get('VAULT_TOKEN','')
url = os.environ['VAULT_URL']
NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\$')
for s in secrets:
    name = s['name']
    # Имя станет shell-переменной → строго валидируем, иначе пропускаем
    # (а не пытаемся экранировать имя — невалидное имя env-var бессмысленно).
    if not NAME_RE.match(name):
        sys.stderr.write(f'vault: пропущен секрет с недопустимым именем env-var: {name!r}\n')
        continue
    req = urllib.request.Request(f\"{url}/api/v1/m/secret/{name}\",
        headers={'Authorization': f'Bearer {tok}'})
    with urllib.request.urlopen(req, timeout=8) as r:
        v = json.load(r)['value']
    # shlex.quote → одинарные кавычки, bash не интерпретирует \$ и backtick.
    # Защита от command injection при eval \$(vault get-all).
    print(f'export {name}={shlex.quote(v)}')"
        ;;
    help|--help|-h|*)
        cat <<EOF
vault — CLI для APS Vault

Команды:
  vault health             статус + scope токена
  vault list               список секретов в scope (без значений)
  vault get <NAME>         значение секрета (для command substitution)
  vault get-all            все секреты в формате 'export KEY=VALUE' (для eval)

Конфиг (в порядке поиска):
  \$VAULT_TOKEN env-var
  /etc/vault.conf
  ~/.vault-token

Примеры:
  export DEEPSEEK_API_KEY=\$(vault get DEEPSEEK_API_KEY)
  eval "\$(vault get-all)"  # все секреты в текущую сессию
EOF
        ;;
esac
