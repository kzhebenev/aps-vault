#!/bin/bash
# Real check of the External Secrets Operator integration against a live APS Vault.
# Needs a cluster with ESO installed and kubectl pointed at it (KUBECTL overrides the command,
# e.g. KUBECTL="docker exec -i k3s kubectl" for a throwaway k3s in Docker — see README.md).
#
#   VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_… ./test-k3s.sh <folder> <secret-name>
#
# Positive: ESO (vault provider AND webhook provider) produces Kubernetes Secrets whose bytes equal
# what the machine API returns for the same token. Negative: a store with a wrong token never
# becomes Ready and the ExternalSecret reports SecretSyncedError.
set -euo pipefail
MOUNT="${1:?folder}"; NAME="${2:?secret name}"
: "${VAULT_URL:?}"; : "${VAULT_TOKEN:?}"
KUBECTL="${KUBECTL:-kubectl}"
NS="${NS:-aps-vault-eso-test}"
k() { $KUBECTL "$@"; }
pass=0; fail=0
ok() { if [ "$2" = 1 ]; then pass=$((pass+1)); echo "  ✓ $1"; else fail=$((fail+1)); echo "  ✗ $1 ${3:-}"; fi; }

direct=$(curl -fsS -H "Authorization: Bearer $VAULT_TOKEN" "$VAULT_URL/api/v1/m/secret/$NAME")
want_value=$(printf '%s' "$direct" | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"], end="")')
want_login=$(printf '%s' "$direct" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("login",""), end="")')
[ -n "$want_value" ] || { echo "the machine API returned no value for $NAME — a sealed token? ESO cannot unseal"; exit 2; }

k delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
k create ns "$NS" >/dev/null
k -n "$NS" create secret generic aps-vault-token --from-literal=token="$VAULT_TOKEN" >/dev/null
# ESO lets the webhook provider read only Secrets labelled for it (a guard against exfiltrating arbitrary Secrets through templated requests)
k -n "$NS" label secret aps-vault-token external-secrets.io/type=webhook >/dev/null
k -n "$NS" create secret generic aps-vault-wrong --from-literal=token="vlt_not_a_real_token_at_all_0000000000" >/dev/null
k apply -f - >/dev/null <<EOF
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: {name: aps-vault, namespace: $NS}
spec:
  provider:
    vault:
      server: "$VAULT_URL"
      path: "$MOUNT"
      version: "v2"
      auth: {tokenSecretRef: {name: aps-vault-token, key: token}}
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: {name: aps-vault-wrong, namespace: $NS}
spec:
  provider:
    vault:
      server: "$VAULT_URL"
      path: "$MOUNT"
      version: "v2"
      auth: {tokenSecretRef: {name: aps-vault-wrong, key: token}}
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: {name: aps-vault-webhook, namespace: $NS}
spec:
  provider:
    webhook:
      url: "$VAULT_URL/api/v1/m/secret/{{ .remoteRef.key }}"
      method: GET
      headers: {Authorization: "Bearer {{ .auth.token }}", Accept: application/json}
      secrets: [{name: auth, secretRef: {name: aps-vault-token, key: token}}]
      result: {jsonPath: "$.{{ .remoteRef.property }}"}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: via-vault-provider, namespace: $NS}
spec:
  refreshInterval: 10s
  secretStoreRef: {name: aps-vault, kind: SecretStore}
  target: {name: via-vault-provider}
  data:
    - {secretKey: PASSWORD, remoteRef: {key: $NAME, property: value}}
    - {secretKey: LOGIN, remoteRef: {key: $NAME, property: login}}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: via-webhook, namespace: $NS}
spec:
  refreshInterval: 10s
  secretStoreRef: {name: aps-vault-webhook, kind: SecretStore}
  target: {name: via-webhook}
  data:
    - {secretKey: PASSWORD, remoteRef: {key: $NAME, property: value}}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: via-wrong-token, namespace: $NS}
spec:
  refreshInterval: 10s
  secretStoreRef: {name: aps-vault-wrong, kind: SecretStore}
  target: {name: via-wrong-token}
  data:
    - {secretKey: PASSWORD, remoteRef: {key: $NAME, property: value}}
EOF

wait_secret() { for i in $(seq 1 40); do k -n "$NS" get secret "$1" >/dev/null 2>&1 && return 0; sleep 3; done; return 1; }
read_key() { k -n "$NS" get secret "$1" -o "jsonpath={.data.$2}" | base64 -d; }

if wait_secret via-vault-provider; then
  ok "vault provider: Kubernetes Secret created from the facade" 1
  ok "vault provider: PASSWORD equals the machine-API value byte for byte" "$([ "$(read_key via-vault-provider PASSWORD)" = "$want_value" ] && echo 1 || echo 0)"
  ok "vault provider: LOGIN equals the secret's login" "$([ "$(read_key via-vault-provider LOGIN)" = "$want_login" ] && echo 1 || echo 0)" "got=$(read_key via-vault-provider LOGIN)"
else
  ok "vault provider: Kubernetes Secret created" 0 "$(k -n "$NS" get externalsecret via-vault-provider -o jsonpath='{.status.conditions[*].message}')"
fi
if wait_secret via-webhook; then
  ok "webhook provider: Secret created from the machine API" 1
  ok "webhook provider: PASSWORD equals the machine-API value" "$([ "$(read_key via-webhook PASSWORD)" = "$want_value" ] && echo 1 || echo 0)"
else
  ok "webhook provider: Secret created" 0 "$(k -n "$NS" get externalsecret via-webhook -o jsonpath='{.status.conditions[*].message}')"
fi
# negative: the wrong token must not produce a Secret, and the status must say why
sleep 15
if k -n "$NS" get secret via-wrong-token >/dev/null 2>&1; then ok "wrong token: NO Secret is created" 0 "a Secret exists!"; else ok "wrong token: NO Secret is created" 1; fi
cond=$(k -n "$NS" get externalsecret via-wrong-token -o jsonpath='{.status.conditions[0].reason} {.status.conditions[0].status} {.status.conditions[0].message}' 2>/dev/null || true)
ok "wrong token: ExternalSecret reports a sync error (visible reason)" "$(echo "$cond" | grep -qiE 'SecretSyncedError|False' && echo 1 || echo 0)" "cond=$cond"
store=$(k -n "$NS" get secretstore aps-vault -o jsonpath='{.status.conditions[0].reason} {.status.conditions[0].status}' 2>/dev/null || true)
ok "good store is Valid/Ready (token checked at lookup-self)" "$(echo "$store" | grep -q True && echo 1 || echo 0)" "store=$store"
echo "RESULT: $pass ok, $fail fail"
[ "${KEEP:-0}" = 1 ] || k delete ns "$NS" --wait=false >/dev/null 2>&1 || true
[ "$fail" = 0 ]
