#!/bin/bash
# The README's path, executed: install → store a secret → connect a service → recover after losing the server.
# Runs the release images (install.sh), an S3 (LocalStack) for the backup, and the PyPI client — the same commands
# the README shows, with a negative check next to every positive one. Leaves nothing behind unless KEEP=1.
#
#   ops/checks/golden-path.sh [version]          # default: the VERSION file; GP_PORT=8195, GP_DIR=/tmp/aps-vault-gp
#
# Exit 0 only when every check passed; one line per check, a summary at the end. The release workflow runs it on every
# tag against the images and the PyPI package it has just published (job golden-path); the pip install waits up to
# two minutes for a fresh upload to appear on PyPI.
set -uo pipefail
cd "$(dirname "$0")/../.."
VER=${1:-$(cat VERSION)}
PORT=${GP_PORT:-8195}; PORT_B=$((PORT + 1))
W=${GP_DIR:-/tmp/aps-vault-gp}
A=$W/vault-a; B=$W/vault-b
URL=http://localhost:$PORT; URL_B=http://localhost:$PORT_B
MASTER='golden path master password'
S3_USER=test; S3_PASS=test; BUCKET=gp-backups
pass=0; fail=0
ok() { if [ "$2" = 0 ]; then pass=$((pass + 1)); echo "  ✓ $1"; else fail=$((fail + 1)); echo "  ✗ $1${3:+  → $3}"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_health() { for _ in $(seq 1 60); do curl -fs "$1/api/health" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: left $A, $B and the S3 container gp-s3 running"; return; }
  for d in "$A" "$B"; do [ -f "$d/docker-compose.yml" ] && (cd "$d" && docker compose down -v >/dev/null 2>&1); done
  docker rm -f gp-s3 >/dev/null 2>&1; docker network rm gp-net >/dev/null 2>&1
  rm -rf "$W"
}
trap cleanup EXIT
cleanup; mkdir -p "$W"; trap cleanup EXIT

echo "== 1. Install (release $VER, install.sh)"
VAULT_PORT=$PORT deploy/images/install.sh "$A" "$VER" "$URL" > "$W/install-a.log" 2>&1
ok "install.sh started the vault" $? "$(tail -2 "$W/install-a.log")"
INIT=$(sed -n 's/^VAULT_INIT_TOKEN=//p' "$A/.env")
grep -q "init token: $INIT" "$W/install-a.log"; ok "install.sh printed the init token" $?
wait_health "$URL"; ok "health answers on $URL" $?
[ "$(curl -s "$URL/api/health" | j 'd["version"]')" = "$VER" ]; ok "it runs $VER" $?
[ "$(curl -s "$URL/api/health" | j 'd["cipher"]')" = aes ]; ok "the default profile is aes (not the experimental gost)" $?
[ "$(code -X POST "$URL/api/init" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\",\"init_token\":\"wrong\"}")" = 403 ]
ok "init with a wrong init token is refused (403)" $?

echo "== 2. Store a secret"
RECOVERY=$(curl -s -X POST "$URL/api/init" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\",\"init_token\":\"$INIT\"}" | j 'd["recovery_code"]')
[ -n "$RECOVERY" ]; ok "init with the init token → a recovery code, shown once" $?
[ "$(code -X POST "$URL/api/init" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\",\"init_token\":\"$INIT\"}")" != 200 ]
ok "a second init is refused" $?
JAR=$W/cookies-a
[ "$(code -c "$JAR" -X POST "$URL/api/auth/unlock" -H 'Content-Type: application/json' -d '{"master_password":"not the master password"}')" = 401 ]
ok "a wrong master password does not unlock (401)" $?
CSRF=$(curl -s -c "$JAR" -X POST "$URL/api/auth/unlock" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\"}" | j 'd["csrf_token"]')
[ -n "$CSRF" ]; ok "the master password unlocks" $?
api() { local m=$1 p=$2; shift 2; curl -s -b "$JAR" -X "$m" "$URL/api$p" -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" "$@"; }
FOLDER=$(api POST /folders -d '{"name":"billing"}' | j 'd["id"]')
OTHER=$(api POST /folders -d '{"name":"hr"}' | j 'd["id"]')
api POST /secrets -d "{\"folder_id\":$FOLDER,\"name\":\"db-password\",\"value\":\"s3cr3t-golden\",\"login\":\"billing\"}" >/dev/null
api POST /secrets -d "{\"folder_id\":$OTHER,\"name\":\"salary-db\",\"value\":\"not-for-billing\"}" >/dev/null
[ "$(api GET /secrets | j 'len(d)')" = 2 ]; ok "a folder per service, a secret in each" $?

echo "== 3. Connect a service"
TOKEN=$(api POST /tokens -d "{\"name\":\"billing-api\",\"folder_id\":$FOLDER}" | j 'd["raw_token"]')
[[ "$TOKEN" == vlt_* ]]; ok "a read-only token for the billing folder" $?
VAL=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/m/secret/db-password" | j 'd["value"]')
[ "$VAL" = s3cr3t-golden ]; ok "curl with the token reads the value" $? "$VAL"
c=$(code -H "Authorization: Bearer $TOKEN" "$URL/api/v1/m/secret/salary-db"); [ "$c" = 404 ] || [ "$c" = 403 ]
ok "the token does not reach the other folder ($c)" $?
[ "$(code -H "Authorization: Bearer $TOKEN" -X POST "$URL/api/v1/m/secret/db-password" -H 'Content-Type: application/json' -d '{"value":"x"}')" != 200 ]
ok "a read-only token cannot write" $?
PY=$(docker run --rm --network host -e VAULT_TOKEN="$TOKEN" python:3.11-slim sh -c \
  "for i in 1 2 3 4 5 6; do pip install -q --disable-pip-version-check aps-vault==$VER >/dev/null 2>&1 && break; sleep 20; done; python -c \"from aps_vault import Vault; import os; print(Vault('$URL', os.environ['VAULT_TOKEN']).get('db-password'))\"" 2>&1 | tail -1)
[ "$PY" = s3cr3t-golden ]; ok "pip install aps-vault==$VER; Vault(...).get() returns the value" $? "$PY"
TMP_TOKEN=$(api POST /tokens -d "{\"name\":\"to-revoke\",\"folder_id\":$FOLDER}" | j 'd["raw_token"]')
TMP_ID=$(api GET /tokens | j '[t["id"] for t in d if t["name"]=="to-revoke"][0]')
api DELETE "/tokens/$TMP_ID" >/dev/null
[ "$(code -H "Authorization: Bearer $TMP_TOKEN" "$URL/api/v1/m/secret/db-password")" = 401 ]
ok "a revoked token is refused at once on the server (401)" $?

echo "== 4. Recover"
docker network create gp-net >/dev/null 2>&1
docker run -d --name gp-s3 --network gp-net -e SERVICES=s3 localstack/localstack:3.8.1 >/dev/null   # any S3 will do; LocalStack 3.8.1 as in run_tests.sh
for _ in $(seq 1 60); do docker exec gp-s3 awslocal s3 mb s3://$BUCKET >/dev/null 2>&1 && break; sleep 2; done
docker exec gp-s3 awslocal s3 ls s3://$BUCKET >/dev/null 2>&1; ok "an S3 bucket for backups" $?
# a private S3 endpoint (this LocalStack) needs VAULT_WEBHOOK_ALLOW_PRIVATE=1; a public https:// one does not
cat >> "$A/.env" <<ENV
VAULT_BACKUP_S3_ENDPOINT=http://gp-s3:4566
VAULT_BACKUP_S3_BUCKET=$BUCKET
VAULT_BACKUP_S3_ACCESS_KEY=$S3_USER
VAULT_BACKUP_S3_SECRET_KEY=$S3_PASS
VAULT_WEBHOOK_ALLOW_PRIVATE=1
ENV
(cd "$A" && docker compose up -d >/dev/null 2>&1 && docker network connect gp-net "$(docker compose ps -q backend)")
wait_health "$URL"
CSRF=$(curl -s -c "$JAR" -X POST "$URL/api/auth/unlock" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\"}" | j 'd["csrf_token"]')
api POST /backup/keygen -d "{\"master_password\":\"$MASTER\"}" | j 'd["private_key"]' > "$W/other-key.txt"   # a real key of the same kind, replaced next — for the negative check
api POST /backup/keygen -d "{\"master_password\":\"$MASTER\"}" | j 'd["private_key"]' > "$W/backup-key.txt"
[ -s "$W/backup-key.txt" ]; ok "backup key pair: the private key is shown once and kept off the server" $?
[ "$(api PUT /backup/config -d '{"enabled":true,"mode":"change"}' -o /dev/null -w '%{http_code}')" = 200 ]; ok "encrypted backups on" $?
OBJ=$(api POST /backup/run | j 'd["object_key"] if d["state"]=="ok" else ""')
[ -n "$OBJ" ]; ok "a backup copy is in S3 ($OBJ)" $?

echo "   -- the server is lost: vault A and its data are gone"
cp "$A/.env" "$A.env.saved"      # the operator knows the S3 settings; nothing else of A survives
(cd "$A" && docker compose down -v >/dev/null 2>&1)
[ "$(code "$URL/api/health")" = 000 ]; ok "vault A is gone" $?

VAULT_PORT=$PORT_B deploy/images/install.sh "$B" "$VER" "$URL_B" > "$W/install-b.log" 2>&1; ok "a fresh installation B (install.sh)" $?
IMG=ghcr.io/kzhebenev/aps-vault/backend:$(sed -n 's/^VAULT_VERSION=//p' "$B/.env")   # as in the README
# the S3 settings go into the new .env (they are not secret to the operator and B will back up there too)
grep '^VAULT_BACKUP_S3_\|^VAULT_WEBHOOK_ALLOW_PRIVATE' "$A.env.saved" >> "$B/.env"
LATEST=$(docker run --rm --network gp-net --env-file "$B/.env" "$IMG" python -m backup list 2>"$W/list.err" | tail -1 | awk '{print $2}')
[ "$LATEST" = "$OBJ" ]; ok "python -m backup list → the newest copy is the one made before the loss" $? "$LATEST $(tail -1 "$W/list.err")"
docker run --rm --network gp-net --env-file "$B/.env" "$IMG" python -m backup fetch "$LATEST" > "$W/latest.vbak" 2>"$W/fetch.err"
[ -s "$W/latest.vbak" ]; ok "python -m backup fetch → the object" $? "$(tail -1 "$W/fetch.err")"
docker run --rm -v "$W:/w" "$IMG" python -m backup decrypt /w/latest.vbak --key /w/other-key.txt > /dev/null 2>&1
[ $? != 0 ]; ok "a different private key does not open the backup" $?
docker run --rm -v "$W:/w" "$IMG" python -m backup decrypt /w/latest.vbak --key /w/backup-key.txt > "$W/dump.json" 2>"$W/decrypt.err"
ok "python -m backup decrypt with the saved private key" $? "$(tail -1 "$W/decrypt.err")"
(cd "$B" && docker compose stop backend >/dev/null 2>&1 && docker compose run --rm -T -v "$W:/w" backend python -m backup restore /w/dump.json > "$W/restore.log" 2>&1)
ok "python -m backup restore into B's empty database" $? "$(tail -1 "$W/restore.log")"
(cd "$B" && docker compose run --rm -T -v "$W:/w" backend python -m backup restore /w/dump.json > /dev/null 2>&1)
[ $? != 0 ]; ok "a second restore into the now initialised database is refused" $?
(cd "$B" && docker compose up -d >/dev/null 2>&1); wait_health "$URL_B"
JAR=$W/cookies-b
[ "$(code -c "$JAR" -X POST "$URL_B/api/auth/unlock" -H 'Content-Type: application/json' -d '{"master_password":"not the master password"}')" = 401 ]
ok "B: a wrong master password still does not unlock" $?
[ "$(code -c "$JAR" -X POST "$URL_B/api/auth/unlock" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\"}")" = 200 ]
ok "B unlocks with the old master password" $?
VAL=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL_B/api/v1/m/secret/db-password" | j 'd["value"]')
[ "$VAL" = s3cr3t-golden ]; ok "the service's old token reads the secret from B — only the address changed" $? "$VAL"
[ "$(code -H "Authorization: Bearer $TMP_TOKEN" "$URL_B/api/v1/m/secret/db-password")" = 401 ]
ok "the token revoked before the loss stays revoked on B" $?

echo "   -- the master password is forgotten"
[ "$(code -X POST "$URL_B/api/auth/recover" -H 'Content-Type: application/json' -d '{"recovery_code":"WRONG-CODE","new_master_password":"a brand new master password"}')" != 200 ]
ok "a wrong recovery code is refused" $?
NEWREC=$(curl -s -X POST "$URL_B/api/auth/recover" -H 'Content-Type: application/json' -d "{\"recovery_code\":\"$RECOVERY\",\"new_master_password\":\"a brand new master password\"}" | j 'd.get("new_recovery_code","")')
[ -n "$NEWREC" ]; ok "the recovery code sets a new master password (and gives a new code)" $?
[ "$(code -X POST "$URL_B/api/auth/unlock" -H 'Content-Type: application/json' -d "{\"master_password\":\"$MASTER\"}")" = 401 ]
ok "the old master password no longer unlocks" $?
[ "$(code -X POST "$URL_B/api/auth/unlock" -H 'Content-Type: application/json' -d '{"master_password":"a brand new master password"}')" = 200 ]
ok "the new one does" $?
VAL=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL_B/api/v1/m/secret/db-password" | j 'd["value"]')
[ "$VAL" = s3cr3t-golden ]; ok "services did not notice: the token still reads the secret" $? "$VAL"

echo "ИТОГ: $pass ok, $fail fail"
[ "$fail" = 0 ]
