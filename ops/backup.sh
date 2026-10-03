#!/bin/bash
# APS Vault backup (single node, SQLite): consistent SQLite snapshot (online backup API inside
# the container) + config.json if present → one zstd archive. Since 0.6 the master-password
# verifier lives inside vault.db (table vault_config); config.json exists only on installs
# upgraded from 0.5 and is kept for completeness. Without the master password the archive is
# ciphertext. Cluster installs on PostgreSQL: use pg_dump instead (docs/CLUSTER.md).
#
#   ./ops/backup.sh                       # defaults below
#   VAULT_CONTAINER=aps-vault-backend-1 VAULT_DATA_DIR=./data BACKUP_DIR=/srv/backups ./ops/backup.sh
#
# Keeps the newest KEEP archives. Run from cron; ship BACKUP_DIR off-host (restic, S3, …).
set -euo pipefail
VAULT_CONTAINER="${VAULT_CONTAINER:-$(docker ps --format '{{.Names}}' | grep -E 'vault.*backend' | head -1)}"
VAULT_DATA_DIR="${VAULT_DATA_DIR:-$(cd "$(dirname "$0")/.." && pwd)/data}"
BACKUP_DIR="${BACKUP_DIR:-$(cd "$(dirname "$0")/.." && pwd)/backups}"
KEEP="${KEEP:-30}"
[ -n "$VAULT_CONTAINER" ] || { echo "backup: set VAULT_CONTAINER (no running *vault*backend* container found)" >&2; exit 1; }

TS=$(date -u +%Y%m%d-%H%M%S)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$BACKUP_DIR"

docker exec "$VAULT_CONTAINER" python3 -c "
import sqlite3
src = sqlite3.connect('/app/data/vault.db'); dst = sqlite3.connect('/tmp/vault.db.snap')
with dst: src.backup(dst)
" >/dev/null
docker cp "$VAULT_CONTAINER:/tmp/vault.db.snap" "$TMP/vault.db" >/dev/null
docker exec "$VAULT_CONTAINER" rm -f /tmp/vault.db.snap >/dev/null 2>&1 || true
[ -f "$VAULT_DATA_DIR/config.json" ] && cp "$VAULT_DATA_DIR/config.json" "$TMP/config.json"
FILES="vault.db$([ -f "$TMP/config.json" ] && echo " config.json")"

TAR="$BACKUP_DIR/vault_$TS.tar.zst"
tar -C "$TMP" -cf - $FILES | zstd -q -19 -o "$TAR"
cat > "$BACKUP_DIR/vault_$TS.meta.json" <<EOF
{"ts_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "files": [$(echo $FILES | sed 's/[^ ]*/"&"/g; s/ /, /g')],
 "size_bytes": $(stat -c %s "$TAR"),
 "note": "values are AES-GCM ciphertext; restore needs the master password (or service tokens for the machine API)"}
EOF
ls -1t "$BACKUP_DIR"/vault_*.tar.zst 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
ls -1t "$BACKUP_DIR"/vault_*.meta.json 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup: $TAR ($(stat -c %s "$TAR") bytes)"
