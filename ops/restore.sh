#!/bin/bash
# APS Vault restore from an archive made by ops/backup.sh.
#   ./ops/restore.sh backups/vault_20261002-120000.tar.zst
#   VAULT_CONTAINER=… VAULT_DATA_DIR=… ./ops/restore.sh <archive>
# Replaces vault.db and config.json; keeps the current pair next to them as *.before-restore.<ts>.
set -euo pipefail
BACKUP="${1:?usage: restore.sh <archive.tar.zst>}"
[ -f "$BACKUP" ] || { echo "restore: $BACKUP not found" >&2; exit 1; }
VAULT_CONTAINER="${VAULT_CONTAINER:-$(docker ps -a --format '{{.Names}}' | grep -E 'vault.*backend' | head -1)}"
VAULT_DATA_DIR="${VAULT_DATA_DIR:-$(cd "$(dirname "$0")/.." && pwd)/data}"

echo "The current vault database in $VAULT_DATA_DIR will be REPLACED. Take a fresh backup first."
read -r -p "Continue (y/N)? " ans
[ "$ans" = "y" ] || exit 0

[ -n "$VAULT_CONTAINER" ] && docker stop "$VAULT_CONTAINER" >/dev/null
TS=$(date -u +%Y%m%d-%H%M%S)
for f in vault.db config.json; do [ -f "$VAULT_DATA_DIR/$f" ] && cp "$VAULT_DATA_DIR/$f" "$VAULT_DATA_DIR/$f.before-restore.$TS"; done

TMP=$(mktemp -d)
trap 'shred -uz "$TMP"/* 2>/dev/null || true; rm -rf "$TMP"' EXIT
zstd -dq "$BACKUP" -o "$TMP/data.tar"
tar -xf "$TMP/data.tar" -C "$TMP"
install -m 600 -o 10001 -g 10001 "$TMP/vault.db" "$VAULT_DATA_DIR/vault.db"
[ -f "$TMP/config.json" ] && install -m 600 -o 10001 -g 10001 "$TMP/config.json" "$VAULT_DATA_DIR/config.json"   # only in archives of ≤0.5 installs

[ -n "$VAULT_CONTAINER" ] && docker start "$VAULT_CONTAINER" >/dev/null
echo "restore: done from $BACKUP; previous files kept as *.before-restore.$TS. The vault comes up locked — unlock with the master password."
