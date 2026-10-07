#!/bin/sh
# Install APS Vault from the release images with the update agent (0.38).
#   ./install.sh <directory> [version] [public-url]          VAULT_PORT / VAULT_BIND from the environment go into .env
# Writes <directory>/docker-compose.yml and <directory>/.env (mode 0600) with fresh random tokens, then starts it.
# Open the printed address and initialise the vault with the init token.
set -eu
DIR=${1:?usage: install.sh <directory> [version] [public-url]}
VERSION=${2:-latest}
URL=${3:-http://localhost:8087}
HERE=$(cd "$(dirname "$0")" && pwd)
if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsS https://api.github.com/repos/kzhebenev/aps-vault/releases/latest | sed -n 's/.*"tag_name": *"v\{0,1\}\([0-9.]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || { echo "could not find the latest release; pass a version" >&2; exit 1; }
fi
mkdir -p "$DIR"; DIR=$(cd "$DIR" && pwd)
[ -e "$DIR/.env" ] && { echo "$DIR/.env exists — this looks like an installation already; not touching it" >&2; exit 1; }
cp "$HERE/docker-compose.yml" "$DIR/docker-compose.yml"
rnd() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
umask 077
cat > "$DIR/.env" <<ENV
# APS Vault $VERSION — written by install.sh $(date -u +%Y-%m-%dT%H:%MZ). Every variable: docs/DEPLOYMENT.md
COMPOSE_PROJECT_NAME=$(basename "$DIR" | tr -c 'a-z0-9_\n-' '-')
VAULT_VERSION=$VERSION
VAULT_INSTALL_DIR=$DIR
VAULT_HOST_NAME=$(hostname)
VAULT_PUBLIC_URL=$URL
VAULT_ALLOWED_ORIGINS=$URL
VAULT_INIT_TOKEN=$(rnd 24)
VAULT_UPDATE_AGENT_TOKEN=$(rnd 32)
VAULT_TRUSTED_PROXIES=127.0.0.1/32 ::1/128 172.16.0.0/12
VAULT_BIND=${VAULT_BIND:-127.0.0.1}
VAULT_PORT=${VAULT_PORT:-8087}
ENV
cd "$DIR"
docker compose pull -q
docker compose up -d
echo "APS Vault $VERSION is starting in $DIR"
echo "Open $URL and initialise with the init token: $(sed -n 's/^VAULT_INIT_TOKEN=//p' .env)"
