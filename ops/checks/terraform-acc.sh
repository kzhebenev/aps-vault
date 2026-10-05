#!/bin/bash
# Live acceptance of the Terraform/OpenTofu provider (clients/terraform) against a real APS Vault:
# unlocks with the master password, makes a scratch folder + a can_write token, runs the Go acceptance
# tests in a container with OpenTofu, then deletes the folder (tokens and secrets go with it).
#   VAULT_URL=https://aps-vault.devkz.ru VAULT_MASTER='…' ./ops/checks/terraform-acc.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
URL="${VAULT_URL:-http://127.0.0.1:8186}"; MASTER="${VAULT_MASTER:?set VAULT_MASTER}"
TOFU="${TOFU_BIN:-/usr/local/bin/tofu}"; [ -x "$TOFU" ] || { echo "no OpenTofu/Terraform binary at $TOFU (TOFU_BIN=…)"; exit 2; }
read -r FID TOKEN < <(python3 - "$URL" "$MASTER" <<'PY'
import json, sys, urllib.request, http.cookiejar
url, pw = sys.argv[1], sys.argv[2]
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def req(m, p, body=None, hdr=None):
    r = urllib.request.Request(url + p, data=json.dumps(body).encode() if body is not None else None, method=m, headers={"Content-Type": "application/json", **(hdr or {})})
    return json.loads(op.open(r, timeout=20).read() or b"{}")
csrf = {"X-CSRF-Token": req("POST", "/api/auth/unlock", {"master_password": pw})["csrf_token"]}
import time
fid = req("POST", "/api/folders", {"name": f"tf-acc-{int(time.time())}"}, csrf)["id"]
tok = req("POST", "/api/tokens", {"name": f"tf-acc-{int(time.time())}", "folder_id": fid, "can_write": True}, csrf)["raw_token"]
print(fid, tok)
PY
)
cleanup() {
  python3 - "$URL" "$MASTER" "$FID" <<'PY'
import json, sys, urllib.request, http.cookiejar
url, pw, fid = sys.argv[1], sys.argv[2], sys.argv[3]
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def req(m, p, body=None, hdr=None):
    r = urllib.request.Request(url + p, data=json.dumps(body).encode() if body is not None else None, method=m, headers={"Content-Type": "application/json", **(hdr or {})})
    return op.open(r, timeout=20).read()
csrf = {"X-CSRF-Token": json.loads(req("POST", "/api/auth/unlock", {"master_password": pw}))["csrf_token"]}
req("DELETE", f"/api/folders/{fid}", None, csrf); print("scratch folder removed")
PY
}
trap cleanup EXIT
echo "--- terraform provider acceptance @ $URL (folder id $FID) ---"
docker run --rm -v "$PWD/clients:/src" -v "$TOFU:/usr/local/bin/tofu:ro" -w /src/terraform \
  -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=auto -e TF_ACC=1 -e TF_ACC_TERRAFORM_PATH=/usr/local/bin/tofu -e TF_ACC_PROVIDER_HOST=registry.opentofu.org \
  -e APSVAULT_ACC_URL="$URL" -e APSVAULT_ACC_TOKEN="$TOKEN" -e VAULT_URL= -e VAULT_TOKEN= \
  golang:1.25-alpine sh -c 'gofmt -l . && go vet ./... && go test -run "TestLive" -v ./internal/provider/ > /tmp/t.log 2>&1; rc=$?; grep -vE "^go: downloading" /tmp/t.log | tail -60; exit $rc'
