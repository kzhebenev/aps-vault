#!/bin/bash
# CI integrations (0.34): validate the GitHub action and the GitLab template, then run the GitLab template's
# before_script lines and the action's fetch step for real against a live vault (scratch folder + read token,
# removed afterwards). Needs python3 with PyYAML on the host.
#   VAULT_URL=https://aps-vault.devkz.ru VAULT_MASTER='…' ./ops/checks/ci-templates.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
URL="${VAULT_URL:-http://127.0.0.1:8186}"; MASTER="${VAULT_MASTER:?set VAULT_MASTER}"
python3 - <<'PY'
import yaml
a = yaml.safe_load(open("clients/github-action/action.yml"))
assert a["runs"]["using"] == "composite" and set(a["inputs"]) == {"url", "token", "secrets", "client_key"} and "variables" in a["outputs"], a.keys()
g = yaml.safe_load(open("clients/gitlab-ci/aps-vault.gitlab-ci.yml"))
assert ".aps-vault-secrets" in g and "aps-vault-secrets" in g and g["aps-vault-secrets"]["artifacts"]["reports"]["dotenv"] == "aps-vault.env"
assert any("--export" in str(l) for l in g[".aps-vault-secrets"]["before_script"]), g[".aps-vault-secrets"]
print("yaml: action + gitlab template ok")
PY
read -r FID TOKEN < <(python3 - "$URL" "$MASTER" <<'PY'
import json, sys, time, urllib.request, http.cookiejar
url, pw = sys.argv[1], sys.argv[2]
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def req(m, p, body=None, hdr=None):
    r = urllib.request.Request(url + p, data=json.dumps(body).encode() if body is not None else None, method=m, headers={"Content-Type": "application/json", **(hdr or {})})
    return json.loads(op.open(r, timeout=20).read() or b"{}")
csrf = {"X-CSRF-Token": req("POST", "/api/auth/unlock", {"master_password": pw})["csrf_token"]}
fid = req("POST", "/api/folders", {"name": f"ci-check-{int(time.time())}"}, csrf)["id"]
req("POST", "/api/secrets", {"folder_id": fid, "name": "db-password", "value": "ci-check-value-1", "login": "ci-user"}, csrf)
tok = req("POST", "/api/tokens", {"name": f"ci-check-{int(time.time())}", "folder_id": fid}, csrf)["raw_token"]
print(fid, tok)
PY
)
cleanup() { python3 - "$URL" "$MASTER" "$FID" <<'PY'
import json, sys, urllib.request, http.cookiejar
url, pw, fid = sys.argv[1], sys.argv[2], sys.argv[3]
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def req(m, p, body=None, hdr=None):
    r = urllib.request.Request(url + p, data=json.dumps(body).encode() if body is not None else None, method=m, headers={"Content-Type": "application/json", **(hdr or {})})
    return op.open(r, timeout=20).read()
csrf = {"X-CSRF-Token": json.loads(req("POST", "/api/auth/unlock", {"master_password": pw}))["csrf_token"]}
for s in json.loads(req("GET", "/api/secrets", None, csrf)):
    if s["folder_id"] == int(fid): req("DELETE", f"/api/secrets/{s['id']}", None, csrf)
req("DELETE", f"/api/folders/{fid}", None, csrf); print("scratch folder removed")
PY
}
trap cleanup EXIT
export VAULT_URL="$URL" VAULT_TOKEN="$TOKEN" APS_VAULT_SECRETS="db-password:DB_PASSWORD db-password.login:DB_USER" APS_VAULT_CI_SCRIPT="$PWD/clients/ci/aps-vault-ci.py"
# GitLab way 1: run the template's before_script lines in a fresh bash
python3 - <<'PY' > /tmp/aps-gl-before.sh
import yaml
g = yaml.safe_load(open("clients/gitlab-ci/aps-vault.gitlab-ci.yml"))
def flat(x):                      # GitLab flattens nested arrays in script sections (YAML anchors, !reference)
    for i in x: yield from (flat(i) if isinstance(i, list) else [i])
print("set -e")
for line in flat(g[".aps-vault-secrets"]["before_script"]): print(line)
print('printf "%s|%s\\n" "$DB_PASSWORD" "$DB_USER"')
PY
out=$(bash /tmp/aps-gl-before.sh); [ "$out" = "ci-check-value-1|ci-user" ] && echo "gitlab .aps-vault-secrets: variables exported in the job shell — ok" || { echo "gitlab before_script FAILED: $out"; exit 1; }
# GitLab way 2: the dotenv job's script line
python3 "$APS_VAULT_CI_SCRIPT" --dotenv /tmp/aps-vault.env $APS_VAULT_SECRETS >/dev/null
[ "$(cat /tmp/aps-vault.env)" = $'DB_PASSWORD=ci-check-value-1\nDB_USER=ci-user' ] && echo "gitlab aps-vault-secrets: dotenv artifact ok" || { echo "dotenv FAILED"; cat /tmp/aps-vault.env; exit 1; }
# GitHub action fetch step, simulated runner files
export GITHUB_ENV=/tmp/aps-gh-env GITHUB_OUTPUT=/tmp/aps-gh-out APS_ITEMS="$APS_VAULT_SECRETS"; : > "$GITHUB_ENV"; : > "$GITHUB_OUTPUT"
python3 - <<'PY' > /tmp/aps-gh-step.sh
import yaml
a = yaml.safe_load(open("clients/github-action/action.yml"))
run = [s for s in a["runs"]["steps"] if s.get("id") == "fetch"][0]["run"].replace("${{ github.action_path }}", "clients/github-action")
print("set -e"); print(run)
PY
log=$(bash /tmp/aps-gh-step.sh)
grep -q "::add-mask::ci-check-value-1" <<<"$log" && grep -q "^DB_PASSWORD<<APSVAULT_EOF_" "$GITHUB_ENV" && grep -q "^ci-check-value-1$" "$GITHUB_ENV" && grep -q "^variables=DB_PASSWORD, DB_USER$" "$GITHUB_OUTPUT" \
  && echo "github action fetch step: GITHUB_ENV heredocs + masks + output ok" || { echo "github step FAILED"; echo "$log"; cat "$GITHUB_ENV" "$GITHUB_OUTPUT"; exit 1; }
grep -q "$TOKEN" <<<"$log" && { echo "token leaked into the log"; exit 1; } || echo "token never printed — ok"
