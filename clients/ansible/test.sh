#!/bin/bash
# Real check of the lookup plugin: ansible-core in a container runs a playbook against a live vault.
#   VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_… ./test.sh <secret-name>
set -euo pipefail
cd "$(dirname "$0")"
NAME="${1:?secret name}"; : "${VAULT_URL:?}"; : "${VAULT_TOKEN:?}"
IMG="${ANSIBLE_IMG:-python:3.11-slim}"
direct=$(curl -fsS -H "Authorization: Bearer $VAULT_TOKEN" "$VAULT_URL/api/v1/m/secret/$NAME")
want_value=$(printf '%s' "$direct" | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"], end="")')
want_login=$(printf '%s' "$direct" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("login",""), end="")')
want_version=$(printf '%s' "$direct" | python3 -c 'import sys,json; print(json.load(sys.stdin)["version"], end="")')
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/play.yml" <<EOF
- hosts: localhost
  gather_facts: false
  tasks:
    - name: value, login and the full record
      ansible.builtin.set_fact:
        v: "{{ lookup('aps_vault', '$NAME') }}"
        l: "{{ lookup('aps_vault', '$NAME', field='login') }}"
        f: "{{ lookup('aps_vault', '$NAME', field='full') }}"
      no_log: true
    - name: the play may use the value — write it like an env file would be written
      ansible.builtin.copy:
        dest: /out/env
        mode: "0644"      # the test host reads it back; a real play would use 0600
        content: "DB_USER={{ l }}\nDB_PASSWORD={{ v }}\nVERSION={{ f.version }}\n"
      no_log: true
    - name: wrong token must fail with the server's 401
      ansible.builtin.set_fact:
        bad: "{{ lookup('aps_vault', '$NAME', token='vlt_definitely_not_a_token_000000000000') }}"
      ignore_errors: true
      register: wrong
    - name: unknown secret must fail with 404
      ansible.builtin.set_fact:
        nope: "{{ lookup('aps_vault', 'no-such-secret-$RANDOM') }}"
      ignore_errors: true
      register: missing
    - ansible.builtin.copy:
        dest: /out/negatives
        mode: "0644"
        content: "wrong_failed={{ wrong.failed }} wrong_msg={{ wrong.msg | default('') }}\nmissing_failed={{ missing.failed }} missing_msg={{ missing.msg | default('') }}\n"
EOF
docker run --rm -v "$PWD/plugins/lookup:/plugins/lookup:ro" -v "$TMP:/out" -e VAULT_URL="$VAULT_URL" -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e ANSIBLE_LOOKUP_PLUGINS=/plugins/lookup -e ANSIBLE_LOCALHOST_WARNING=False -e ANSIBLE_INVENTORY_UNPARSED_WARNING=False "$IMG" \
  sh -c "pip install -q --root-user-action=ignore ansible-core==2.17.* >/dev/null 2>&1 && ansible-playbook -i localhost, -c local /out/play.yml" > "$TMP/run.log" 2>&1 || { echo "ansible-playbook failed:"; tail -30 "$TMP/run.log"; exit 1; }
pass=0; fail=0
ok() { if [ "$2" = 1 ]; then pass=$((pass+1)); echo "  ✓ $1"; else fail=$((fail+1)); echo "  ✗ $1 ${3:-}"; fi; }
ok "lookup value equals the machine-API value" "$([ "$(grep '^DB_PASSWORD=' "$TMP/env" | cut -d= -f2-)" = "$want_value" ] && echo 1 || echo 0)"
ok "field=login equals the secret's login" "$([ "$(grep '^DB_USER=' "$TMP/env" | cut -d= -f2-)" = "$want_login" ] && echo 1 || echo 0)"
ok "field=full carries the version" "$([ "$(grep '^VERSION=' "$TMP/env" | cut -d= -f2-)" = "$want_version" ] && echo 1 || echo 0)"
ok "wrong token: task failed with the 401 message" "$(grep -q 'wrong_failed=True wrong_msg=.*401' "$TMP/negatives" && echo 1 || echo 0)" "$(grep wrong "$TMP/negatives")"
ok "unknown secret: task failed with 'no secret'" "$(grep -q "missing_failed=True missing_msg=.*no secret" "$TMP/negatives" && echo 1 || echo 0)" "$(grep missing "$TMP/negatives")"
ok "the value never appears in the ansible output (no_log)" "$(grep -qF "$want_value" "$TMP/run.log" && echo 0 || echo 1)"
echo "RESULT: $pass ok, $fail fail"
[ "$fail" = 0 ]
