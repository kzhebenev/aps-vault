# APS Vault for Ansible — lookup plugin

One file, standard library only: `plugins/lookup/aps_vault.py`. Drop it into your project's
`lookup_plugins/` (or point `ANSIBLE_LOOKUP_PLUGINS` at this directory) and read secrets
with a folder-scoped service token:

```yaml
- hosts: app
  vars:
    db_password: "{{ lookup('aps_vault', 'db-password') }}"          # VAULT_URL + VAULT_TOKEN from the environment
    db_user:     "{{ lookup('aps_vault', 'db-password', field='login') }}"
  tasks:
    - name: Write the application's environment file
      ansible.builtin.copy:
        dest: /etc/app/env
        mode: "0600"
        content: |
          DB_USER={{ db_user }}
          DB_PASSWORD={{ db_password }}
      no_log: true
```

| option | env | meaning |
|---|---|---|
| `url` | `VAULT_URL` | vault base URL |
| `token` / `token_file` | `VAULT_TOKEN` / `VAULT_TOKEN_FILE` | service token (`vlt_…`); a 0600 file is the better home |
| `field` | — | `value` (default), `login`, `notes`, `totp` (current code), `full` (the whole record) |
| `version` | — | an older value, `?version=N` |
| `client_key` | `VAULT_CLIENT_KEY` | node private key for **sealed** tokens; needs `pip install aps-vault` on the controller |
| `validate_certs`, `timeout` | — | TLS verification (default on), HTTP timeout |

Errors are the server's: `401` (token invalid, revoked or expired), `403` (outside its
where-and-when policy, or the field is not granted) and `404` (no such secret in the token's
folder) fail the task with a readable message — a play never silently continues with an empty
password.

**Where the token lives.** The controller reads it; the managed hosts never see it. Keep it in
the controller's environment, in `VAULT_TOKEN_FILE` with mode 0600, or in `ansible.cfg`:

```ini
[aps_vault]
url = https://vault.example.com
token_file = /etc/ansible/vault.token
```

Issue the token read-only on exactly the folder the playbook needs, and bind it to the
controller's networks with the token's `allowed_cidrs` (docs/ACCESS-POLICIES.md). For an AWX /
Semaphore controller, a sealed token plus `VAULT_CLIENT_KEY` means the value is encrypted
until it reaches the controller process.

## Verified

`test.sh` runs a real `ansible-playbook` (ansible-core in a `python:3.11-slim` container)
against a live vault: the looked-up value and login equal what the machine API returns
directly; `field=full` carries `version`; a wrong token fails the task with the 401 message
and a nonexistent secret with the 404 message.

```bash
VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_… ./test.sh db-password
```
