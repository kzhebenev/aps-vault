# Examples

All examples read `VAULT_URL` and `VAULT_TOKEN` (or `VAULT_TOKEN_FILE`) from the environment
and use a **read-only service token** scoped to one folder. Create the token in the UI
(Tokens → new, pick the folder) or see `docs/API.md`.

| Example | What it shows |
|---|---|
| `python/app.py` | fetch a DB password at startup, fail fast if missing, use TOTP for a second factor |
| `node/app.mjs` | same in Node 18+ |
| `go/main.go` | same in Go, with context timeout |
| `java/App.java` | same in Java 11+ (single file, `java App.java`) |
| `shell/with-secrets.sh` | wrapper that exports secrets as environment variables and `exec`s your program — no code changes needed |
| `docker-compose.sidecar.yml` | vault running next to an application on one host, app reads secrets through the private network |
| `../deploy/k8s/external-secrets/` | Kubernetes: External Secrets Operator manifests (vault and webhook providers) and a real-cluster check — `docs/KUBERNETES.md` |
| `../clients/ansible/` | Ansible lookup plugin `aps_vault`: `{{ lookup('aps_vault', 'db-password') }}` |
| `../clients/terraform/examples/` | Terraform / OpenTofu: `data "apsvault_secret"` and `resource "apsvault_secret"` — `docs/TERRAFORM.md` |

Sealed delivery (0.17): if the token is bound to the application's X25519 key, also export
`VAULT_CLIENT_KEY=<base64 private key>` — every client picks it up and decrypts in-process
(`python -m aps_vault keygen` makes the pair; the Python client needs `pip install cryptography`).

Run against your vault:

```bash
export VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_…
python3 examples/python/app.py
node examples/node/app.mjs
cd examples/go && go run .
java -cp ../../clients/java/src/main/java examples/java/App.java   # or compile both
examples/shell/with-secrets.sh db-password:DB_PASSWORD smtp:SMTP_PASSWORD -- ./my-service
```
