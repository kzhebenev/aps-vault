# terraform-provider-apsvault

Terraform / OpenTofu provider for APS Vault (0.33). Built on the Go client (`clients/go`), so it opens
sealed envelopes (X25519, GOST, P-256, the two ML-KEM hybrids) with the token's private key.

| Block | What |
|---|---|
| `provider "apsvault"` | `url`, `token`, `client_private_key`, `timeout_seconds` — or `VAULT_URL`, `VAULT_TOKEN` / `VAULT_TOKEN_FILE`, `VAULT_CLIENT_KEY` |
| `data "apsvault_secret"` | one secret: `value`, `login`, `notes`, `totp`, `version`, `updated_at`; `version = N` reads an older value |
| `data "apsvault_secrets"` | `names` and `secrets[]` (name, tags, url, has_totp, has_notes, updated_at) — no values |
| `resource "apsvault_secret"` | create / update / delete a secret (token needs **can_write**); import by name |

```hcl
provider "apsvault" {}                       # VAULT_URL / VAULT_TOKEN in the environment

data "apsvault_secret" "db" { name = "db-password" }

resource "apsvault_secret" "api_key" {
  name  = "api-key"
  value = random_password.api.result
  login = "svc-api"
}
```

Full example: `examples/main.tf`. Reference and caveats (state holds the values, write-token scope,
what the machine API cannot clear): `docs/TERRAFORM.md`.

## Install

Until the provider is on a registry (needs the maintainer's registry account — `docs/PUBLISHING.md`),
take the binary from the GitHub Release (`terraform-provider-apsvault_<version>_<os>_<arch>.zip`, Sigstore
bundle next to it) or build it:

```bash
cd clients/terraform && go build -o terraform-provider-apsvault .
```

and point the CLI at it — a **filesystem mirror** (works for `init` + lockfile):

```bash
d=~/.terraform.d/plugins/registry.terraform.io/aps-vault/apsvault/0.33.0/linux_amd64
mkdir -p "$d" && cp terraform-provider-apsvault "$d/terraform-provider-apsvault_v0.33.0"
```
```hcl
# ~/.terraformrc  (OpenTofu: ~/.tofurc)
provider_installation {
  filesystem_mirror { path = "/home/me/.terraform.d/plugins"  include = ["registry.terraform.io/aps-vault/*"] }
  direct { exclude = ["registry.terraform.io/aps-vault/*"] }
}
```

or `dev_overrides` while developing (no `init` needed):

```hcl
provider_installation {
  dev_overrides { "registry.terraform.io/aps-vault/apsvault" = "/path/to/clients/terraform" }
  direct {}
}
```

## Tests

```bash
cd clients/terraform
TF_ACC=1 TF_ACC_TERRAFORM_PATH=$(command -v tofu) TF_ACC_PROVIDER_HOST=registry.opentofu.org go test ./...
```
runs the provider through the real CLI against a fake machine API (data sources, resource lifecycle with
import, drift and external delete, clear errors for a wrong token / missing secret / read-only token).
`ops/checks/terraform-acc.sh` runs `TestLive…` against a real vault (scratch folder + can_write token,
removed afterwards). Go 1.25+ (the testing framework), Terraform 1.0+ / OpenTofu 1.6+ (plugin protocol 6).
