# Terraform / OpenTofu provider (0.33)

`clients/terraform` is a provider built on the Go client: Terraform reads secrets of one folder through a
service token and, with a **can_write** token, manages secrets as resources. Sealed tokens work — the
provider opens the envelope with `client_private_key` (any kind the token is bound to: X25519, GOST,
P-256, the X25519 or GOST ML-KEM hybrids).

```hcl
terraform {
  required_providers {
    apsvault = { source = "registry.terraform.io/aps-vault/apsvault", version = ">= 0.33.0" }
  }
}

provider "apsvault" {}          # VAULT_URL, VAULT_TOKEN (or VAULT_TOKEN_FILE), VAULT_CLIENT_KEY

data "apsvault_secret" "db" { name = "db-password" }

resource "apsvault_secret" "api_key" {
  name  = "api-key"
  value = random_password.api.result
  login = "svc-api"
  tags  = "terraform,prod"
}
```

## Blocks

**provider "apsvault"** — `url`, `token` (sensitive), `client_private_key` (sensitive), `timeout_seconds`
(default 10). Each falls back to the environment (`VAULT_URL`, `VAULT_TOKEN` / `VAULT_TOKEN_FILE`,
`VAULT_CLIENT_KEY`). Configuration calls `GET /api/v1/m/health`: a wrong token or an unreachable vault
fails here, with the reason, before any plan. A sealed token without a key is refused with a pointer to
`client_private_key`.

**data "apsvault_secret"** — `name` (required), `version` (optional: read an older value, `GET ?version=N`).
Computed: `value` (sensitive), `login`, `notes` (sensitive; needs `can_read_notes`), `totp` (sensitive;
the current one-time code, needs `can_read_totp`), `version`, `updated_at`, `id` = `name@vN`. A missing
secret is an error ("secret not found"), never an empty string.

**data "apsvault_secrets"** — `names` and `secrets[]` (`name`, `tags`, `url`, `has_totp`, `has_notes`,
`updated_at`) of the whole folder, no values.

**resource "apsvault_secret"** — `name` (replaces on change), `value` (required, sensitive), `login`,
`tags`, `url`; computed `version`, `updated_at`, `id` = name. Create and update are `POST
/api/v1/m/secret/{name}` (an update is a new version; the old value stays readable as history), delete is
`DELETE /api/v1/m/secret/{name}` (vault 0.30.1+). `terraform import apsvault_secret.x <name>` reads the
secret from the vault. A secret changed or deleted behind Terraform's back shows up in the next plan —
the provider never caches.

## What to know

- **State holds the values.** Like every secret Terraform reads, `value`, `notes` and `totp` are in the
  state file (marked sensitive, so hidden from output). Protect the state as you protect the vault: an
  encrypted backend, no state in git. Terraform 1.10+ ephemeral resources would avoid this; they are not
  in this provider yet (OpenTofu 1.8 does not have them).
- **One folder per token.** The provider sees the folder the token is scoped to. Several folders →
  several provider aliases with several tokens.
- **The machine API cannot clear** `login` / `tags` / `url` — it sets them only when non-empty.
  Removing one of these attributes from the configuration therefore does not empty it in the vault; the
  attributes are *Optional + Computed* so the vault's value is kept in state without a diff. Clear them in
  the UI.
- **Write tokens are powerful.** `can_write` lets the token create, overwrite and delete any secret of
  its folder. Give Terraform its own folder and its own token; keep read-only tokens for applications.
- **Values stay in the vault's history.** Terraform's `destroy` deletes the secret with its history (the
  machine API does what the human one does); an *update* keeps the previous value as a version.

## Install

Until the provider is on the Terraform / OpenTofu registries (the maintainer's account — `docs/PUBLISHING.md`
§6), use the release zip (`terraform-provider-apsvault_<version>_<os>_<arch>.zip`, Sigstore bundle next to it)
or `go build` in `clients/terraform`, and a filesystem mirror or `dev_overrides` — both spelled out in
`clients/terraform/README.md`.

## Verified

`clients/terraform/internal/provider/provider_test.go` drives the provider through the real CLI
(OpenTofu, plugin protocol 6) against a fake machine API: current and older versions through the data
sources, the folder listing, the resource lifecycle (create → version 1, update → version 2 with the
old value in history, import by name, drift repaired, external delete recreated, destroy sends exactly
one DELETE), and the negatives — a wrong token is refused at configuration, a missing secret is an
error, a read-only token cannot create and leaves nothing behind, missing settings name themselves.
`acc_live_test.go` (run by `ops/checks/terraform-acc.sh`) does the same against a real vault: the
script unlocks, creates a scratch folder and a can_write token, and deletes the folder afterwards.
