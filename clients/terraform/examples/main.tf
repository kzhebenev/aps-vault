# APS Vault provider — read a secret, manage another one.
#   export VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_…   (a can_write token for the resource)
#   tofu init && tofu apply
terraform {
  required_providers {
    apsvault = {
      source  = "registry.terraform.io/aps-vault/apsvault"   # same string for OpenTofu with the mirror below
      version = ">= 0.33.0"
    }
  }
}

provider "apsvault" {}   # url / token / client_private_key from VAULT_URL / VAULT_TOKEN / VAULT_CLIENT_KEY

# read: the current value of a secret in the token's folder
data "apsvault_secret" "db" {
  name = "db-password"
}

# read an older version (key rotation window)
data "apsvault_secret" "db_previous" {
  name    = "db-password"
  version = data.apsvault_secret.db.version - 1
}

# manage: Terraform owns this secret; every change is a new version in the vault
resource "random_password" "api" {
  length  = 40
  special = false
}

resource "apsvault_secret" "api_key" {
  name  = "api-key"
  value = random_password.api.result
  login = "svc-api"
  tags  = "terraform,prod"
}

output "db_user" { value = data.apsvault_secret.db.login }
output "api_key_version" { value = apsvault_secret.api_key.version }
