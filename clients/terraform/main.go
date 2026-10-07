// terraform-provider-apsvault — Terraform / OpenTofu provider for APS Vault (0.33).
//
// Reads secrets of one folder through a service token (data sources apsvault_secret, apsvault_secrets)
// and manages secrets with a can_write token (resource apsvault_secret). Sealed tokens are opened with
// the token's private key (client_private_key / VAULT_CLIENT_KEY) — the Go client does the envelope work.
//
// Build: go build -o terraform-provider-apsvault . ; install through a filesystem mirror or dev_overrides
// (clients/terraform/README.md) until the provider is on a registry.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/aps-vault/aps-vault/clients/terraform/internal/provider"
)

// Version is stamped into the provider's User-Agent and reported by `terraform providers`.
const Version = "0.41.5"

func main() {
	debug := flag.Bool("debug", false, "run with the debugger-friendly reattach protocol")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(Version), providerserver.ServeOpts{
		Address: "registry.terraform.io/aps-vault/apsvault",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
