package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Against a real APS Vault: APSVAULT_ACC_URL + APSVAULT_ACC_TOKEN (a can_write token of a scratch folder —
// ops/checks/terraform-acc.sh creates both and removes the folder afterwards). Skipped otherwise.
func TestLiveVaultResourceAndDataSource(t *testing.T) {
	url, token := os.Getenv("APSVAULT_ACC_URL"), os.Getenv("APSVAULT_ACC_TOKEN")
	if url == "" || token == "" {
		t.Skip("НЕ НАСТРОЕНО: APSVAULT_ACC_URL / APSVAULT_ACC_TOKEN not set — no live vault to run against")
	}
	name := fmt.Sprintf("tf-%d", time.Now().UnixNano()%1_000_000)
	cfg := func(value string) string {
		return providerBlock(url, token) + fmt.Sprintf(`
resource "apsvault_secret" "s" {
  name  = %q
  value = %q
  login = "svc"
  tags  = "terraform"
}
data "apsvault_secret" "read" {
  name       = apsvault_secret.s.name
  depends_on = [apsvault_secret.s]
}
data "apsvault_secrets" "all" {
  depends_on = [apsvault_secret.s]
}
`, name, value)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: cfg("live-value-1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("apsvault_secret.s", "value", "live-value-1"),
					resource.TestCheckResourceAttr("apsvault_secret.s", "version", "1"),
					resource.TestCheckResourceAttr("apsvault_secret.s", "login", "svc"),
					resource.TestCheckResourceAttr("apsvault_secret.s", "tags", "terraform"),
					resource.TestCheckResourceAttr("data.apsvault_secret.read", "value", "live-value-1"),
					resource.TestCheckResourceAttr("data.apsvault_secret.read", "login", "svc"),
					resource.TestCheckTypeSetElemAttr("data.apsvault_secrets.all", "names.*", name),
				),
			},
			{
				Config: cfg("live-value-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("apsvault_secret.s", "value", "live-value-2"),
					resource.TestCheckResourceAttr("apsvault_secret.s", "version", "2"),
					resource.TestCheckResourceAttr("data.apsvault_secret.read", "value", "live-value-2"),
				),
			},
			{ // the previous value is still version 1 in the vault
				Config: cfg("live-value-2") + fmt.Sprintf(`
data "apsvault_secret" "v1" {
  name       = %q
  version    = 1
  depends_on = [apsvault_secret.s]
}
`, name),
				Check: resource.TestCheckResourceAttr("data.apsvault_secret.v1", "value", "live-value-1"),
			},
			{ResourceName: "apsvault_secret.s", ImportState: true, ImportStateVerify: true, ImportStateId: name},
		},
	})
	// after destroy the secret is gone: a data source for it is an error, not an empty value
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{{
			Config:      providerBlock(url, token) + fmt.Sprintf("data \"apsvault_secret\" \"gone\" {\n  name = %q\n}\n", name),
			ExpectError: regexp.MustCompile(`secret not found`),
		}},
	})
}
