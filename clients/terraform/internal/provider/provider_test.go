package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// fakeVault speaks the machine API subset the provider uses (sdk_api.py): health, list, read (+?version),
// write (upsert with history), delete. One folder, one token; `canWrite` is the token's flag.
type fakeVault struct {
	mu       sync.Mutex
	canWrite bool
	secrets  map[string]*fakeSecret
	calls    map[string]int
}

type fakeSecret struct {
	value, login, tags, url string
	version                 int
	history                 map[int]string
}

func newFake(canWrite bool) *fakeVault {
	return &fakeVault{canWrite: canWrite, secrets: map[string]*fakeSecret{
		"db-password": {value: "pg-pass-2026", login: "core", version: 1, history: map[int]string{}},
	}, calls: map[string]int{}}
}

func (f *fakeVault) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls[r.Method+" "+r.URL.Path]++
		write := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
		if r.Header.Get("Authorization") != "Bearer vlt_test_token" {
			write(401, map[string]any{"detail": "invalid token"})
			return
		}
		switch {
		case r.URL.Path == "/api/v1/m/health":
			write(200, map[string]any{"status": "ok", "token_name": "tf", "scope_folder": "tf-acc", "sealed": false})
		case r.URL.Path == "/api/v1/m/secrets":
			out := []map[string]any{}
			for n, s := range f.secrets {
				out = append(out, map[string]any{"name": n, "tags": s.tags, "url": s.url, "has_totp": false, "has_notes": false, "updated_at": "2026-10-04T14:00:00"})
			}
			write(200, out)
		case strings.HasPrefix(r.URL.Path, "/api/v1/m/secret/"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/m/secret/")
			s, ok := f.secrets[name]
			switch r.Method {
			case http.MethodGet:
				if !ok {
					write(404, map[string]any{"detail": fmt.Sprintf("secret '%s' not found in scope 'tf-acc'", name)})
					return
				}
				value, version := s.value, s.version
				if q := r.URL.Query().Get("version"); q != "" {
					n, _ := strconv.Atoi(q)
					if n != s.version {
						old, ok := s.history[n]
						if !ok {
							write(404, map[string]any{"detail": "version not found"})
							return
						}
						value, version = old, n
					}
				}
				write(200, map[string]any{"name": name, "value": value, "login": s.login, "version": version, "current_version": s.version, "updated_at": "2026-10-04T14:00:00"})
			case http.MethodPost:
				if !f.canWrite {
					write(403, map[string]any{"detail": "this service token has no write permission (can_write)"})
					return
				}
				var b map[string]string
				_ = json.NewDecoder(r.Body).Decode(&b)
				created := !ok
				if created {
					s = &fakeSecret{history: map[int]string{}}
					f.secrets[name] = s
				} else {
					s.history[s.version] = s.value
				}
				s.value = b["value"]
				if b["login"] != "" {
					s.login = b["login"]
				}
				if b["tags"] != "" {
					s.tags = b["tags"]
				}
				if b["url"] != "" {
					s.url = b["url"]
				}
				s.version++
				write(200, map[string]any{"id": 1, "name": name, "created": created, "version": s.version})
			case http.MethodDelete:
				if !f.canWrite {
					write(403, map[string]any{"detail": "this service token has no write permission (can_write)"})
					return
				}
				if !ok {
					write(404, map[string]any{"detail": "not found"})
					return
				}
				delete(f.secrets, name)
				write(200, map[string]any{"ok": true, "name": name})
			default:
				write(405, nil)
			}
		default:
			write(404, map[string]any{"detail": "no route"})
		}
	})
}

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"apsvault": providerserver.NewProtocol6WithError(New("test")()),
}

func providerBlock(url, token string) string {
	return fmt.Sprintf("provider \"apsvault\" {\n  url   = %q\n  token = %q\n}\n", url, token)
}

func TestDataSourceSecretReadsCurrentAndOlderVersion(t *testing.T) {
	f := newFake(true)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	// a second version exists in the fake's history
	f.secrets["db-password"].history[1] = "pg-pass-2025"
	f.secrets["db-password"].value, f.secrets["db-password"].version = "pg-pass-2026", 2
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{{
			Config: providerBlock(srv.URL, "vlt_test_token") + `
data "apsvault_secret" "cur" { name = "db-password" }
data "apsvault_secret" "old" {
  name    = "db-password"
  version = 1
}
data "apsvault_secrets" "all" {}
output "cur" {
  value     = data.apsvault_secret.cur.value
  sensitive = true
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.apsvault_secret.cur", "value", "pg-pass-2026"),
				resource.TestCheckResourceAttr("data.apsvault_secret.cur", "login", "core"),
				resource.TestCheckResourceAttr("data.apsvault_secret.cur", "version", "2"),
				resource.TestCheckResourceAttr("data.apsvault_secret.cur", "id", "db-password@v2"),
				resource.TestCheckResourceAttr("data.apsvault_secret.old", "value", "pg-pass-2025"),
				resource.TestCheckResourceAttr("data.apsvault_secret.old", "version", "1"),
				resource.TestCheckResourceAttr("data.apsvault_secrets.all", "names.#", "1"),
				resource.TestCheckResourceAttr("data.apsvault_secrets.all", "names.0", "db-password"),
				resource.TestCheckResourceAttr("data.apsvault_secrets.all", "secrets.0.name", "db-password"),
			),
		}},
	})
}

func TestResourceSecretLifecycle(t *testing.T) {
	f := newFake(true)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	cfg := func(value, login string) string {
		return providerBlock(srv.URL, "vlt_test_token") + fmt.Sprintf(`
resource "apsvault_secret" "app" {
  name  = "app-token"
  value = %q
  login = %q
  tags  = "tf,prod"
  url   = "https://app.example.com"
}
`, value, login)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		CheckDestroy: func(*terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.secrets["app-token"]; ok {
				return fmt.Errorf("app-token still exists in the vault after destroy")
			}
			if f.calls["DELETE /api/v1/m/secret/app-token"] != 1 {
				return fmt.Errorf("expected exactly one DELETE, got %d", f.calls["DELETE /api/v1/m/secret/app-token"])
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: cfg("tok-1", "svc"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("apsvault_secret.app", "id", "app-token"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "value", "tok-1"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "login", "svc"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "tags", "tf,prod"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "url", "https://app.example.com"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "version", "1"),
					func(*terraform.State) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						if s := f.secrets["app-token"]; s == nil || s.value != "tok-1" || s.login != "svc" || s.tags != "tf,prod" {
							return fmt.Errorf("vault side after create: %+v", s)
						}
						return nil
					},
				),
			},
			{ // a value change is a new version; the old value is still in history
				Config: cfg("tok-2", "svc"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("apsvault_secret.app", "value", "tok-2"),
					resource.TestCheckResourceAttr("apsvault_secret.app", "version", "2"),
					func(*terraform.State) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						if f.secrets["app-token"].history[1] != "tok-1" {
							return fmt.Errorf("version 1 must be kept in history")
						}
						return nil
					},
				),
			},
			{ // import by name reads everything back from the vault
				ResourceName: "apsvault_secret.app", ImportState: true, ImportStateVerify: true,
				ImportStateId: "app-token",
			},
			{ // drift: the value changed behind Terraform's back → plan shows an update back to the config
				PreConfig: func() { f.mu.Lock(); f.secrets["app-token"].value = "changed-by-hand"; f.mu.Unlock() },
				Config:    cfg("tok-2", "svc"),
				Check:     resource.TestCheckResourceAttr("apsvault_secret.app", "value", "tok-2"),
			},
			{ // deleted outside Terraform → recreated, not an error
				PreConfig: func() { f.mu.Lock(); delete(f.secrets, "app-token"); f.mu.Unlock() },
				Config:    cfg("tok-2", "svc"),
				Check: func(*terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if s := f.secrets["app-token"]; s == nil || s.value != "tok-2" {
						return fmt.Errorf("secret must be recreated after an external delete")
					}
					return nil
				},
			},
		},
	})
}

func TestNegativesAreClearErrors(t *testing.T) {
	ro := newFake(false)
	srv := httptest.NewServer(ro.handler())
	defer srv.Close()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{ // wrong token: refused at provider configuration, before any data source runs
				Config:      providerBlock(srv.URL, "vlt_wrong") + `data "apsvault_secret" "x" { name = "db-password" }`,
				ExpectError: regexp.MustCompile(`token refused|HTTP 401`),
			},
			{ // a name that is not in the folder
				Config:      providerBlock(srv.URL, "vlt_test_token") + `data "apsvault_secret" "x" { name = "ghost" }`,
				ExpectError: regexp.MustCompile(`secret not found`),
			},
			{ // a read-only token cannot manage resources — and nothing is written
				Config:      providerBlock(srv.URL, "vlt_test_token") + "resource \"apsvault_secret\" \"x\" {\n  name  = \"new\"\n  value = \"v\"\n}\n",
				ExpectError: regexp.MustCompile(`token cannot write`),
			},
			{ // missing address / token: the provider says which setting is missing
				Config:      "provider \"apsvault\" {\n  url   = \"\"\n  token = \"\"\n}\n" + `data "apsvault_secret" "x" { name = "db-password" }`,
				ExpectError: regexp.MustCompile(`vault address missing|service token missing`),
			},
		},
	})
	ro.mu.Lock()
	defer ro.mu.Unlock()
	if _, ok := ro.secrets["new"]; ok {
		t.Fatal("a 403 on write must leave nothing behind")
	}
}
