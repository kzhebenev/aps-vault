// Package provider implements the apsvault Terraform provider on top of the Go client (clients/go).
package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apsvault "github.com/aps-vault/aps-vault/clients/go"
)

// New returns the provider constructor the plugin server and the tests use.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &apsProvider{version: version} }
}

type apsProvider struct{ version string }

type providerModel struct {
	URL              types.String `tfsdk:"url"`
	Token            types.String `tfsdk:"token"`
	ClientPrivateKey types.String `tfsdk:"client_private_key"`
	TimeoutSeconds   types.Int64  `tfsdk:"timeout_seconds"`
}

func (p *apsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "apsvault"
	resp.Version = p.version
}

func (p *apsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "APS Vault: secrets of one folder through a service token. Reads need a plain token; " +
			"`apsvault_secret` resources need a token with can_write. A sealed token (bound to a client key) is " +
			"opened with `client_private_key` — values never travel in plaintext.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "Vault address, e.g. https://vault.example.com. Default: environment variable VAULT_URL.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Service token (vlt_…). Default: VAULT_TOKEN. Keep it out of the configuration: use the environment or a variable marked sensitive.",
			},
			"client_private_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 private key of a sealed token (X25519, GOST, P-256, or one of the two ML-KEM hybrids — whatever the token is bound to). Default: VAULT_CLIENT_KEY.",
			},
			"timeout_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "HTTP timeout per request (default 10).",
			},
		},
	}
}

func (p *apsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	pick := func(v types.String, env string) string {
		if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
			return v.ValueString()
		}
		return os.Getenv(env)
	}
	url, token, key := pick(cfg.URL, "VAULT_URL"), pick(cfg.Token, "VAULT_TOKEN"), pick(cfg.ClientPrivateKey, "VAULT_CLIENT_KEY")
	if url == "" {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "vault address missing", "Set `url` or the environment variable VAULT_URL.")
	}
	if token == "" {
		if f := os.Getenv("VAULT_TOKEN_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				token = string(trimSpace(b))
			}
		}
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "service token missing", "Set `token`, or VAULT_TOKEN / VAULT_TOKEN_FILE in the environment.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	timeout := 10 * time.Second
	if !cfg.TimeoutSeconds.IsNull() && !cfg.TimeoutSeconds.IsUnknown() {
		timeout = time.Duration(cfg.TimeoutSeconds.ValueInt64()) * time.Second
	} else if s := os.Getenv("VAULT_TIMEOUT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}
	// no cache: Terraform compares live state on every plan, a stale value would hide drift
	client, err := apsvault.New(url, token, apsvault.Options{CacheTTL: -1, Timeout: timeout, MaxRetries: 2, ClientPrivateKey: key})
	if err != nil {
		resp.Diagnostics.AddError("vault client", err.Error())
		return
	}
	health, err := client.Health(ctx)
	if err != nil {
		resp.Diagnostics.AddError("vault unreachable or token refused", fmt.Sprintf("GET %s/api/v1/m/health: %s", url, err))
		return
	}
	if health["sealed"] == true && key == "" {
		resp.Diagnostics.AddAttributeError(path.Root("client_private_key"), "sealed token without a private key",
			"This token is bound to a client key: values arrive encrypted. Set `client_private_key` or VAULT_CLIENT_KEY.")
		return
	}
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *apsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newSecretDataSource, newSecretsDataSource}
}

func (p *apsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource}
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

// clientFrom is the shared ProviderData unpacking with a clear message when Configure did not run.
func clientFrom(data any) (*apsvault.Client, error) {
	c, ok := data.(*apsvault.Client)
	if !ok || c == nil {
		return nil, fmt.Errorf("provider not configured")
	}
	return c, nil
}
