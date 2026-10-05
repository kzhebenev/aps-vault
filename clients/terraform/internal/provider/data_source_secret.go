package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apsvault "github.com/aps-vault/aps-vault/clients/go"
)

type secretDataSource struct{ client *apsvault.Client }

type secretDataModel struct {
	Name      types.String `tfsdk:"name"`
	Version   types.Int64  `tfsdk:"version"`
	Value     types.String `tfsdk:"value"`
	Login     types.String `tfsdk:"login"`
	Notes     types.String `tfsdk:"notes"`
	TOTP      types.String `tfsdk:"totp"`
	UpdatedAt types.String `tfsdk:"updated_at"`
	ID        types.String `tfsdk:"id"`
}

func newSecretDataSource() datasource.DataSource { return &secretDataSource{} }

func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One secret of the token's folder — the current value, or an older version with `version`. " +
			"`value` and `totp` are sensitive; they end up in the state like every secret Terraform reads, so protect the state.",
		Attributes: map[string]schema.Attribute{
			"name":       schema.StringAttribute{Required: true, Description: "Secret name inside the folder the token is scoped to."},
			"version":    schema.Int64Attribute{Optional: true, Computed: true, Description: "Read this version instead of the current one (GET ?version=N). Computed: the version actually returned."},
			"value":      schema.StringAttribute{Computed: true, Sensitive: true},
			"login":      schema.StringAttribute{Computed: true, Description: "Login / user name, if set."},
			"notes":      schema.StringAttribute{Computed: true, Sensitive: true, Description: "Notes, when the token has can_read_notes."},
			"totp":       schema.StringAttribute{Computed: true, Sensitive: true, Description: "Current one-time code, when the token has can_read_totp and the secret carries a TOTP seed."},
			"updated_at": schema.StringAttribute{Computed: true},
			"id":         schema.StringAttribute{Computed: true, Description: "`<name>@v<version>`."},
		},
	}
}

func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, err := clientFrom(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("provider", err.Error())
		return
	}
	d.client = c
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m secretDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var s apsvault.Secret
	var err error
	if !m.Version.IsNull() && !m.Version.IsUnknown() && m.Version.ValueInt64() > 0 {
		s, err = d.client.GetFullVersion(ctx, m.Name.ValueString(), int(m.Version.ValueInt64()))
	} else {
		s, err = d.client.GetFull(ctx, m.Name.ValueString())
	}
	if err != nil {
		var ve *apsvault.Error
		if errors.As(err, &ve) && ve.Status == 404 {
			resp.Diagnostics.AddError("secret not found", fmt.Sprintf("%q is not in the folder this token is scoped to (or the requested version does not exist).", m.Name.ValueString()))
			return
		}
		resp.Diagnostics.AddError("reading secret", err.Error())
		return
	}
	fill(&m, s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func fill(m *secretDataModel, s apsvault.Secret) {
	m.Value = types.StringValue(s.Value)
	m.Login = types.StringValue(s.Login)
	m.Notes = types.StringValue(s.Notes)
	if s.TOTP != nil {
		m.TOTP = types.StringValue(*s.TOTP)
	} else {
		m.TOTP = types.StringNull()
	}
	v := s.Version
	if v == 0 {
		v = 1
	}
	m.Version = types.Int64Value(int64(v))
	m.UpdatedAt = types.StringValue(s.UpdatedAt)
	m.ID = types.StringValue(fmt.Sprintf("%s@v%d", s.Name, v))
}
