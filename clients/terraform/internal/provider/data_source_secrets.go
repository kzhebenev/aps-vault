package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apsvault "github.com/aps-vault/aps-vault/clients/go"
)

type secretsDataSource struct{ client *apsvault.Client }

func newSecretsDataSource() datasource.DataSource { return &secretsDataSource{} }

func (d *secretsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

var secretMetaType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name": types.StringType, "tags": types.StringType, "url": types.StringType,
	"has_totp": types.BoolType, "has_notes": types.BoolType, "updated_at": types.StringType,
}}

func (d *secretsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Names and metadata of every secret in the token's folder — no values.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true},
			"names":   schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Secret names, sorted as the vault lists them."},
			"secrets": schema.ListAttribute{Computed: true, ElementType: secretMetaType, Description: "name, tags, url, has_totp, has_notes, updated_at."},
		},
	}
}

func (d *secretsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *secretsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	rows, err := d.client.List(ctx)
	if err != nil {
		resp.Diagnostics.AddError("listing secrets", err.Error())
		return
	}
	names := make([]attr.Value, 0, len(rows))
	objs := make([]attr.Value, 0, len(rows))
	str := func(v any) string { s, _ := v.(string); return s }
	boolean := func(v any) bool { b, _ := v.(bool); return b }
	for _, r := range rows {
		names = append(names, types.StringValue(str(r["name"])))
		o, diags := types.ObjectValue(secretMetaType.AttrTypes, map[string]attr.Value{
			"name": types.StringValue(str(r["name"])), "tags": types.StringValue(str(r["tags"])), "url": types.StringValue(str(r["url"])),
			"has_totp": types.BoolValue(boolean(r["has_totp"])), "has_notes": types.BoolValue(boolean(r["has_notes"])), "updated_at": types.StringValue(str(r["updated_at"])),
		})
		resp.Diagnostics.Append(diags...)
		objs = append(objs, o)
	}
	namesList, diags := types.ListValue(types.StringType, names)
	resp.Diagnostics.Append(diags...)
	objList, diags := types.ListValue(secretMetaType, objs)
	resp.Diagnostics.Append(diags...)
	state := struct {
		ID      types.String `tfsdk:"id"`
		Names   types.List   `tfsdk:"names"`
		Secrets types.List   `tfsdk:"secrets"`
	}{ID: types.StringValue(fmt.Sprintf("folder:%d", len(rows))), Names: namesList, Secrets: objList}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
