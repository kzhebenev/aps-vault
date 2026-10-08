package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apsvault "github.com/aps-vault/aps-vault/clients/go"
)

type secretResource struct{ client *apsvault.Client }

type secretResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Value     types.String `tfsdk:"value"`
	Login     types.String `tfsdk:"login"`
	Tags      types.String `tfsdk:"tags"`
	URL       types.String `tfsdk:"url"`
	Version   types.Int64  `tfsdk:"version"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func newSecretResource() resource.Resource { return &secretResource{} }

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A secret in the token's folder, managed by Terraform (token needs can_write). Every value change " +
			"becomes a new numbered version in the vault; the previous value stays readable as history. The machine API " +
			"only sets login / tags / url when they are non-empty — clear them in the vault UI, not by removing the attribute.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":       schema.StringAttribute{Required: true, Description: "Secret name (1..128 characters). Changing it replaces the secret.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"value":      schema.StringAttribute{Required: true, Sensitive: true, Description: "The secret value. Prefer a sensitive variable or a generated value (random_password) over a literal."},
			"login":      schema.StringAttribute{Optional: true, Computed: true, Description: "Login / user name.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tags":       schema.StringAttribute{Optional: true, Computed: true, Description: "Comma-separated tags.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"url":        schema.StringAttribute{Optional: true, Computed: true, Description: "Related URL (http:// or https://).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"version":    schema.Int64Attribute{Computed: true, Description: "Current version number in the vault."},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, err := clientFrom(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("provider", err.Error())
		return
	}
	r.client = c
}

func str(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

func (r *secretResource) write(ctx context.Context, m *secretResourceModel) error {
	return r.client.Put(ctx, m.Name.ValueString(), m.Value.ValueString(), str(m.Login), str(m.Tags), str(m.URL))
}

// refresh reads the secret back and fills the computed attributes; the value in state is what Terraform
// wrote (the vault returns the same bytes — a mismatch would mean someone changed it behind Terraform).
func (r *secretResource) refresh(ctx context.Context, m *secretResourceModel) (bool, error) {
	s, err := r.client.GetFull(ctx, m.Name.ValueString())
	if err != nil {
		var ve *apsvault.Error
		if errors.As(err, &ve) && ve.Status == 404 {
			return false, nil
		}
		return false, err
	}
	m.ID = types.StringValue(s.Name)
	m.Value = types.StringValue(s.Value)
	m.Login = types.StringValue(s.Login)
	v := s.Version
	if v == 0 {
		v = 1
	}
	m.Version = types.Int64Value(int64(v))
	m.UpdatedAt = types.StringValue(s.UpdatedAt)
	// tags and url are not in the read payload; the list endpoint has them
	rows, err := r.client.List(ctx)
	if err == nil {
		for _, row := range rows {
			if n, _ := row["name"].(string); n == s.Name {
				t, _ := row["tags"].(string)
				u, _ := row["url"].(string)
				m.Tags = types.StringValue(t)
				m.URL = types.StringValue(u)
			}
		}
	}
	if m.Tags.IsUnknown() || m.Tags.IsNull() {
		m.Tags = types.StringValue("")
	}
	if m.URL.IsUnknown() || m.URL.IsNull() {
		m.URL = types.StringValue("")
	}
	return true, nil
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &m); err != nil {
		var ve *apsvault.Error
		if errors.As(err, &ve) && ve.Status == 403 {
			resp.Diagnostics.AddError("token cannot write", "This service token has no can_write permission; create one with can_write for the folder (Tokens → new → «запись»).")
			return
		}
		resp.Diagnostics.AddError("creating secret", err.Error())
		return
	}
	if _, err := r.refresh(ctx, &m); err != nil {
		resp.Diagnostics.AddError("reading back the created secret", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.refresh(ctx, &m)
	if err != nil {
		resp.Diagnostics.AddError("reading secret", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx) // deleted outside Terraform → plan recreates it
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &m); err != nil {
		resp.Diagnostics.AddError("updating secret", err.Error())
		return
	}
	if _, err := r.refresh(ctx, &m); err != nil {
		resp.Diagnostics.AddError("reading back the updated secret", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, m.Name.ValueString()); err != nil {
		var ve *apsvault.Error
		if errors.As(err, &ve) && ve.Status == 404 {
			return // already gone
		}
		resp.Diagnostics.AddError("deleting secret", fmt.Sprintf("%s (the token needs can_write; vault 0.30.1+)", err))
	}
}

// ImportState: `terraform import apsvault_secret.db <name>` — the value is read from the vault.
func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

var _ resource.ResourceWithImportState = (*secretResource)(nil)
