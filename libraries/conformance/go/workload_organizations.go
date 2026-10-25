package conformance

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WorkloadOrganizationCase names a workload and its headless binding. Organization
// is the expected tenant for successful inference. Module is the owner principal.
type WorkloadOrganizationCase struct {
	Credential, Module, Binding, Audience, Organization string
}

// WorkloadOrganizationsCase exercises omitted organization without granting a
// caller arbitrary tenant authority. Single has one active installation (or a
// delivered tenant pin). Ambiguous has multiple active installing organizations
// and no tenant pin; None has no active installation and no tenant pin.
// Use dedicated modules: the suite also exercises composition and revocation.
type WorkloadOrganizationsCase struct {
	Single, Ambiguous, None WorkloadOrganizationCase
}

func (c *client) workloadOrganizations(t *testing.T, ctx context.Context, f WorkloadOrganizationsCase) {
	for _, tc := range []struct {
		name    string
		fixture WorkloadOrganizationCase
		reason  string
	}{
		{"single", f.Single, ""},
		{"ambiguous", f.Ambiguous, "ambiguous"},
		{"none", f.None, "no active installation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fixture
			if f.Credential == "" || f.Module == "" || f.Binding == "" || f.Audience == "" || (tc.reason == "" && f.Organization == "") {
				t.Fatal("workload organization fixture is incomplete")
			}
			out, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
				"workload": map[string]any{"credential": f.Credential}, "operation_binding_id": f.Binding,
			})
			if tc.reason != "" {
				if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), tc.reason) || !strings.Contains(status.Convert(err).Message(), "must name one organization") {
					t.Fatalf("want named %s organization refusal, got %v", tc.reason, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wc := msg(out, "context")
			if str(wc, "tenant_id") != f.Organization || str(wc, "organization_id") != f.Organization ||
				str(wc, "owner_principal_id") != f.Module || str(wc, "owner_principal_kind") != "service" || str(wc, "audience") != f.Audience ||
				str(msg(wc, "seal"), "installation_id") == "" || str(msg(wc, "operation_binding"), "binding_id") == "" {
				t.Fatalf("inferred workload context lost tenant or binding: %v", wc)
			}
			c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Audience})
		})
	}
}
