package conformance

import (
	"context"
	"google.golang.org/grpc/codes"
	"testing"
)

// WorkloadOrganizationCase names a dedicated module and its declared binding.
// The fixture supplies its actual workload credential, not a tenant override.
type WorkloadOrganizationCase struct{ Credential, Module, Binding, Audience string }

// WorkloadOrganizationsCase requires both isolation refusals; it makes no
// inference promise. Ambiguous has two active installing organizations; None
// has no active installation. Neither principal has a delivered tenant pin.
type WorkloadOrganizationsCase struct{ Ambiguous, None WorkloadOrganizationCase }

func (c *client) workloadOrganizations(t *testing.T, ctx context.Context, f *WorkloadOrganizationsCase) {
	for _, name := range []string{"ambiguous", "none"} {
		t.Run("an empty workload organization with "+name+" installations is refused", func(t *testing.T) {
			if f == nil {
				t.Fatal("required conformance fixture missing: ambiguous and absent workload installations")
			}
			probe := f.Ambiguous
			if name == "none" {
				probe = f.None
			}
			if probe.Credential == "" || probe.Module == "" || probe.Binding == "" || probe.Audience == "" {
				t.Fatal("required workload organization refusal fixture is incomplete")
			}
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"workload": map[string]any{"credential": probe.Credential}, "operation_binding_id": probe.Binding, "audience": probe.Audience})
			refused(t, err, codes.PermissionDenied, "must name the organization of the work item")
		})
	}
}
