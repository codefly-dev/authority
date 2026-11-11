package installation

import (
	"testing"

	"gateway/pkg/business/state"
)

// A composed installation is named to ANY member of the organization, so the
// projection carries only which installation, of what, and the source its
// authored agents belong to. Nobody holds a role on a composed installation,
// so a member reading one has no claim on its principal, the generation its
// consent sits at, its status, the roles its target declares, or what its
// declared reach leaves unreached: those answer the administrator read.
//
// This is a projection test, not an end-to-end one: it pins what wireComposed
// emits, and does not exercise ListHeld's handler.
func TestComposedProjectionCarriesOnlyWhatNamingOneRequires(t *testing.T) {
	in := state.Installation{
		ID:           "inst-1",
		Organization: "acme",
		Target:       "records",
		Status:       state.Active,
		AgentRole:    "records-agent",
		PrincipalID:  "principal-should-not-travel",
		InstalledBy:  "someone",
	}

	out := wireComposed(in)

	if out.GetId() != "inst-1" {
		t.Fatalf("id: want inst-1, got %q", out.GetId())
	}
	if out.GetTarget() != "records" {
		t.Fatalf("target: want records, got %q", out.GetTarget())
	}
	if out.GetNamespace() != state.Namespace(in) {
		t.Fatalf("namespace: want %q, got %q", state.Namespace(in), out.GetNamespace())
	}

	// What a member has no claim on.
	if out.GetPrincipalId() != "" {
		t.Errorf("principal_id travelled to a member: %q", out.GetPrincipalId())
	}
	if out.GetApprovedGeneration() != 0 {
		t.Errorf("approved_generation travelled to a member: %d", out.GetApprovedGeneration())
	}
	if len(out.GetUnreached()) != 0 {
		t.Errorf("unreached travelled to a member: %v", out.GetUnreached())
	}
	if len(out.GetRoles()) != 0 {
		t.Errorf("roles travelled to a member: %v", out.GetRoles())
	}
	if out.GetRole() != "" {
		t.Errorf("agent role travelled to a member: %q", out.GetRole())
	}
	if out.GetOrganizationId() != "" {
		t.Errorf("organization_id is not needed to name one: %q", out.GetOrganizationId())
	}
	if out.GetUpgradeAvailable() {
		t.Error("upgrade_available travelled to a member")
	}
}
