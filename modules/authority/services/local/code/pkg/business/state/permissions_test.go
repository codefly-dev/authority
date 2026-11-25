package state_test

import (
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// The permission report covers a method by the module's own roles alone. A
// module declaring none is reported as reached through an installation that
// binds it, never through an organisation role, and nobody is issued anything
// at it on their own session: not the developer the fixture once generated a
// role for, not the administrator.
func TestThePermissionReportCoversAMethodByInstallationRolesAlone(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Name: "ledger", Principal: "ledger", Kind: "module", Generation: 1,
		Methods: map[string]state.MethodPolicy{
			"/ledger/Write":   {Requires: []*basev1.WorkScopeV1{testkit.Scope("ledger.entry", "write")}},
			"/ledger/Version": {AnyCheckedCaller: true},
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	page := testkit.Records(2)
	page.Methods = map[string]state.MethodPolicy{"/records/Write": {Requires: []*basev1.WorkScopeV1{testkit.Scope("records.records", "write")}}}
	if _, err := k.State.ApplyManifest(page); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"dev", "alex", "maya"} {
		if held, err := k.PersonScopes(t, person, "ledger"); err == nil || len(held) != 0 {
			t.Fatalf("%s holds %v at the ledger (%v)", person, held, err)
		}
	}
	report := strings.Join(k.State.PermissionReport(), "\n")
	for _, want := range []string{
		"ledger@1 /ledger/Write: declares no roles; reached through a role on an installation that binds it, never an organisation role",
		"role installation/admin × records@2 × /records/Write: covered statically; identity, installation and resource checks still apply",
		"role installation/user × records@2 × /records/Write: state: forbidden",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q in report:\n%s", want, report)
		}
	}
	for _, gone := range []string{"acme/developer", "acme/viewer", "acme/admin ×"} {
		if strings.Contains(report, gone) {
			t.Errorf("the report still covers a method by the organisation role %q", gone)
		}
	}
}

func TestThePermissionReportNamesAWildcardCeiling(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Name: "unresolved", Principal: "unresolved", Kind: "module", Generation: 1,
		ResourceKinds: []*basev1.WorkScopeV1{testkit.Scope("unresolved.entry", "*")},
		Methods:       map[string]state.MethodPolicy{"/unresolved/Read": {Requires: []*basev1.WorkScopeV1{testkit.Scope("unresolved.entry", "read")}}}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(k.State.PermissionReport(), "\n"), "wildcard ceiling is unresolved") {
		t.Fatal("missing wildcard diagnostic")
	}
}
