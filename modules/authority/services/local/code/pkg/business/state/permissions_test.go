package state_test

import (
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"slices"
	"strings"
	"testing"
)

func TestGeneratedDeveloperTracksReplacementAndReportsBusinessGaps(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Name: "ledger", Principal: "ledger", Kind: "module", Generation: 1,
		Methods: map[string]state.MethodPolicy{
			"/ledger/Write":   {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}},
			"/ledger/Version": {AnyCheckedCaller: true},
			"/ledger/Missing": {},
		}}
	before := k.State.RoleScopes("acme", "viewer")
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	held, err := k.PersonScopes(t, "dev", "ledger")
	if err != nil || !state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}, held) {
		t.Fatalf("developer: %v %v", held, err)
	}
	report := strings.Join(k.State.PermissionReport(), "\n")
	for _, want := range []string{"acme/developer × ledger@1 × /ledger/Write: covered statically", "acme/viewer × ledger@1 × /ledger/Write: state: forbidden", "/ledger/Missing: no single declared role", "resource checks still apply"} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q in report", want)
		}
	}
	m.Generation = 2
	m.Methods = map[string]state.MethodPolicy{"/ledger/Read": {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "read")}}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	held, err = k.PersonScopes(t, "dev", "ledger")
	if err != nil || state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}, held) {
		t.Fatalf("removed write retained: %v %v", held, err)
	}
	if !state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "read")}, held) {
		t.Fatal("new read missing")
	}
	after := k.State.RoleScopes("acme", "viewer")
	if !state.Attenuates(before, after) || !state.Attenuates(after, before) {
		t.Fatal("business role changed")
	}
	for _, sc := range k.State.RoleScopes("acme", "developer") {
		if sc.GetResourceKind() == "*" {
			t.Fatal("generated wildcard")
		}
	}
}

func TestGeneratedDeveloperNeverCopiesWildcardCarrierCeilings(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Name: "unresolved", Principal: "unresolved", Kind: "module", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("unresolved.entry", "*")},
		Methods:       map[string]state.MethodPolicy{"/unresolved/Read": {Requires: []*basev0.WorkScopeV1{testkit.Scope("unresolved.entry", "read")}}}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	held := k.State.RoleScopes("acme", "developer")
	for _, scope := range held {
		if scope.GetResourceKind() == "*" || slices.Contains(scope.GetActions(), "*") {
			t.Fatalf("wildcard leaked: %v", scope)
		}
	}
	if !state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("unresolved.entry", "read")}, held) {
		t.Fatal("explicit method permission lost")
	}
	if !strings.Contains(strings.Join(k.State.PermissionReport(), "\n"), "wildcard ceiling is unresolved") {
		t.Fatal("missing wildcard diagnostic")
	}
}
