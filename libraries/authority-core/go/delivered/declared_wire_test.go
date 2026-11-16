package delivered_test

import (
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	compositionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/composition/v1"
	"github.com/codefly-dev/authority/libraries/authority-core/go/declare"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// declaration is one rendering exercising every field the document carries:
// own scopes, installation-owned scopes, a through per binding first named,
// shared kinds, owner-aware, an installation role and an edge.
func declaration() *declare.Declaration {
	scope := func(kind string, actions ...string) declare.DeclaredScope {
		return declare.DeclaredScope{ResourceKind: kind, Actions: actions}
	}
	return &declare.Declaration{
		Authority: solutionhost.Authority{Principal: "notebook", InstallationRole: "none", ResourceKinds: []string{"notebook.page", "notebook.catalogue"},
			EdgeDependencies: []modulecontract.EdgeDependency{{Module: "tracing", Presence: "optional"}},
			Bindings:         []solutionhost.AuthorityBinding{{ID: "store", Audience: "store", Operations: map[string][]string{"invoke": {"store.item:read", "store.item:write"}}}}},
		Document: declare.AuthorityDocument{
			ScopeCeilings: []declare.DeclaredScope{scope("notebook.page", "read", "write"), scope("notebook.catalogue", "read")},
			Roles: []declare.DeclaredRole{
				{Name: "admin", Scopes: []declare.DeclaredScope{scope("notebook.page", "read", "write"), scope("store.item", "read", "write")},
					InstallationOwnedScopes: []declare.DeclaredScope{scope("store.item", "read")},
					Through:                 []declare.RoleThrough{{Binding: "store", Scopes: []declare.DeclaredScope{scope("model.profiles", "invoke")}}}},
				{Name: "user", Scopes: []declare.DeclaredScope{scope("notebook.page", "read"), scope("store.item", "read")}},
			},
			OwnerAware: true, SharedKinds: []string{"notebook.catalogue"}, InstallationRole: "none",
			EdgeDependencies: []modulecontract.EdgeDependency{{Module: "tracing", Presence: "optional"}},
		},
	}
}

func manifest() *solutionhost.ModuleManifest {
	return &solutionhost.ModuleManifest{Alias: "notebook", Kind: solutionhost.KindSolution, Generation: 3}
}

// fromWire is the CLI's wire path for d: its readers spell the declaration as
// the authority's interface (cli pkg/gitops roles.go, wireScopes), the
// delivery marshals it as AuthorityManifestV1 (AuthoritySources.Declaration),
// and the host decodes those bytes into the authority's Document
// (delivered_authority.go deliveredModule), which Module reads.
func fromWire(t *testing.T, d *declare.Declaration, methods []*compositionv1.MethodPolicyV1) domain.Module {
	t.Helper()
	wire := func(in []declare.DeclaredScope) []*authorityv1.WorkScopeV1 {
		var out []*authorityv1.WorkScopeV1
		for _, sc := range in {
			out = append(out, &authorityv1.WorkScopeV1{ResourceKind: sc.ResourceKind, Actions: sc.Actions})
		}
		return out
	}
	document := &compositionv1.AuthorityManifestV1{Methods: methods, ScopeCeilings: wire(d.Document.ScopeCeilings), OwnerAware: d.Document.OwnerAware,
		InstallationRole: d.Document.InstallationRole, SharedKinds: d.Document.SharedKinds}
	for _, edge := range d.Document.EdgeDependencies {
		document.EdgeDependencies = append(document.EdgeDependencies, &compositionv1.EdgeDependencyV1{Module: edge.Module, Presence: edge.Presence})
	}
	for _, role := range d.Document.Roles {
		r := &compositionv1.RoleV1{Name: role.Name, Scopes: wire(role.Scopes), InstallationOwnedScopes: wire(role.InstallationOwnedScopes)}
		for _, through := range role.Through {
			r.Through = append(r.Through, &compositionv1.RoleThroughV1{Binding: through.Binding, Scopes: wire(through.Scopes)})
		}
		document.Roles = append(document.Roles, r)
	}
	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var read compositionv1.AuthorityManifestV1
	if err := proto.Unmarshal(bytes, &read); err != nil {
		t.Fatal(err)
	}
	core := func(in []*authorityv1.WorkScopeV1) []*basev0.WorkScopeV1 {
		out := make([]*basev0.WorkScopeV1, 0, len(in))
		for _, sc := range in {
			raw, _ := proto.Marshal(sc)
			c := &basev0.WorkScopeV1{}
			_ = proto.Unmarshal(raw, c)
			out = append(out, c)
		}
		return out
	}
	m := manifest()
	authority := d.Authority
	m.Authority = &authority
	doc := &delivered.Document{Module: m.Alias, Generation: m.Generation, ScopeCeilings: core(read.GetScopeCeilings()), OwnerAware: read.GetOwnerAware(),
		InstallationRole: read.GetInstallationRole(), SharedKinds: read.GetSharedKinds()}
	for _, edge := range read.GetEdgeDependencies() {
		doc.EdgeDependencies = append(doc.EdgeDependencies, domain.EdgeDependency{Module: edge.GetModule(), Presence: edge.GetPresence()})
	}
	for _, method := range read.GetMethods() {
		doc.Methods = append(doc.Methods, delivered.Method{Method: method.GetMethod(), Requires: core(method.GetRequires()), AnyCheckedCaller: method.GetAnyCheckedCaller()})
	}
	for _, r := range read.GetRoles() {
		role := delivered.Role{Name: r.GetName(), Scopes: core(r.GetScopes()), InstallationOwned: core(r.GetInstallationOwnedScopes())}
		for _, through := range r.GetThrough() {
			if role.Through == nil {
				role.Through = map[string]delivered.Scopes{}
			}
			role.Through[through.GetBinding()] = append(role.Through[through.GetBinding()], core(through.GetScopes())...)
		}
		doc.Roles = append(doc.Roles, role)
	}
	module, err := delivered.Module(m, doc)
	if err != nil {
		t.Fatal(err)
	}
	return module
}

// Declared, the in-process reading of core's declaration, composes the same
// module as the CLI's wire path through AuthorityManifestV1: the two paths
// from one declaration to the authority's module never drift apart. An empty
// list and an absent one are the same (the wire cannot tell them apart).
func TestDeclaredComposesWhatTheWireDelivers(t *testing.T) {
	requires := []*authorityv1.WorkScopeV1{{ResourceKind: "notebook.page", Actions: []string{"read"}}}
	wireMethods := []*compositionv1.MethodPolicyV1{{Method: "GET /v1/notebook/pages", Requires: requires}, {Method: "GET /v1/notebook/elsewhere", AnyCheckedCaller: true}}
	methods := []delivered.Method{{Method: "GET /v1/notebook/pages", Requires: []*basev0.WorkScopeV1{{ResourceKind: "notebook.page", Actions: []string{"read"}}}},
		{Method: "GET /v1/notebook/elsewhere", AnyCheckedCaller: true}}
	declared, err := delivered.Declared(manifest(), declaration(), methods)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(fromWire(t, declaration(), wireMethods), declared, protocmp.Transform(), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("Declared and the wire path compose different modules (-wire +declared):\n%s", diff)
	}
}
