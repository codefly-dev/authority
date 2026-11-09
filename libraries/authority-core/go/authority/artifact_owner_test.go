package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// An owner's artifact: a person reaching an artifact module through a
// solution's binding holds its policy owned by that solution's installation,
// so the artifact is the solution installation's, in its namespace. Consent
// in person (activate) comes through the solution's page hop; running comes
// through any hop; the artifact module's own namespace is refused to such a
// parent, as another owner's would be.
func TestAnOwnersArtifactIsInItsOwnersNamespace(t *testing.T) {
	h := newHarness(t)
	agent := domain.Module{Name: "agent", Principal: "agent", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "read", "activate", "run")}}
	if _, err := h.svc.ApplyModule(h.ctx, agent); err != nil {
		t.Fatal(err)
	}
	builder := domain.Module{Name: "builder", Principal: "builder", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole,
		ResourceKinds:    []*basev0.WorkScopeV1{sc("builder.note", "read", "write")},
		Bindings:         map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{sc("agent.intents", "read", "activate", "run")}}},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc("builder.note", "read", "write"), sc("agent.intents", "read", "activate", "run")},
			"editor":             {sc("builder.note", "read"), sc("agent.intents", "read", "activate", "run")},
			"viewer":             {sc("builder.note", "read"), sc("agent.intents", "read", "run")},
		}}
	if _, err := h.svc.ApplyModule(h.ctx, builder); err != nil {
		t.Fatal(err)
	}
	h.installAs(acme, "builder", "")
	h.grant("builder", "editor", "maya")
	h.grant("builder", "viewer", "remi")
	all, err := h.svc.Installations(h.ctx, h.admin(acme), acme)
	if err != nil {
		t.Fatal(err)
	}
	var agentInst string
	for _, i := range all {
		if i.Target == "agent" {
			agentInst = i.ID
		}
	}
	if agentInst == "" {
		t.Fatal("agent is not installed by composition")
	}
	owned := acme + ".builder"
	decideAs := func(parent authority.Issued, action, source string) error {
		_, err := h.svc.DecideArtifact(h.ctx, parent.Token, authority.Workload{Module: "agent"}, agentInst, "agent.intents", action,
			&decide.ArtifactIdentity{Schema: "s/v1", Source: source, Subject: []byte("x")})
		return err
	}
	page := h.must(h.page("maya", "builder", "agent"))
	if got := effective(page)[0].GetResourceOwnerId(); got != h.principal(acme, "builder") {
		t.Fatalf("through the solution the policy is owned by its installation, got %q", got)
	}
	if err := decideAs(page, decide.ArtifactActivate, owned); err != nil {
		t.Fatalf("the editor present on the builder's page consents to the builder's artifact: %v", err)
	}
	if err := decideAs(page, decide.ArtifactRun, owned); err != nil {
		t.Fatalf("and runs it: %v", err)
	}
	refused(t, decideAs(page, decide.ArtifactActivate, acme+".agent"), "namespace")
	refused(t, decideAs(page, decide.ArtifactActivate, acme+".other"), "namespace")
	backend := h.must(h.through("maya", "builder", "agent"))
	refused(t, decideAs(backend, decide.ArtifactActivate, owned), "person present")
	if err := decideAs(backend, decide.ArtifactRun, owned); err != nil {
		t.Fatalf("the builder's backend runs its artifact for the editor: %v", err)
	}
	viewer := h.must(h.page("remi", "builder", "agent"))
	refused(t, decideAs(viewer, decide.ArtifactActivate, owned), "agent.intents:activate")
	if err := decideAs(viewer, decide.ArtifactRun, owned); err != nil {
		t.Fatalf("the viewer runs the builder's artifact: %v", err)
	}
}

// The namespace an owned parent authors in is its owner's installation's; an
// unowned parent's is the module installation's own.
func TestTheParentAuthorsInItsOwnersNamespace(t *testing.T) {
	h := newHarness(t)
	agent := domain.Module{Name: "agent", Principal: "agent", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "read", "activate", "run")}}
	if _, err := h.svc.ApplyModule(h.ctx, agent); err != nil {
		t.Fatal(err)
	}
	builder := domain.Module{Name: "builder", Principal: "builder", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("builder.note", "read")},
		Bindings: map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{sc("agent.intents", "read", "run")}}},
		Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {sc("builder.note", "read")}, "viewer": {sc("builder.note", "read"), sc("agent.intents", "read", "run")}}}
	if _, err := h.svc.ApplyModule(h.ctx, builder); err != nil {
		t.Fatal(err)
	}
	h.installAs(acme, "builder", "")
	h.grant("builder", "viewer", "remi")
	owned := h.must(h.page("remi", "builder", "agent"))
	inst, namespace, err := h.svc.CurrentAuthoring(h.ctx, owned.Token, authority.Workload{Module: "agent"})
	if err != nil || namespace != acme+".builder" || inst.Target != "agent" {
		t.Fatalf("an owned parent authors in %q at %s (%v)", namespace, inst.Target, err)
	}
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "agent-reader", Scopes: []domain.RoleScope{{Kind: "agent.intents", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "lea", Organization: acme, Roles: []string{"agent-reader"}})
	own := h.must(h.root("lea", "agent"))
	if _, namespace, err := h.svc.CurrentAuthoring(h.ctx, own.Token, authority.Workload{Module: "agent"}); err != nil || namespace != acme+".agent" {
		t.Fatalf("an unowned parent authors in %q (%v)", namespace, err)
	}
}
