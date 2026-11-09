package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The chain a solution's page reaches through an agent: wiki or builder →
// agent (robin's shape: owner-aware, onward to the model and the document
// store) → model (shared profiles, not owner-aware) and docs (owner-aware).
func reachComposition(t *testing.T, h *harness, modelShared bool) {
	t.Helper()
	model := domain.Module{Name: "model", Principal: "model", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke")}}
	if modelShared {
		model.SharedKinds = []string{"model.profiles"}
	}
	docs := domain.Module{Name: "docs", Principal: "docs", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("docs.doc", "read", "write")}}
	agent := domain.Module{Name: "agent", Principal: "agent", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "read", "configure", "activate", "run"), sc("agent.tasks", "execute")},
		Bindings: map[string]domain.Binding{
			"model":               {ID: "model", Audience: "model", InvokeScopes: []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke")}},
			"evidence":            {ID: "evidence", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{sc("docs.doc", "read")}},
			"configuration-write": {ID: "configuration-write", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{sc("docs.doc", "write")}},
		}}
	for _, m := range []domain.Module{model, docs, agent} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	chat := []*basev0.WorkScopeV1{sc("agent.intents", "read", "run"), sc("agent.tasks", "execute"), sc("model.profiles", "read", "invoke"), sc("docs.doc", "read")}
	wiki := domain.Module{Name: "wiki", Principal: "wiki", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("wiki.page", "read")},
		Bindings: map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{sc("agent.intents", "read", "run"), sc("agent.tasks", "execute")}}},
		Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {sc("wiki.page", "read")}, "viewer": append([]*basev0.WorkScopeV1{sc("wiki.page", "read")}, chat...)}}
	author := []*basev0.WorkScopeV1{sc("builder.assistant", "read", "write"), sc("agent.intents", "read", "configure", "activate", "run"), sc("agent.tasks", "execute"),
		sc("model.profiles", "read", "invoke"), sc("docs.doc", "read", "write")}
	builder := domain.Module{Name: "builder", Principal: "builder", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("builder.assistant", "read", "write")},
		Bindings: map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{
			sc("agent.intents", "read", "configure", "activate", "run"), sc("agent.tasks", "execute")}}},
		Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: author, "editor": author,
			"viewer": append([]*basev0.WorkScopeV1{sc("builder.assistant", "read")}, chat...)}}
	for _, m := range []domain.Module{wiki, builder} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatalf("%s's roles name what its binding reaches through the agent: %v", m.Name, err)
		}
		h.installAs(acme, m.Name, "")
	}
}

func (h *harness) onward(parent authority.Issued, binding string, scopes ...*basev0.WorkScopeV1) (authority.Issued, error) {
	return h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "agent"}, authority.IssueRequest{Binding: binding, Scopes: scopes})
}

// Consent covers reach: a solution's roles name what they reach through the
// agent (the model's profiles, the document store), and a hop of the agent's
// for the person present on the solution's page carries the role there, cut
// to the agent's binding, owned by the solution's installation — except a kind
// the module declares shared (the model's profiles), held unselected.
func TestAPagesPersonReachesThroughTheAgentWhatTheirRoleNames(t *testing.T) {
	h := newHarness(t)
	reachComposition(t, h, true)
	h.grant("wiki", "viewer", "maya")
	h.grant("builder", "editor", "remi")
	h.grant("builder", "viewer", "tal")

	t.Run("a wiki viewer's turn reaches the model and reads the evidence", func(t *testing.T) {
		atAgent := h.must(h.page("maya", "wiki", "agent"))
		model := h.must(h.onward(atAgent, "model"))
		exactly(t, model, "model.profiles", "", []string{"invoke", "read"})
		evidence := h.must(h.onward(atAgent, "evidence"))
		exactly(t, evidence, "docs.doc", h.principal(acme, "wiki"), []string{"read"})
		_, err := h.onward(atAgent, "configuration-write")
		refused(t, err, `holds nothing at docs through binding "configuration-write"`)
	})
	t.Run("a builder editor publishes, activates and runs", func(t *testing.T) {
		atAgent := h.must(h.page("remi", "builder", "agent"))
		exactly(t, h.must(h.onward(atAgent, "configuration-write")), "docs.doc", h.principal(acme, "builder"), []string{"write"})
		exactly(t, h.must(h.onward(atAgent, "model")), "model.profiles", "", []string{"invoke", "read"})
		inst := ""
		all, _ := h.svc.Installations(h.ctx, h.admin(acme), acme)
		for _, i := range all {
			if i.Target == "agent" {
				inst = i.ID
			}
		}
		for _, action := range []string{decide.ArtifactActivate, decide.ArtifactRun} {
			if _, err := h.svc.DecideArtifact(h.ctx, atAgent.Token, authority.Workload{Module: "agent"}, inst, "agent.intents", action,
				&decide.ArtifactIdentity{Schema: "s/v1", Source: acme + ".builder", Subject: []byte("x")}); err != nil {
				t.Fatalf("%s: %v", action, err)
			}
		}
	})
	t.Run("a builder viewer runs, and neither writes a configuration nor activates", func(t *testing.T) {
		atAgent := h.must(h.page("tal", "builder", "agent"))
		_, err := h.onward(atAgent, "configuration-write")
		refused(t, err, `holds nothing at docs through binding "configuration-write"`)
		h.must(h.onward(atAgent, "model"))
	})
}

// A selector is never silently dropped: a module that declares no kind
// shared and checks no owner receives no owner-selected scope, as before.
func TestAModelThatDeclaresNoSharedKindReceivesNoOwnedScope(t *testing.T) {
	h := newHarness(t)
	reachComposition(t, h, false)
	h.grant("wiki", "viewer", "maya")
	atAgent := h.must(h.page("maya", "wiki", "agent"))
	_, err := h.onward(atAgent, "model")
	refused(t, err, "does not declare owner-aware checking")
}

// A shared kind is one the module serves.
func TestASharedKindIsServed(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.ApplyModule(h.ctx, domain.Module{Name: "model", Principal: "model", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc("model.profiles", "read")}, SharedKinds: []string{"other.kind"}})
	refused(t, err, "a kind it does not serve")
}
