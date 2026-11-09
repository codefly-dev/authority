package authority_test

import (
	"slices"
	"strings"
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
	wiki, builder := reachSolutions()
	for _, m := range []domain.Module{wiki, builder} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatalf("%s's roles name what its binding reaches through the agent: %v", m.Name, err)
		}
		h.installAs(acme, m.Name, "")
	}
}

// reachSolutions are a wiki and a builder whose roles name, through their
// binding to the agent, what the agent's own bindings reach: the model's
// profiles and the evidence for a chat; the configuration write for an
// editor alone.
func reachSolutions() (wiki, builder domain.Module) {
	chat := []*basev0.WorkScopeV1{sc("agent.intents", "read", "run"), sc("agent.tasks", "execute")}
	chatThrough := []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke"), sc("docs.doc", "read")}
	wiki = domain.Module{Name: "wiki", Principal: "wiki", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("wiki.page", "read")},
		Bindings: map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{sc("agent.intents", "read", "run"), sc("agent.tasks", "execute")}}},
		Roles:    map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {sc("wiki.page", "read")}, "viewer": append([]*basev0.WorkScopeV1{sc("wiki.page", "read")}, chat...)}}
	through(&wiki, "viewer", "agent", chatThrough...)
	author := []*basev0.WorkScopeV1{sc("builder.assistant", "read", "write"), sc("agent.intents", "read", "configure", "activate", "run"), sc("agent.tasks", "execute")}
	authorThrough := []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke"), sc("docs.doc", "read", "write")}
	builder = domain.Module{Name: "builder", Principal: "builder", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("builder.assistant", "read", "write")},
		Bindings: map[string]domain.Binding{"agent": {ID: "agent", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{
			sc("agent.intents", "read", "configure", "activate", "run"), sc("agent.tasks", "execute")}}},
		Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: slices.Clone(author), "editor": slices.Clone(author),
			"viewer": append([]*basev0.WorkScopeV1{sc("builder.assistant", "read")}, chat...)}}
	through(&builder, domain.InstallerRole, "agent", authorThrough...)
	through(&builder, "editor", "agent", authorThrough...)
	through(&builder, "viewer", "agent", chatThrough...)
	return wiki, builder
}

// through declares scopes role names through binding, part of its grant, as
// a delivered document reads them.
func through(m *domain.Module, role, binding string, scopes ...*basev0.WorkScopeV1) {
	if m.Through == nil {
		m.Through = map[string]map[string][]*basev0.WorkScopeV1{}
	}
	if m.Through[role] == nil {
		m.Through[role] = map[string][]*basev0.WorkScopeV1{}
	}
	m.Through[role][binding] = append(m.Through[role][binding], scopes...)
	m.Roles[role] = append(m.Roles[role], scopes...)
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

// Transitive reach is declared: a role names a kind reached downstream of a
// binding through that binding, never by inference, and the binding is one
// it declares that carries a person's capability.
func TestReachIsDeclaredThroughABinding(t *testing.T) {
	h := newHarness(t)
	reachComposition(t, h, true)
	wiki, _ := reachSolutions()
	wiki.Generation = 2
	wiki.Roles["viewer"] = append(wiki.Roles["viewer"], sc("docs.doc", "write"))
	_, err := h.svc.ApplyModule(h.ctx, wiki)
	refused(t, err, "a kind reached downstream of a binding is named through it")

	wiki, _ = reachSolutions()
	wiki.Generation = 2
	through(&wiki, "viewer", "nowhere", sc("docs.doc", "read"))
	_, err = h.svc.ApplyModule(h.ctx, wiki)
	refused(t, err, `names scopes through binding "nowhere", which wiki does not declare`)

	wiki, _ = reachSolutions()
	wiki.Generation = 2
	wiki.Bindings["jobs"] = domain.Binding{ID: "jobs", Audience: "agent", HeadlessScopes: []*basev0.WorkScopeV1{sc("agent.tasks", "execute")}}
	through(&wiki, "viewer", "jobs", sc("docs.doc", "read"))
	_, err = h.svc.ApplyModule(h.ctx, wiki)
	refused(t, err, `through binding "jobs", which carries nothing for a person`)

	wiki, _ = reachSolutions()
	wiki.Generation = 2
	through(&wiki, "viewer", "agent", sc("billing.invoice", "read"))
	_, err = h.svc.ApplyModule(h.ctx, wiki)
	refused(t, err, `names billing.invoice:read through binding "agent", which reaches it nowhere`)
}

// Delivery order is free, and a reach once declared holds: a solution
// naming what an agent not yet composed reaches is accepted, and the agent's
// own delivery is then held to reach it; a later delivery that would leave
// it unreached is refused naming the reach.
func TestAReachIsHeldAtEveryDelivery(t *testing.T) {
	h := newHarness(t)
	for _, m := range []domain.Module{
		{Name: "model", Principal: "model", Kind: domain.KindModule, Generation: 1, ResourceKinds: []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke")}, SharedKinds: []string{"model.profiles"}},
		{Name: "docs", Principal: "docs", Kind: domain.KindModule, Generation: 1, OwnerAware: true, ResourceKinds: []*basev0.WorkScopeV1{sc("docs.doc", "read", "write")}},
	} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	wiki, _ := reachSolutions()
	if _, err := h.svc.ApplyModule(h.ctx, wiki); err != nil {
		t.Fatalf("a reach through a module not yet composed waits for it: %v", err)
	}
	agent := domain.Module{Name: "agent", Principal: "agent", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "read", "run"), sc("agent.tasks", "execute")},
		Bindings: map[string]domain.Binding{
			"model": {ID: "model", Audience: "model", InvokeScopes: []*basev0.WorkScopeV1{sc("model.profiles", "read", "invoke")}},
		}}
	_, err := h.svc.ApplyModule(h.ctx, agent)
	refused(t, err, `delivering agent at 1 would leave a reach unreached: role "viewer" of wiki names docs.doc:read through binding "agent"`)
	agent.Bindings["evidence"] = domain.Binding{ID: "evidence", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{sc("docs.doc", "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, agent); err != nil {
		t.Fatalf("the agent reaches what the wiki names through it: %v", err)
	}
	agent.Generation = 2
	delete(agent.Bindings, "model")
	_, err = h.svc.ApplyModule(h.ctx, agent)
	refused(t, err, `names model.profiles:invoke, model.profiles:read through binding "agent"`)
}

// The install review shows a kind reached through the agent where it is
// held: in the agent, then in the model, on the path from the solution.
func TestTheReviewShowsAReachThroughTheAgent(t *testing.T) {
	h := newHarness(t)
	reachComposition(t, h, true)
	wiki, _ := reachSolutions()
	composition := map[string]domain.Module{}
	for _, name := range []string{"model", "docs", "agent", "wiki"} {
		m, err := h.svc.Composed(h.ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		composition[m.Principal] = m
	}
	rows, err := decide.Reach(composition[wiki.Principal], "viewer", composition)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, row := range rows {
		if row.Module == "model" || row.Module == "docs" {
			paths = append(paths, strings.Join(row.Path, " > ")+": "+row.Via)
		}
	}
	slices.Sort(paths)
	if want := []string{"wiki > agent > docs: binding", "wiki > agent > model: binding"}; !slices.Equal(paths, want) {
		t.Fatalf("the review shows %v, want %v", paths, want)
	}
}
