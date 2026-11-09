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
			// A runnable operation's prepared binding (one per operation, its
			// invoke scopes the operation's own), and one of the agent's own
			// operations as a runnable, addressed to the agent itself.
			"DOCS__SEARCH": {ID: "DOCS__SEARCH", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{sc("docs.doc", "read")}},
			"AGENT__READ":  {ID: "AGENT__READ", Audience: "agent", InvokeScopes: []*basev0.WorkScopeV1{sc("agent.intents", "read")}},
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

// Delivery order is free, and a module's release is never tied to the
// solutions reaching through it: a solution naming what an agent not yet
// composed reaches is accepted; an agent delivered without what the solution
// names through it is accepted too, the solution's reach reported unreached
// on its installation (journaled once) and a turn's hop there refused by
// name; the agent redelivered with it re-converges the reach by itself.
func TestAnUnreachedReachIsReportedAndReconverges(t *testing.T) {
	t.Run("a reach through a module not yet composed waits for it", func(t *testing.T) {
		h := newHarness(t)
		wiki, _ := reachSolutions()
		if _, err := h.svc.ApplyModule(h.ctx, wiki); err != nil {
			t.Fatal(err)
		}
		h.installAs(acme, "wiki", "")
		if gaps, _ := h.svc.Unreached(h.ctx, h.stored(acme, "wiki")); len(gaps) != 1 || gaps[0] != "role viewer reaches nothing of docs.doc:read, model.profiles:invoke, model.profiles:read through agent: agent not composed" {
			t.Fatalf("a reach waiting for its module is reported so: %v", gaps)
		}
	})
	h := newHarness(t)
	svc, events := journaled(h)
	h.svc = svc
	reachComposition(t, h, true)
	h.grant("wiki", "viewer", "maya")
	wiki := h.stored(acme, "wiki")
	if gaps, _ := h.svc.Unreached(h.ctx, wiki); len(gaps) != 0 {
		t.Fatalf("a composition reaching what the wiki names reports %v", gaps)
	}
	agent, err := h.svc.Composed(h.ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	withModel := agent.Bindings["model"]
	agent.Generation = 2
	delete(agent.Bindings, "model")
	if _, err := h.svc.ApplyModule(h.ctx, agent); err != nil {
		t.Fatalf("an agent delivered without what a solution names through it is accepted: %v", err)
	}
	gaps, err := h.svc.Unreached(h.ctx, h.stored(acme, "wiki"))
	if err != nil || len(gaps) != 1 || gaps[0] != "role viewer reaches nothing of model.profiles:invoke, model.profiles:read through agent: no module agent reaches consumes it for a person" {
		t.Fatalf("the wiki's reach is reported unreached: %v %v", gaps, err)
	}
	if e, ok := lastEvent(*events, domain.InstallationReachUnreached); !ok || e.Subject != wiki.ID || !strings.Contains(e.Detail["unreached"], "model.profiles") {
		t.Fatalf("installation.reach_unreached was not journaled: %+v %v", e, ok)
	}
	atAgent := h.must(h.page("maya", "wiki", "agent"))
	_, err = h.onward(atAgent, "model")
	refused(t, err, `operation binding "model" is not one agent declares`)
	h.must(h.onward(atAgent, "evidence"))

	agent.Generation = 3
	agent.Bindings["model"] = withModel
	if _, err := h.svc.ApplyModule(h.ctx, agent); err != nil {
		t.Fatal(err)
	}
	if gaps, _ := h.svc.Unreached(h.ctx, h.stored(acme, "wiki")); len(gaps) != 0 {
		t.Fatalf("the reach did not re-converge: %v", gaps)
	}
	if e, ok := lastEvent(*events, domain.InstallationReachRestored); !ok || e.Subject != wiki.ID {
		t.Fatalf("installation.reach_restored was not journaled: %+v %v", e, ok)
	}
	if up, _ := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "wiki")); up {
		t.Fatal("a declared reach reached again asks the administrator nothing new")
	}
	atAgent = h.must(h.page("maya", "wiki", "agent"))
	exactly(t, h.must(h.onward(atAgent, "model")), "model.profiles", "", []string{"invoke", "read"})
	reported := map[domain.EventKind]int{}
	for _, e := range *events {
		if e.Subject == wiki.ID {
			reported[e.Kind]++
		}
	}
	if reported[domain.InstallationReachUnreached] != 1 || reported[domain.InstallationReachRestored] != 1 {
		t.Fatalf("each change is journaled once, got %v", reported)
	}
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

// A runnable tool asks its operation's own scopes, selected to the owner its
// capability is confined to (the solution's installation, which the asking
// module reads from its own admitted scopes): issued through the operation's
// prepared binding, and through one of the agent's own operations as a
// runnable addressed to the agent itself; a kind the audience declares shared
// is asked and issued unselected. Owner-blind, the ask is the whole kind and
// is refused as a widening; another owner's too.
func TestARunnableAsksItsOperationsScopesThroughTheSolution(t *testing.T) {
	h := newHarness(t)
	reachComposition(t, h, true)
	h.grant("wiki", "viewer", "maya")
	wiki := h.principal(acme, "wiki")
	owned := func(kind, owner string, actions ...string) *basev0.WorkScopeV1 {
		return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceOwnerId: owner}
	}
	atAgent := h.must(h.page("maya", "wiki", "agent"))
	exactly(t, h.must(h.onward(atAgent, "DOCS__SEARCH", owned("docs.doc", wiki, "read"))), "docs.doc", wiki, []string{"read"})
	exactly(t, h.must(h.onward(atAgent, "AGENT__READ", owned("agent.intents", wiki, "read"))), "agent.intents", wiki, []string{"read"})
	exactly(t, h.must(h.onward(atAgent, "model", owned("model.profiles", wiki, "invoke"))), "model.profiles", "", []string{"invoke"})
	for name, ask := range map[string]*basev0.WorkScopeV1{
		"the whole kind": sc("docs.doc", "read"), "another owner": owned("docs.doc", "someone-else", "read"), "beyond the role": owned("docs.doc", wiki, "write"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.onward(atAgent, "DOCS__SEARCH", ask)
			refused(t, err, `a child widens what its owner holds through binding "DOCS__SEARCH"`)
		})
	}
}
