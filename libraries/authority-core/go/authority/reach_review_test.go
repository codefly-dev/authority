package authority_test

import (
	"errors"
	"maps"
	"math/rand"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// widenDownstream relaxes the store's Purge to what a's author holds and
// binds the store to a new replica: a's reach widens, a unchanged.
func widenDownstream(t *testing.T, h *harness) {
	t.Helper()
	replica := domain.Module{Name: "replica", Principal: "replica", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, replica); err != nil {
		t.Fatal(err)
	}
	wider := storeAt(3, "write", true)
	wider.Bindings["replica"] = domain.Binding{ID: "replica", Audience: "replica", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
}

// The installation's agent is held to the approved reach as its holders
// are: a downstream redelivery that relaxes a method and adds a binding
// widens what a's agent (author) reaches; until an administrator approves,
// the agent's call to the relaxed method and its hop onward are refused;
// once approved, both are admitted.
func TestTheInstallationsAgentIsHeldToTheApprovedReach(t *testing.T) {
	h := reachHarness(t)
	widenDownstream(h.t, h)
	inst := h.stored(acme, "a")
	agentAt := func() authority.Issued {
		return h.must(h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, inst.ID, authority.IssueRequest{Audience: "store", Binding: "store"}))
	}
	at := agentAt()
	if err := h.callStore(at, storeRead); err != nil {
		t.Fatalf("the agent's approved reach is refused: %v", err)
	}
	refused(t, h.callStore(at, storePurge), "beyond the reach its solution's installation approved")
	_, err := h.hop(at, "replica")
	refused(t, err, "holds nothing at replica")

	h.install(acme, "a")
	at = agentAt()
	if err := h.callStore(at, storePurge); err != nil {
		t.Fatalf("the approved wider reach is refused to the agent: %v", err)
	}
	if _, err := h.hop(at, "replica"); err != nil {
		t.Fatalf("the approved path to the replica is refused to the agent: %v", err)
	}
}

// legacy writes a's installation as a consent recorded before reach was
// kept would read.
func (h *harness) legacy(target string) {
	h.t.Helper()
	inst := h.stored(acme, target)
	inst.Consent.ReachDigest, inst.Consent.Reach = "", ""
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		h.t.Fatal(err)
	}
}

// A consent recorded before reach was kept is held to what its holders hold
// now, offers no upgrade for it, and adopts that reach once, before a
// delivery changes the composition or when the host starts: a later
// widening is then measured against it, offered as an upgrade, and refused
// until approved.
func TestALegacyConsentAdoptsItsReachOnce(t *testing.T) {
	h := reachHarness(t)
	h.legacy("a")
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || up {
		t.Fatalf("a legacy consent offers an upgrade for its reach: %v %v", up, err)
	}
	at := h.must(h.through("maya", "a", "store"))
	if err := h.callStore(at, storeRead); err != nil {
		t.Fatal(err)
	}
	before := h.stored(acme, "a")
	if err := h.svc.ReconcileOrganizations(h.ctx); err != nil {
		t.Fatal(err)
	}
	adopted := h.stored(acme, "a")
	if adopted.Consent.ReachDigest == "" || adopted.Revision != before.Revision {
		t.Fatalf("starting did not adopt the legacy consent's reach, or ended what it issued: %+v", adopted)
	}
	if err := h.check(at); err != nil {
		t.Fatalf("adopting the reach ended a capability: %v", err)
	}

	h.legacy("a")
	widenDownstream(h.t, h)
	inst := h.stored(acme, "a")
	if inst.Consent.ReachDigest == "" {
		t.Fatal("the delivery did not adopt the legacy consent's reach")
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, inst); err != nil || !up {
		t.Fatalf("a widening after adoption offers no upgrade: %v %v", up, err)
	}
	at = h.must(h.through("maya", "a", "store"))
	refused(t, h.callStore(at, storePurge), "beyond the reach its solution's installation approved")
	_, err := h.hop(at, "replica")
	refused(t, err, "holds nothing at replica")
}

// A delegation through a consented solution is held to its approved reach:
// the store serving write only after a's consent, maya's delegation to a
// issues read through it, never write, until an administrator approves.
func TestADelegationThroughASolutionIsHeldToTheApprovedReach(t *testing.T) {
	h := newHarness(t)
	readOnly := storeAt(2, "admin", true)
	readOnly.ResourceKinds = []*basev0.WorkScopeV1{sc(kind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, readOnly); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	h.grant("a", "author", "maya")
	if _, err := h.svc.ApplyModule(h.ctx, storeAt(3, "admin", true)); err != nil {
		t.Fatal(err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || !up {
		t.Fatalf("the store serving write offers a no upgrade: %v %v", up, err)
	}
	d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read", "write"})}, "a run", 3600)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(actions ...string) (authority.Issued, error) {
		return h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store",
			Scopes: []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), actions)}})
	}
	if _, err := issue("read"); err != nil {
		t.Fatalf("the approved reach is refused to the delegation: %v", err)
	}
	_, err = issue("write")
	refused(t, err, "")
	h.install(acme, "a")
	if _, err := issue("write"); err != nil {
		t.Fatalf("the approved wider reach is refused to the delegation: %v", err)
	}
}

// A hop for a person never exercises a binding's headless scopes, which are
// its module acting for nobody: through a headless-only binding, rob's hop
// from the store is refused by name.
func TestAHeadlessHopForAPersonIsRefused(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "legacy-reader", Scopes: []domain.RoleScope{{Kind: legacyKind, Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "rob", Organization: acme, Roles: []string{"store-reader", "legacy-reader"}})
	m := storeAt(2, "admin", true)
	m.Bindings["quiet"] = domain.Binding{ID: "quiet", Audience: "legacy-store", HeadlessScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	at := h.must(h.root("rob", "store"))
	_, err := h.svc.IssueChild(h.ctx, at.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "quiet", Operation: "headless"})
	refused(t, err, "acting for nobody")
	if _, err := h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "quiet", Organization: acme}); err != nil {
		t.Fatalf("the module acting for nobody is refused its headless scopes: %v", err)
	}
}

// A module withdrawn and delivered again on a host that installs modules
// follows the new generation on the host's active record: the grants of a
// role it no longer declares end; the others stay.
func TestAModuleDeliveredAgainAfterAWithdrawalDropsUndeclaredGrants(t *testing.T) {
	h := newHostInstalled(t)
	h.store.PutPerson(domain.Person{ID: "maya", Organization: acme})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		return tx.PutInstallation(domain.Installation{ID: "host-pages", Organization: acme, Target: "pages", Status: domain.Active, Revision: 1})
	}); err != nil {
		t.Fatal(err)
	}
	alex := authority.Person{ID: "alex", Organization: acme, SessionID: "s"}
	for _, g := range []authority.RoleRequest{
		{Organization: acme, InstallationID: "host-pages", Role: "viewer", PersonID: "maya"},
		{Organization: acme, InstallationID: "host-pages", Role: domain.InstallerRole, PersonID: "alex"},
	} {
		if _, err := h.svc.GrantRole(h.ctx, alex, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.svc.WithdrawModule(h.ctx, "pages"); err != nil {
		t.Fatal(err)
	}
	again := pageModule(2, true)
	delete(again.Roles, "viewer")
	if _, err := h.svc.ApplyModule(h.ctx, again); err != nil {
		t.Fatal(err)
	}
	grants, err := h.svc.ListRoleGrants(h.ctx, alex, acme, "host-pages")
	if err != nil || len(grants) != 1 || grants[0].Role != domain.InstallerRole {
		t.Fatalf("after the redelivery the grants are %v (%v), want the installer's alone", grants, err)
	}
}

// soundComposition is a solution "app" and three modules over three kinds,
// all owner-aware, with random served scopes, method policies, roles and
// bindings: self-bindings, re-entries and cycles included. Every scope a
// role names is one the solution serves or consumes, as delivery requires.
func soundComposition(r *rand.Rand) []domain.Module {
	kinds, actions := []string{"data.one", "data.two", "data.three"}, []string{"read", "write", "admin"}
	some := func(min int) []*basev0.WorkScopeV1 {
		for {
			var out []*basev0.WorkScopeV1
			for _, k := range kinds {
				var acts []string
				for _, a := range actions {
					if r.Intn(2) == 0 {
						acts = append(acts, a)
					}
				}
				if len(acts) > 0 && r.Intn(3) > 0 {
					out = append(out, sc(k, acts...))
				}
			}
			if len(out) >= min {
				return out
			}
		}
	}
	names := []string{"app", "mod-one", "mod-two", "mod-three"}
	var out []domain.Module
	for i, name := range names {
		m := domain.Module{Name: name, Principal: name, Kind: domain.KindModule, Generation: 1, OwnerAware: true, ResourceKinds: some(1),
			Bindings: map[string]domain.Binding{}, Methods: map[string]domain.MethodPolicy{}}
		for j := 0; j < 3; j++ {
			m.Methods[fmtMethod(name, j)] = domain.MethodPolicy{Requires: some(1)}
		}
		// The first operation is declared on its gRPC and its Connect face.
		m.Methods["POST "+fmtMethod(name, 0)] = m.Methods[fmtMethod(name, 0)]
		for _, other := range names {
			if r.Intn(2) == 0 {
				id := "to-" + other
				invoke := some(1)
				var lookup []*basev0.WorkScopeV1
				if r.Intn(2) == 0 {
					lookup = scope.Intersect(some(1), invoke)
				}
				m.Bindings[id] = domain.Binding{ID: id, Audience: other, InvokeScopes: invoke, LookupScopes: lookup}
			}
		}
		if i == 0 {
			grantable := slices.Clone(m.ResourceKinds)
			for _, b := range m.Bindings {
				grantable = append(grantable, b.InvokeScopes...)
			}
			role := func() []*basev0.WorkScopeV1 {
				if role := scope.Intersect(some(1), grantable); len(role) > 0 {
					return role
				}
				return slices.Clone(m.ResourceKinds)
			}
			m.Kind, m.Roles = domain.KindSolution, map[string][]*basev0.WorkScopeV1{domain.InstallerRole: slices.Clone(m.ResourceKinds), "r": role(), "s": role()}
		}
		out = append(out, m)
	}
	return out
}

func fmtMethod(module string, n int) string {
	return "/" + module + ".v1.Service/Op" + string(rune('a'+n))
}

// Reach is an upper bound of the uncapped runtime: over random compositions
// (bindings with invoke and lookup scopes, self-bindings, re-entries and
// cycles, an operation on its gRPC and Connect faces) and random chains, no
// capability issuance mints carries, at its audience, a kind or action the
// owner's reach does not list there, and no operation CheckMethod admits,
// on either face, is missing from it. Owners and starting points: a person
// holding two roles at once (reach: the union of both roles'), from a root
// at the solution, plain or naming a binding, and from a delegation to the
// solution; the installation's agent, from its root. Hops invoke or look up.
// The solution is installed by its host without consent, so nothing caps the
// runtime by the reach it is measured against. Seeded, so deterministic.
func TestTheRuntimeNeverAdmitsBeyondReach(t *testing.T) {
	for seed := int64(0); seed < 120; seed++ {
		r := rand.New(rand.NewSource(seed))
		h := newHarness(t)
		modules := soundComposition(r)
		for _, m := range modules[1:] {
			if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
		}
		if _, err := h.svc.ApplyModule(h.ctx, modules[0]); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		inst, err := h.svc.InstallAsHost(h.ctx, acme, "app", "r", "alex", nil)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		h.grant("app", "r", "maya")
		h.grant("app", "s", "maya")
		byPrincipal := map[string]domain.Module{}
		for _, m := range modules {
			stored, err := h.svc.Composed(h.ctx, m.Name)
			if err != nil {
				t.Fatal(err)
			}
			byPrincipal[m.Principal] = stored
		}
		type bound struct {
			cells map[string][]*basev0.WorkScopeV1
			ops   map[string]map[string]bool
		}
		reachOf := func(roles ...string) bound {
			b := bound{map[string][]*basev0.WorkScopeV1{}, map[string]map[string]bool{}}
			for _, role := range roles {
				rows, err := decide.Reach(byPrincipal["app"], role, byPrincipal)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if row.Via != decide.ReachPerson {
						b.cells[row.Module] = append(b.cells[row.Module], row.Scopes...)
					}
				}
			}
			// The roles held together are admitted to what their joined
			// scopes cover at each module.
			for module, scopes := range b.cells {
				b.ops[module] = map[string]bool{}
				for _, op := range decide.Operations(byPrincipal[module], scope.Normalize(scopes)) {
					b.ops[module][op] = true
				}
			}
			return b
		}
		person, agent := reachOf("r", "s"), reachOf("r")
		verify := func(b bound, at authority.Issued, module string, chain []string) {
			// What a capability carries for kinds its audience does not
			// serve (a root naming a binding) is usable only further on.
			got := scope.Intersect(scope.Unowned(effective(at)), byPrincipal[module].ResourceKinds)
			if !scope.Attenuates(got, b.cells[module]) {
				t.Fatalf("seed %d: %v carries %v at %s beyond its reach %v", seed, chain, got, module, b.cells[module])
			}
			for _, method := range slices.Sorted(maps.Keys(byPrincipal[module].Methods)) {
				if _, _, _, err := h.svc.CheckMethod(h.ctx, at.Token, module, method, false); err == nil && !b.ops[module][decide.Operation(method)] {
					t.Fatalf("seed %d: %v is admitted to %s at %s, which its reach does not list (%v)", seed, chain, method, module, b.ops[module])
				}
			}
		}
		pick := func(m domain.Module) string {
			ids := slices.Sorted(maps.Keys(m.Bindings))
			if len(ids) == 0 {
				return ""
			}
			return ids[r.Intn(len(ids))]
		}
		type start struct {
			owner string
			reach bound
			root  func() (authority.Issued, string, error)
		}
		starts := []start{
			{"person", person, func() (authority.Issued, string, error) {
				at, err := h.root("maya", "app")
				return at, "app", err
			}},
			{"person naming a binding", person, func() (authority.Issued, string, error) {
				at, err := h.svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "app", Binding: pick(byPrincipal["app"])})
				return at, "app", err
			}},
			{"delegation", person, func() (authority.Issued, string, error) {
				id := pick(byPrincipal["app"])
				if id == "" {
					return authority.Issued{}, "", errNothing
				}
				target := byPrincipal[byPrincipal["app"].Bindings[id].Audience]
				d, err := h.svc.Delegate(h.ctx, h.person("maya"), "app", scope.Intersect(target.ResourceKinds, byPrincipal["app"].Bindings[id].InvokeScopes), "a run", 3600)
				if err != nil {
					return authority.Issued{}, "", err
				}
				at, err := h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "app"}, authority.IssueRequest{Binding: id})
				return at, target.Name, err
			}},
			{"agent", agent, func() (authority.Issued, string, error) {
				at, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "app"}, inst.ID, authority.IssueRequest{Audience: "app"})
				return at, "app", err
			}},
		}
		for _, st := range starts {
			for walk := 0; walk < 5; walk++ {
				at, module, err := st.root()
				if err != nil {
					continue // this start holds nothing here
				}
				chain := []string{st.owner, module}
				verify(st.reach, at, module, chain)
				for hop := 0; hop < 6; hop++ {
					id := pick(byPrincipal[module])
					if id == "" {
						break
					}
					operation := ""
					if r.Intn(2) == 0 {
						operation = "lookup"
					}
					next, err := h.svc.IssueChild(h.ctx, at.Token, authority.Workload{Module: module}, authority.IssueRequest{Binding: id, Operation: operation})
					if err != nil {
						continue
					}
					at, module = next, byPrincipal[module].Bindings[id].Audience
					chain = append(chain, module)
					verify(st.reach, at, module, chain)
				}
			}
		}
	}
}

var errNothing = errors.New("nothing to start from")
