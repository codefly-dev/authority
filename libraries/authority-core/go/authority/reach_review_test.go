package authority_test

import (
	"context"
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
	refused(t, h.callStore(at, storePurge), "beyond the reach its installation approved")
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
	refused(t, h.callStore(at, storePurge), "beyond the reach its installation approved")
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
// from the ledger is refused by name.
func TestAHeadlessHopForAPersonIsRefused(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "legacy-reader", Scopes: []domain.RoleScope{{Kind: legacyKind, Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "rob", Organization: acme, Roles: []string{"ledger-reader", "legacy-reader"}})
	m := ledger()
	m.Generation = 2
	m.Bindings["quiet"] = domain.Binding{ID: "quiet", Audience: "legacy-store", HeadlessScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	at := h.must(h.root("rob", "ledger"))
	_, err := h.svc.IssueChild(h.ctx, at.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "quiet", Operation: "headless"})
	refused(t, err, "acting for nobody")
	if _, err := h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "quiet", Organization: acme}); err != nil {
		t.Fatalf("the module acting for nobody is refused its headless scopes: %v", err)
	}
}

// A module withdrawn and delivered again on a host that installs modules
// keeps the host's active record, but no grant: each role granted on it ended
// with the withdrawal, so a redelivery cannot give a grant a meaning nobody
// approved (delivery_widening_test.go proves the widening it prevents).
func TestAModuleDeliveredAgainAfterAWithdrawalHoldsNoGrants(t *testing.T) {
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
	var grants []domain.RoleGrant
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { grants, err = tx.RoleGrants("host-pages"); return }); err != nil || len(grants) != 0 {
		t.Fatalf("after the redelivery the grants are %v (%v), want none", grants, err)
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
		// The first operation is declared on its gRPC and its Connect face,
		// each with its own policy.
		m.Methods["POST "+fmtMethod(name, 0)] = domain.MethodPolicy{Requires: some(1)}
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

// Reach is an upper bound of the uncapped runtime, and the cap it sets is
// exact at the composition approved. Over random compositions (bindings with
// invoke and lookup scopes, self-bindings, re-entries and cycles, an
// operation on its gRPC and Connect faces with policies of their own) and
// random chains, run alike on two hosts of the same composition, one whose
// solution is installed by its host without consent (uncapped) and one
// whose administrator consented to its reach (capped):
//   - no capability the uncapped host mints carries, at its audience, a kind
//     or action the owner's reach does not list there, and no operation it
//     admits, on either face, is missing from it;
//   - the capped host refuses nothing the uncapped one admits, issuing the
//     same scopes and admitting the same methods.
//
// Owners and starting points: a person holding two roles at once (their
// reach: the joint reach of the declared roles, within the two roles'
// scopes), from a root at the solution, plain or naming a binding, and from
// a delegation to the solution; the installation's agent, from its root.
// Hops invoke or look up. Seeded, so deterministic.
func TestTheRuntimeNeverAdmitsBeyondReach(t *testing.T) {
	for seed := int64(0); seed < 120; seed++ {
		r := rand.New(rand.NewSource(seed))
		modules := soundComposition(r)
		build := func(consented bool) (*harness, domain.Installation) {
			h := newHarness(t)
			for _, m := range append(slices.Clone(modules[1:]), modules[0]) {
				if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
			}
			var inst domain.Installation
			var err error
			if consented {
				inst = h.installAs(acme, "app", "r")
			} else if inst, err = h.svc.InstallAsHost(h.ctx, acme, "app", "r", "alex", nil); err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			h.grant("app", "r", "maya")
			h.grant("app", "s", "maya")
			return h, inst
		}
		uncapped, uInst := build(false)
		capped, cInst := build(true)
		byPrincipal := map[string]domain.Module{}
		for _, m := range modules {
			stored, err := uncapped.svc.Composed(uncapped.ctx, m.Name)
			if err != nil {
				t.Fatal(err)
			}
			byPrincipal[m.Principal] = stored
		}
		reach, err := decide.ReachOf(byPrincipal["app"], slices.Collect(maps.Values(byPrincipal)))
		if err != nil {
			t.Fatal(err)
		}
		type bound struct {
			cells map[string][]*basev0.WorkScopeV1
			ops   map[string]map[string]bool
		}
		boundOf := func(key string, within []*basev0.WorkScopeV1) bound {
			b := bound{map[string][]*basev0.WorkScopeV1{}, map[string]map[string]bool{}}
			for _, row := range reach[key] {
				if row.Via != decide.ReachPerson {
					b.cells[row.Module] = append(b.cells[row.Module], row.Scopes...)
				}
			}
			for module, scopes := range b.cells {
				cell := scope.Normalize(scopes)
				if within != nil {
					cell = scope.Intersect(cell, within)
				}
				b.cells[module] = cell
				b.ops[module] = map[string]bool{}
				for _, op := range decide.Operations(byPrincipal[module], cell) {
					b.ops[module][op] = true
				}
			}
			return b
		}
		app := byPrincipal["app"]
		person := boundOf(decide.JointRoles, scope.Unowned(append(slices.Clone(app.Roles["r"]), app.Roles["s"]...)))
		agent := boundOf("r", nil)
		verify := func(b bound, u, c authority.Issued, module string, chain []string) {
			// What a capability carries for kinds its audience does not
			// serve (a root naming a binding) is usable only further on.
			got := scope.Intersect(scope.Unowned(effective(u)), byPrincipal[module].ResourceKinds)
			if !scope.Attenuates(got, b.cells[module]) {
				t.Fatalf("seed %d: %v carries %v at %s beyond its reach %v", seed, chain, got, module, b.cells[module])
			}
			if !sameScopes(scope.Unowned(effective(u)), scope.Unowned(effective(c))) {
				t.Fatalf("seed %d: %v: the capped host issues %v, the uncapped %v", seed, chain, effective(c), effective(u))
			}
			for _, method := range slices.Sorted(maps.Keys(byPrincipal[module].Methods)) {
				_, _, _, errU := uncapped.svc.CheckMethod(uncapped.ctx, u.Token, module, method, false)
				_, _, _, errC := capped.svc.CheckMethod(capped.ctx, c.Token, module, method, false)
				if errU == nil && !b.ops[module][decide.Operation(method)] {
					t.Fatalf("seed %d: %v is admitted to %s at %s, which its reach does not list (%v)", seed, chain, method, module, b.ops[module])
				}
				if (errU == nil) != (errC == nil) {
					t.Fatalf("seed %d: %v at %s: %s is admitted uncapped (%v) and capped (%v) differently", seed, chain, module, method, errU, errC)
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
			root  func(h *harness, inst domain.Installation, id string) (authority.Issued, string, error)
		}
		starts := []start{
			{"person", person, func(h *harness, _ domain.Installation, _ string) (authority.Issued, string, error) {
				at, err := h.root("maya", "app")
				return at, "app", err
			}},
			{"person naming a binding", person, func(h *harness, _ domain.Installation, id string) (authority.Issued, string, error) {
				at, err := h.svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "app", Binding: id})
				return at, "app", err
			}},
			{"delegation", person, func(h *harness, _ domain.Installation, id string) (authority.Issued, string, error) {
				if id == "" {
					return authority.Issued{}, "", errNothing
				}
				b := app.Bindings[id]
				target := byPrincipal[b.Audience]
				d, err := h.svc.Delegate(h.ctx, h.person("maya"), "app", scope.Intersect(target.ResourceKinds, b.InvokeScopes), "a run", 3600)
				if err != nil {
					return authority.Issued{}, "", err
				}
				at, err := h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "app"}, authority.IssueRequest{Binding: id})
				return at, target.Name, err
			}},
			{"agent", agent, func(h *harness, inst domain.Installation, _ string) (authority.Issued, string, error) {
				at, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "app"}, inst.ID, authority.IssueRequest{Audience: "app"})
				return at, "app", err
			}},
		}
		for _, st := range starts {
			for walk := 0; walk < 4; walk++ {
				id := pick(app)
				u, module, errU := st.root(uncapped, uInst, id)
				c, _, errC := st.root(capped, cInst, id)
				if (errU == nil) != (errC == nil) {
					t.Fatalf("seed %d: %s starts uncapped (%v) and capped (%v) differently", seed, st.owner, errU, errC)
				}
				if errU != nil {
					continue // this start holds nothing here
				}
				chain := []string{st.owner, module}
				verify(st.reach, u, c, module, chain)
				for hop := 0; hop < 6; hop++ {
					id := pick(byPrincipal[module])
					if id == "" {
						break
					}
					operation := ""
					if r.Intn(2) == 0 {
						operation = "lookup"
					}
					ask := authority.IssueRequest{Binding: id, Operation: operation}
					nextU, errU := uncapped.svc.IssueChild(uncapped.ctx, u.Token, authority.Workload{Module: module}, ask)
					nextC, errC := capped.svc.IssueChild(capped.ctx, c.Token, authority.Workload{Module: module}, ask)
					if (errU == nil) != (errC == nil) {
						t.Fatalf("seed %d: %v > %s hops uncapped (%v) and capped (%v) differently", seed, chain, id, errU, errC)
					}
					if errU != nil {
						continue
					}
					u, c, module = nextU, nextC, byPrincipal[module].Bindings[id].Audience
					chain = append(chain, module)
					verify(st.reach, u, c, module, chain)
				}
			}
		}
	}
}

var errNothing = errors.New("nothing to start from")

// sameScopes: each attenuates the other.
func sameScopes(a, b []*basev0.WorkScopeV1) bool {
	return scope.Attenuates(a, b) && scope.Attenuates(b, a)
}

// Each face of an operation is held to its own approved policy: the store's
// Connect face of Purge asks write where its gRPC face asks admin, and a's
// author (write, no admin), through a, is admitted on the Connect face and
// refused on the gRPC one by the store's own policy, never by the cap.
func TestEachFaceOfAnOperationIsHeldToItsOwnApprovedPolicy(t *testing.T) {
	h := newHarness(t)
	store := storeAt(2, "admin", true)
	store.Methods["POST "+storePurge] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{sc(kind, "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, store); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	h.grant("a", "author", "maya")
	at := h.must(h.through("maya", "a", "store"))
	if err := h.callStore(at, "POST "+storePurge); err != nil {
		t.Fatalf("the Connect face, approved with its own policy, is refused: %v", err)
	}
	refused(t, h.callStore(at, storePurge), "requires "+kind+":admin")
}

// One installation's state never refuses a delivery: a legacy consent whose
// approved generation the store does not keep (a host migration may record
// one) is skipped by the adoption, left unadopted and offering its upgrade,
// its holders refused by name; another legacy consent is adopted; a delivery
// of an unrelated module and a host's start both succeed.
func TestALegacyConsentWhoseApprovedGenerationIsNotKeptNeverRefusesADelivery(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	widened := solution("a", true).Roles
	widened["extra"] = []*basev0.WorkScopeV1{sc("a.note", "read")}
	for _, generation := range []uint64{2, 3} {
		if _, err := h.svc.ApplyModule(h.ctx, at("a", generation, widened)); err != nil {
			t.Fatal(err)
		}
	}
	unkept := h.stored(acme, "a")
	unkept.Consent.Generation, unkept.Consent.ReachDigest, unkept.Consent.Reach = 2, "", "" // generation 2 was never approved, so never kept
	adoptable := h.stored(acme, "b")
	adoptable.Consent.ReachDigest, adoptable.Consent.Reach = "", ""
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		if err := tx.PutInstallation(unkept); err != nil {
			return err
		}
		return tx.PutInstallation(adoptable)
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.AdoptLegacyReach(h.ctx); err != nil {
		t.Fatalf("a host's start fails on one installation's state: %v", err)
	}
	h.legacy("b")
	unrelated := domain.Module{Name: "replica", Principal: "replica", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, unrelated); err != nil {
		t.Fatalf("a delivery of an unrelated module is refused by one installation's state: %v", err)
	}
	if b := h.stored(acme, "b"); b.Consent.ReachDigest == "" {
		t.Fatal("the adoptable legacy consent was not adopted")
	}
	a := h.stored(acme, "a")
	if a.Consent.ReachDigest != "" {
		t.Fatalf("the unkept consent was adopted: %+v", a.Consent)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, a); err != nil || !up {
		t.Fatalf("the unkept consent offers no upgrade: %v %v", up, err)
	}
	_, err := h.root("maya", "a")
	refused(t, err, "that installation "+a.ID+" approved is not kept")
}

// A widening is journaled once: two unrelated deliveries after it, which
// change nothing a's roles reach, journal nothing for a's installation.
func TestAWideningIsJournaledOnce(t *testing.T) {
	h := reachHarness(t)
	offered := 0
	cfg := h.cfg
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error {
		if e.Kind == domain.InstallationUpgradeAvailable && e.Subject == h.inst(acme, "a").ID {
			offered++
		}
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	widenDownstream(t, h)
	if offered != 1 {
		t.Fatalf("the widening was journaled %d times, want once", offered)
	}
	for _, name := range []string{"unrelated-one", "unrelated-two"} {
		if _, err := h.svc.ApplyModule(h.ctx, domain.Module{Name: name, Principal: name, Kind: domain.KindModule, Generation: 1,
			ResourceKinds: []*basev0.WorkScopeV1{sc(name+".item", "read")}}); err != nil {
			t.Fatal(err)
		}
	}
	if offered != 1 {
		t.Fatalf("unrelated deliveries journaled the widening again: %d times in all", offered)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || !up {
		t.Fatalf("the upgrade is no longer offered: %v %v", up, err)
	}
}
