package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

var read, write, create, admin = []string{"read"}, []string{"write"}, []string{"create"}, []string{"admin"}

func TestThePrincipalIsStableDistinctAndPerOrganization(t *testing.T) {
	h := newHarness(t)
	u := h.principal(acme, "a")
	if u == h.inst(acme, "a").ID || u == h.principal(acme, "b") || u == h.principal(globex, "a") {
		t.Fatal("a principal is shared with an installation id, another solution or another organization")
	}
	if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if again := h.install(acme, "a"); again.PrincipalID != u {
		t.Fatalf("a reinstall made principal %s, want %s", again.PrincipalID, u)
	}
}

func TestNobodyHoldsARoleUntilGranted(t *testing.T) {
	h := newHarness(t)
	for _, person := range []string{"maya", "alex"} {
		_, err := h.root(person, "a")
		refused(t, err, "holds no role")
	}
}

func TestAViewerReadsOnlyThePrincipalsData(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	u, v := h.principal(acme, "a"), h.principal(acme, "b")
	exactly(t, h.must(h.root("maya", "a")), "a.note", u, read)
	exactly(t, h.must(h.through("maya", "a", "store")), kind, u, read)
	exactly(t, h.must(h.through("maya", "a", "store", owned(kind, u, read, "u-doc"))), kind, u, read, "u-doc")
	for name, ask := range map[string]*basev0.WorkScopeV1{
		"another principal":         owned(kind, v, read),
		"another organization's":    owned(kind, h.principal(globex, "a"), read),
		"the whole kind":            sc(kind, "read"),
		"an id alone":               {ResourceKind: kind, Actions: read, ResourceIds: []string{"store-x"}},
		"a person as owner":         owned(kind, "maya", read),
		"the installation as owner": owned(kind, h.inst(acme, "a").ID, read),
		"the organization as owner": owned(kind, acme, read),
		"an action the role lacks":  owned(kind, u, write),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.through("maya", "a", "store", ask)
			refused(t, err, "widens")
		})
	}
	grants, err := h.svc.ListResources(h.ctx, h.must(h.through("maya", "a", "store")).Token, "store", kind, "read")
	if err != nil || len(grants) != 1 || !grants[0].All || grants[0].Owner != u {
		t.Fatalf("listed %+v %v", grants, err)
	}
}

func TestTheAgentIsThePrincipalConfinedToItsData(t *testing.T) {
	h := newHarness(t)
	u := h.principal(acme, "a")
	agent := h.must(h.agent("a", "store"))
	if agent.Context.GetOwnerPrincipalId() != u || agent.Context.GetOwnerPrincipalKind() != "agent" {
		t.Fatalf("the agent is %s (%s)", agent.Context.GetOwnerPrincipalId(), agent.Context.GetOwnerPrincipalKind())
	}
	exactly(t, agent, kind, u, []string{"create", "read", "write"})
	_, err := h.agent("a", "store", owned(kind, u, admin))
	refused(t, err, "beyond")
	_, err = h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, h.inst(acme, "a").ID, authority.IssueRequest{Audience: "store"})
	refused(t, err, "binding")
	for _, ask := range []*basev0.WorkScopeV1{sc(kind, "read"), owned(kind, h.principal(acme, "b"), read), {ResourceKind: kind, Actions: read, ResourceIds: []string{"x"}}} {
		_, err := h.agent("a", "store", ask)
		refused(t, err, "widens")
	}
}

func TestASolutionCapabilityIsConfined(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "rob")
	h.grant("a", "viewer", "ada")
	exactly(t, h.must(h.through("rob", "a", "store")), kind, h.principal(acme, "a"), read)
	_, err := h.through("rob", "a", "store", &basev0.WorkScopeV1{ResourceKind: kind, Actions: read, ResourceIds: []string{"store-x"}})
	refused(t, err, "confined")
	_, err = h.through("ada", "a", "store", &basev0.WorkScopeV1{ResourceKind: kind, Actions: admin, ResourceIds: []string{"store-x"}})
	refused(t, err, "confined")
}

func TestOwnerSelectedScopesGoOnlyToOwnerAwareAudiences(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("c", "viewer", "maya")
	_, err := h.through("maya", "a", "legacy")
	refused(t, err, "owner-aware")
	_, err = h.agent("a", "legacy")
	refused(t, err, "owner-aware")
	_, err = h.root("maya", "c")
	refused(t, err, "owner-aware")
	_, err = h.hop(h.must(h.through("maya", "a", "store")), "legacy")
	refused(t, err, "owner-aware")
}

func TestWithdrawingOwnerAwareRefusesEarlierCapabilitiesForGood(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	before := h.must(h.through("maya", "a", "store"))
	store := func(gen uint64, aware bool) {
		if _, err := h.svc.ApplyModule(h.ctx, domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: gen, OwnerAware: aware,
			ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")},
			Bindings: map[string]domain.Binding{"self": {ID: "self", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}},
				"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}}}); err != nil {
			t.Fatal(err)
		}
	}
	store(2, false)
	refused(t, h.check(before), "owner-aware")
	store(3, true)
	refused(t, h.check(before), "owner-aware")
	if err := h.check(h.must(h.through("maya", "a", "store"))); err != nil {
		t.Fatalf("a fresh capability: %v", err)
	}
}

func TestARoleWritesByItsScopesNotItsName(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "author", "remi")
	h.grant("a", "editor", "dev")
	u := h.principal(acme, "a")
	exactly(t, h.must(h.through("remi", "a", "store", owned(kind, u, write))), kind, u, write)
	_, err := h.through("dev", "a", "store", owned(kind, u, write))
	refused(t, err, "widens")
	created := h.must(h.through("remi", "a", "store", owned(kind, u, create)))
	if created.Context.GetOwnerPrincipalId() != "remi" {
		t.Fatal("the author is the person")
	}
}

func TestAChildNeverWidens(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("a", "author", "remi")
	u, v := h.principal(acme, "a"), h.principal(acme, "b")
	narrowed := h.must(h.through("maya", "a", "store", owned(kind, u, read)))
	exactly(t, h.must(h.hop(narrowed, "self")), kind, u, read)
	readOnly := h.must(h.through("remi", "a", "store", owned(kind, u, read)))
	oneDoc := h.must(h.through("maya", "a", "store", owned(kind, u, read, "u-doc")))
	exactly(t, h.must(h.hop(oneDoc, "self")), kind, u, read, "u-doc")
	for name, c := range map[string]struct {
		parent authority.Issued
		ask    *basev0.WorkScopeV1
	}{
		"another owner": {narrowed, owned(kind, v, read)}, "the whole kind": {narrowed, sc(kind, "read")},
		"a dropped action": {readOnly, owned(kind, u, write)}, "the narrowed ids": {oneDoc, owned(kind, u, read)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.hop(c.parent, "self", c.ask)
			refused(t, err, "widens")
		})
	}
}

func TestOtherInstallationsAndOrganizationsNeverReach(t *testing.T) {
	h := newHarness(t)
	h.grant("b", "viewer", "dev")
	_, err := h.root("dev", "a")
	refused(t, err, "holds no role")
	exactly(t, h.must(h.through("dev", "b", "store")), kind, h.principal(acme, "b"), read)
	_, err = h.through("dev", "b", "store", owned(kind, h.principal(acme, "a"), read))
	refused(t, err, "widens")
	if _, err := h.svc.GrantRole(h.ctx, h.person("zoe"), authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "viewer", PersonID: "omar"}); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("omar", "a", "store")), kind, h.principal(globex, "a"), read)
}

func TestWhoMayGrantAndEveryMalformedGrant(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("a", "installer", "ines")
	h.grant("a", "viewer", "maya")
	grants, err := h.svc.ListRoleGrants(h.ctx, h.person("alex"), acme, h.inst(acme, "a").ID)
	if err != nil || slices.IndexFunc(grants, func(g domain.RoleGrant) bool { return g.PersonID == "maya" }) < 0 || len(grants) != 2 {
		t.Fatalf("grants %v %v: a repeated grant is one row", grants, err)
	}
	ines := h.person("ines")
	if _, err := h.svc.GrantRole(h.ctx, ines, authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "viewer", PersonID: "dev"}); err != nil {
		t.Fatalf("the installer grants: %v", err)
	}
	instA, instB, elsewhere := h.inst(acme, "a").ID, h.inst(acme, "b").ID, h.inst(globex, "a").ID
	for name, c := range map[string]struct {
		caller authority.Person
		req    authority.RoleRequest
		code   domain.Code
		reason string
	}{
		"a viewer granting itself":             {h.person("maya"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: domain.InstallerRole, PersonID: "maya"}, domain.Denied, "belongs to another organization"},
		"another organization's administrator": {h.person("zoe"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "dev"}, domain.Denied, "belongs to another organization"},
		"A's installer on B":                   {ines, authority.RoleRequest{Organization: acme, InstallationID: instB, Role: "author", PersonID: "ines"}, domain.Denied, "belongs to another organization"},
		"another organization named":           {h.person("alex"), authority.RoleRequest{Organization: globex, InstallationID: instA, Role: "viewer", PersonID: "dev"}, domain.Denied, "organization"},
		"another organization's installation":  {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: elsewhere, Role: "viewer", PersonID: "dev"}, domain.Denied, "organization"},
		"an undeclared role":                   {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "owner", PersonID: "dev"}, domain.NotFound, "declares no role"},
		"both subjects":                        {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "dev", TeamID: "team"}, domain.Invalid, "exactly one"},
		"no subject":                           {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer"}, domain.Invalid, "exactly one"},
		"a person of another organization":     {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "omar"}, domain.Denied, "not a member"},
		"a team of another organization":       {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", TeamID: "ops"}, domain.Denied, "not a team of"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.GrantRole(h.ctx, c.caller, c.req)
			refused(t, err, c.reason)
			code(t, err, c.code)
		})
	}
	_, err = h.svc.ListRoleGrants(h.ctx, h.person("maya"), acme, instA)
	refused(t, err, "belongs to another organization")
}
