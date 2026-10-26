package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func sc(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

func owned(kind, owner string, actions []string, ids ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: ids, ResourceOwnerId: owner}
}

func refused(t *testing.T, err error, code domain.Code, reason string) {
	t.Helper()
	got, ok := domain.CodeOf(err)
	if !ok || got != code || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want code %v naming %q, got %v", code, reason, err)
	}
}

var solution = domain.Module{Name: "a", Principal: "a", Kind: domain.KindSolution, Generation: 1,
	ResourceKinds: []*basev0.WorkScopeV1{sc("a.note", "read", "write")},
	Bindings:      map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc("doc", "read", "write")}}},
	Roles: map[string][]*basev0.WorkScopeV1{
		domain.InstallerRole: {sc("a.note", "read", "write"), sc("doc", "read", "write")},
		"viewer":             {sc("a.note", "read"), sc("doc", "read")},
	}}

func TestRolesAreGrantsOnThePrincipalsData(t *testing.T) {
	inst := domain.Installation{ID: "i", Organization: "acme", Target: "a", Status: domain.Active, PrincipalID: "u"}
	maya := domain.Person{ID: "maya", Organization: "acme", Teams: []string{"finance"}}
	grants := []domain.RoleGrant{{InstallationID: "i", Role: "viewer", TeamID: "finance"}, {InstallationID: "i", Role: domain.InstallerRole, PersonID: "alex"}}
	roles := decide.HeldRoles(maya, grants)
	if len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("held %v: a team grant is its members' role, a person's grant theirs alone", roles)
	}
	for _, s := range decide.RoleScopes(solution, inst, roles) {
		if s.GetResourceOwnerId() != "u" {
			t.Fatalf("a role scope %v is not owned by the principal", s)
		}
	}
	if decide.RoleScopes(solution, inst, nil) != nil {
		t.Fatal("no role grants something")
	}
}

func TestIssueNamesWhyAnAskIsRefused(t *testing.T) {
	held := []*basev0.WorkScopeV1{owned("doc", "u", []string{"read"})}
	if got, err := decide.Issue(nil, held); err != nil || len(got) != 1 {
		t.Fatalf("an empty ask is everything held: %v %v", got, err)
	}
	_, err := decide.Issue([]*basev0.WorkScopeV1{owned("doc", "u", []string{"admin"})}, held)
	refused(t, err, domain.Denied, "beyond")
	for _, ask := range []*basev0.WorkScopeV1{sc("doc", "read"), owned("doc", "v", []string{"read"})} {
		_, err := decide.Issue([]*basev0.WorkScopeV1{ask}, held)
		refused(t, err, domain.Denied, "widens")
	}
	_, err = decide.Issue(nil, nil)
	refused(t, err, domain.Denied, "holds nothing")
}

func TestAChildRefusalNamesConfinement(t *testing.T) {
	ask := []*basev0.WorkScopeV1{{ResourceKind: "doc", Actions: []string{"read"}, ResourceIds: []string{"x"}}}
	ceiling := []*basev0.WorkScopeV1{owned("doc", "u", []string{"read"})}
	own := []*basev0.WorkScopeV1{{ResourceKind: "doc", Actions: []string{"read"}, ResourceIds: []string{"x"}}}
	refused(t, decide.Child(ask, ceiling, own, true, "store"), domain.Denied, "confined")
	refused(t, decide.Child(ask, ceiling, own, false, "store"), domain.Denied, "widens")
	refused(t, decide.Child(ask, ceiling, nil, true, "store"), domain.Denied, "widens")
}

func TestOwnerSelectedScopesNeedAnOwnerAwareAudience(t *testing.T) {
	scopes := []*basev0.WorkScopeV1{owned("doc", "u", []string{"read"})}
	refused(t, decide.OwnerAware(domain.Module{Principal: "legacy"}, scopes), domain.Denied, "owner-aware")
	if err := decide.OwnerAware(domain.Module{Principal: "store", OwnerAware: true}, scopes); err != nil {
		t.Fatal(err)
	}
	if err := decide.OwnerAware(domain.Module{Principal: "legacy"}, []*basev0.WorkScopeV1{sc("doc", "read")}); err != nil {
		t.Fatal("a plain scope needs no owner-aware audience")
	}
}

func TestWhoMayChangeARoleInOrder(t *testing.T) {
	inst := domain.Installation{ID: "i", Organization: "acme", Target: "a", Status: domain.Active}
	admin := domain.Person{ID: "alex", Organization: "acme", Roles: []string{"admin"}}
	member := domain.Person{ID: "dev", Organization: "acme"}
	omar := domain.Person{ID: "omar", Organization: "globex"}
	base := func() decide.RoleChange {
		return decide.RoleChange{RequestOrganization: "acme", Installation: inst, Solution: solution, Caller: admin, Role: "viewer", PersonID: "dev", Subject: &member}
	}
	if err := decide.ChangeRole(base()); err != nil {
		t.Fatal(err)
	}
	installer := base()
	installer.Caller, installer.CallerRoles = member, []string{domain.InstallerRole}
	if err := decide.ChangeRole(installer); err != nil {
		t.Fatalf("the installer grants: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(*decide.RoleChange)
		code   domain.Code
		reason string
	}{
		"another organization, even for a non-admin": {func(r *decide.RoleChange) { r.RequestOrganization = "globex"; r.Caller = member }, domain.Denied, "organization"},
		"a member": {func(r *decide.RoleChange) { r.Caller = member }, domain.Denied, "may not grant"},
		"another organization's admin": {func(r *decide.RoleChange) {
			r.Caller = domain.Person{ID: "zoe", Organization: "globex", Roles: []string{"admin"}}
		}, domain.Denied, "may not grant"},
		"a disabled installation":          {func(r *decide.RoleChange) { r.Installation.Status = domain.Revoked }, domain.Precondition, "not installed"},
		"an undeclared role":               {func(r *decide.RoleChange) { r.Role = "owner" }, domain.NotFound, "declares no role"},
		"both subjects":                    {func(r *decide.RoleChange) { r.TeamID = "t" }, domain.Invalid, "exactly one"},
		"no subject":                       {func(r *decide.RoleChange) { r.PersonID = "" }, domain.Invalid, "exactly one"},
		"a person of another organization": {func(r *decide.RoleChange) { r.PersonID, r.Subject = "omar", &omar }, domain.Denied, "not a member"},
		"a team of another organization":   {func(r *decide.RoleChange) { r.PersonID, r.TeamID = "", "ops" }, domain.Denied, "not a team of"},
		"a member listing":                 {func(r *decide.RoleChange) { r.Caller, r.List = member, true }, domain.Denied, "may not list"},
	} {
		t.Run(name, func(t *testing.T) {
			r := base()
			c.mutate(&r)
			refused(t, decide.ChangeRole(r), c.code, c.reason)
		})
	}
}

func TestATransferIsDecidedInOrder(t *testing.T) {
	ada := domain.Person{ID: "ada", Organization: "acme"}
	omar := domain.Person{ID: "omar", Organization: "globex"}
	base := func() decide.Transfer {
		return decide.Transfer{OwnerKind: "human", Person: ada, Through: []string{"u"}, From: "acme", To: "u", Administers: true, Writes: true}
	}
	if err := decide.AuthorizeTransfer(base()); err != nil {
		t.Fatal(err)
	}
	fromPerson := base()
	fromPerson.From, fromPerson.FromPerson = "ada", &ada
	if err := decide.AuthorizeTransfer(fromPerson); err != nil {
		t.Fatalf("from a person of the organization: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(*decide.Transfer)
		reason string
	}{
		"the agent":                          {func(x *decide.Transfer) { x.OwnerKind = "agent" }, "a person's act"},
		"to a principal not through":         {func(x *decide.Transfer) { x.To = "v" }, "not issued through"},
		"from a solution principal":          {func(x *decide.Transfer) { x.From, x.FromPrincipal = "v", true }, "solution principal"},
		"from another organization":          {func(x *decide.Transfer) { x.From = "globex" }, "not a person or the organization"},
		"from another organization's person": {func(x *decide.Transfer) { x.From, x.FromPerson = "omar", &omar }, "not a person or the organization"},
		"from nobody":                        {func(x *decide.Transfer) { x.From = "" }, "not a person or the organization"},
		"without admin on the resource":      {func(x *decide.Transfer) { x.Administers = false }, "own organization grants"},
		"without write on the principal":     {func(x *decide.Transfer) { x.Writes = false }, "write on"},
	} {
		t.Run(name, func(t *testing.T) {
			x := base()
			c.mutate(&x)
			refused(t, decide.AuthorizeTransfer(x), domain.Denied, c.reason)
		})
	}
	for _, id := range []string{"", " x", "a*b", "x\n", strings.Repeat("x", 129)} {
		if decide.ValidResourceID(id) == nil {
			t.Fatalf("id %q is usable", id)
		}
	}
}

func TestOrganizationGrantsAndModules(t *testing.T) {
	audience := domain.Module{ResourceKinds: []*basev0.WorkScopeV1{sc("doc", "read", "admin")}}
	roles := []domain.OrgRole{{Name: "r", Scopes: []domain.RoleScope{{Kind: "*", Actions: []string{"read"}}, {Kind: "doc", Actions: []string{"admin"}, Resources: []resources.Grant{{ID: "x"}}}}}}
	if got := decide.OrgScopes(roles, audience); len(got) != 1 || len(got[0].GetActions()) != 2 {
		t.Fatalf("org scopes %v", got)
	}
	if got := decide.ResourceGrants(roles, "doc", "admin"); len(got) != 1 || got[0].ID != "x" {
		t.Fatalf("matchers %v", got)
	}
	if err := decide.ValidateModule(solution); err != nil {
		t.Fatal(err)
	}
	bad := solution
	bad.Roles = map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {owned("doc", "u", []string{"read"})}}
	refused(t, decide.ValidateModule(bad), domain.Denied, "selects an owner")
	module := domain.Module{Name: "m", Principal: "m", Kind: domain.KindModule, Generation: 1, Roles: solution.Roles}
	refused(t, decide.ValidateModule(module), domain.Denied, "declares roles")
}
