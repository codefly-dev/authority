package decide_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
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
	grants := []domain.RoleGrant{{InstallationID: "i", Role: "viewer", TeamID: "finance"}, {InstallationID: "i", Role: domain.InstallerRole, PersonID: "alex"},
		{InstallationID: "elsewhere", Role: domain.InstallerRole, PersonID: "maya"}}
	roles := decide.HeldRoles(maya, inst, grants)
	if len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("held %v: a team grant is its members' role, a person's grant theirs alone, another installation's grant nothing here", roles)
	}
	scopes, err := decide.RoleScopes(solution, inst, roles)
	if err != nil || len(scopes) == 0 {
		t.Fatalf("role scopes %v, %v", scopes, err)
	}
	for _, s := range scopes {
		if s.GetResourceOwnerId() != "u" {
			t.Fatalf("a role scope %v is not owned by the principal", s)
		}
	}
	if got, err := decide.RoleScopes(solution, inst, nil); got != nil || err != nil {
		t.Fatal("no role grants something")
	}
}

// An installation with no principal (a zero value, a row from before the
// principal existed) grants nothing: an empty owner selects every owner.
func TestAnInstallationWithoutAPrincipalGrantsNothing(t *testing.T) {
	got, err := decide.RoleScopes(solution, domain.Installation{ID: "i"}, []string{"viewer"})
	refused(t, err, domain.Denied, "no principal")
	if got != nil {
		t.Fatalf("an installation with no principal granted %v", got)
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

// Through a solution the refusal says the capability is confined, in the
// same words whatever the person's own grants hold, so the module asking
// learns nothing of them; elsewhere it says the child widens.
func TestAChildRefusalNamesConfinementAndRevealsNoGrant(t *testing.T) {
	through := decide.Child("store", true)
	refused(t, through, domain.Denied, "confined")
	refused(t, through, domain.Denied, "widens")
	refused(t, decide.Child("store", false), domain.Denied, "widens")
	if strings.Contains(decide.Child("store", false).Error(), "confined") {
		t.Fatal("a child through no solution is called confined")
	}
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
		return decide.RoleChange{RequestOrganization: "acme", RequestedID: inst.ID, Installation: inst, Solution: solution, Caller: admin, Role: "viewer", PersonID: "dev", Subject: &member}
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
		"a member": {func(r *decide.RoleChange) { r.Caller = member }, domain.Denied, "belongs to another organization"},
		"another organization's admin": {func(r *decide.RoleChange) {
			r.Caller = domain.Person{ID: "zoe", Organization: "globex", Roles: []string{"admin"}}
		}, domain.Denied, "belongs to another organization"},
		"a disabled installation":          {func(r *decide.RoleChange) { r.Installation.Status = domain.Revoked }, domain.Precondition, "not installed"},
		"an undeclared role":               {func(r *decide.RoleChange) { r.Role = "owner" }, domain.NotFound, "declares no role"},
		"both subjects":                    {func(r *decide.RoleChange) { r.TeamID = "t" }, domain.Invalid, "exactly one"},
		"no subject":                       {func(r *decide.RoleChange) { r.PersonID = "" }, domain.Invalid, "exactly one"},
		"a person of another organization": {func(r *decide.RoleChange) { r.PersonID, r.Subject = "omar", &omar }, domain.Denied, "not a member"},
		"a team of another organization":   {func(r *decide.RoleChange) { r.PersonID, r.TeamID = "", "ops" }, domain.Denied, "not a team of"},
		"a member listing":                 {func(r *decide.RoleChange) { r.Caller, r.List = member, true }, domain.Denied, "belongs to another organization"},
		"a member revoking":                {func(r *decide.RoleChange) { r.Caller, r.Revoke = member, true }, domain.Denied, "belongs to another organization"},
	} {
		t.Run(name, func(t *testing.T) {
			r := base()
			c.mutate(&r)
			refused(t, decide.ChangeRole(r), c.code, c.reason)
		})
	}
	// A grant stays revocable after its person left, its team is gone, its
	// installation was uninstalled, or its role is no longer declared.
	for name, mutate := range map[string]func(*decide.RoleChange){
		"an uninstalled installation":       func(r *decide.RoleChange) { r.Installation.Status = domain.Revoked },
		"a role no longer declared":         func(r *decide.RoleChange) { r.Role = "retired" },
		"a person who left":                 func(r *decide.RoleChange) { r.Subject = nil },
		"a person now elsewhere":            func(r *decide.RoleChange) { r.Subject = &omar },
		"a team no longer in the directory": func(r *decide.RoleChange) { r.PersonID, r.TeamID = "", "gone" },
	} {
		t.Run("revoking "+name, func(t *testing.T) {
			r := base()
			r.Revoke = true
			mutate(&r)
			if err := decide.ChangeRole(r); err != nil {
				t.Fatalf("the grant cannot be revoked: %v", err)
			}
		})
	}
	refused(t, func() error { r := base(); r.Revoke, r.TeamID = true, "t"; return decide.ChangeRole(r) }(), domain.Invalid, "exactly one")
	// Another organization's installation and none at all answer alike, with
	// the id as requested.
	other := base()
	other.RequestOrganization, other.RequestedID = "globex", "I"
	if got, absent := decide.ChangeRole(other).Error(), decide.ForeignInstallation("I", "globex").Error(); got != absent {
		t.Fatalf("a foreign installation answers %q, an absent one %q", got, absent)
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
		refused(t, decide.ValidResourceID(id), domain.Invalid, "not a usable id")
	}
}

func TestOrganizationGrantsAndModules(t *testing.T) {
	audience := domain.Module{ResourceKinds: []*basev0.WorkScopeV1{sc("doc", "read", "admin")}}
	roles := []domain.OrgRole{{Name: "r", Scopes: []domain.RoleScope{{Kind: "*", Actions: []string{"read"}}, {Kind: "doc", Actions: []string{"admin"}, Resources: []resources.Grant{{ID: "x"}}}}}}
	// read holds the whole kind; admin holds x alone, never the kind.
	if got := decide.OrgScopes(roles, audience, nil); !scope.Same(got, []*basev0.WorkScopeV1{sc("doc", "read"), owned("doc", "", []string{"admin"}, "x")}) {
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
	noInstaller := solution
	noInstaller.Roles = map[string][]*basev0.WorkScopeV1{"viewer": solution.Roles["viewer"]}
	if err := decide.ValidateModule(noInstaller); !errors.Is(err, domain.ErrNoInstallerRole) {
		t.Fatalf("a solution with no installer role: %v", err)
	}
	for name, methods := range map[string]map[string]domain.MethodPolicy{
		"a method naming resource ids": {"/doc.Store/Read": {Requires: []*basev0.WorkScopeV1{{ResourceKind: "doc", Actions: []string{"read"}, ResourceIds: []string{"x"}}}}},
		"a method naming an owner":     {"/doc.Store/Read": {Requires: []*basev0.WorkScopeV1{owned("doc", "u", []string{"read"})}}},
		"a method requiring and not":   {"/doc.Store/Read": {Requires: []*basev0.WorkScopeV1{sc("doc", "read")}, AnyCheckedCaller: true}},
	} {
		t.Run(name, func(t *testing.T) {
			m := domain.Module{Name: "m", Principal: "m", Kind: domain.KindModule, Generation: 1, Methods: methods}
			refused(t, decide.ValidateModule(m), domain.Denied, "m:")
		})
	}
	served := domain.Module{Name: "m", Principal: "m", Kind: domain.KindModule, Generation: 1,
		Methods: map[string]domain.MethodPolicy{"/doc.Store/Read": {Requires: []*basev0.WorkScopeV1{sc("doc", "read")}}, "/doc.Store/Ping": {AnyCheckedCaller: true}}}
	if err := decide.ValidateModule(served); err != nil {
		t.Fatalf("a valid method policy: %v", err)
	}
}

// Withdrawing owner-aware checking is a narrowing: owner-selected
// capabilities already issued to the module end with it.
func TestWithdrawingOwnerAwareIsANarrowing(t *testing.T) {
	aware := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1, OwnerAware: true}
	blind := aware
	blind.OwnerAware, blind.Generation = false, 2
	if !decide.Narrowed(aware, blind) {
		t.Fatal("withdrawing owner-aware checking is not a narrowing")
	}
	if decide.Narrowed(blind, aware) {
		t.Fatal("declaring owner-aware checking is a narrowing")
	}
}
